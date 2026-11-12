//! 共享转发原语：请求体转发、上游发送序列与响应回传
//!
//! 经典代理与路径前缀直连共用同一份请求发送序列 [`send_upstream_request`]
//! （写头 → 应答 `100 Continue` → 转发请求体，差异只有日志标签 [`RelayLink`]），
//! 以及同一段「读上游 → 写客户端」循环（自适应缓冲、单次读单次写、不解析响应语义）
//! 与结束契约 [`RelayOutcome`]。
//! 各调用点只负责把 outcome 映射成日志级别与自身返回类型，映射规则统一为：
//!
//! | outcome | 日志 | 说明 |
//! | --- | --- | --- |
//! | `Completed` | 调用方的完成日志（debug，含缓冲大小） | 正常收尾 |
//! | `ClientGone` | **不记 error** | 客户端断开，正常下载中断不得刷屏 |
//! | `ClientStalled` | warn | 写客户端在 `timeout` 内毫无进展：对端已不可用 |
//! | `UpstreamClosed` | debug | 上游未产生数据即关闭 |
//! | `TimedOut` | warn | 读上游超时 |
//! | `UpstreamError` | benign → debug / 其余 → warn | 是否影响响应由调用方决定 |
//!
//! 经典代理的编排在 [`crate::protocol::classic`]，本模块只提供它需要的原语。

use crate::protocol::forward::UpstreamHead;
use crate::protocol::http_body::{
    forward_chunked_body, forward_content_length_body, BodyFailureSide, BodyForwardError,
};
use crate::support::buffer_pool::{AdaptiveBuffer, BufferPool};
use crate::support::net::{is_benign_close_error, write_all_with_timeout};
use log::{debug, warn};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

/// 响应拷贝结束原因（两条链路共用的统一契约）
#[derive(Debug)]
pub(super) enum RelayOutcome {
    /// 上游 EOF，且已向客户端写出至少一段数据：响应正常收尾
    Completed,
    /// 写客户端失败：客户端已断开（调度方不得记 error，避免正常中断刷屏）
    ClientGone,
    /// 写客户端超时：对端在 `timeout` 内一个字节都没接受，已不再可用
    ClientStalled,
    /// 上游在写出任何数据前 EOF
    UpstreamClosed,
    /// 读上游超时
    TimedOut,
    /// 读上游出错；原始错误保留，调用方按 benign 与否决定日志级别
    UpstreamError(std::io::Error),
}

/// 写客户端失败的归类结果（两条链路共用同一套判据）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClientWriteFailure {
    /// 对端已断开（含良性关闭）
    Gone,
    /// 对端在 `timeout` 内毫无进展
    Stalled,
}

/// 归类写客户端失败，并按 `label` 统一日志口径
///
/// 超时（对端不读）与普通断开（对端已关）含义不同：前者对端仍连着但不消费，
/// 后者连接已经没了。非超时且非良性关闭（如 `WriteZero`、TLS 内部错误）**不是**
/// 客户端正常断开，记 warn 后才按 [`ClientWriteFailure::Gone`] 收尾，避免本地写缺陷
/// 被 debug 静默吞掉。`label` 用于区分链路来源（`classic` / `path-proxy`）。
pub(super) fn classify_client_write_error(
    e: &std::io::Error,
    label: &str,
) -> ClientWriteFailure {
    if e.kind() == std::io::ErrorKind::TimedOut {
        ClientWriteFailure::Stalled
    } else {
        if !is_benign_close_error(e) {
            warn!("[{}] unexpected error writing response to client: {}", label, e);
        }
        ClientWriteFailure::Gone
    }
}

/// 把写客户端失败映射为拷贝循环的结束状态
fn outcome_for_client_write_error(e: &std::io::Error, link: RelayLink) -> RelayOutcome {
    match classify_client_write_error(e, link.label()) {
        ClientWriteFailure::Stalled => RelayOutcome::ClientStalled,
        ClientWriteFailure::Gone => RelayOutcome::ClientGone,
    }
}

/// 流式转发响应体：一次读上游、一次写客户端，直到上游 EOF 或任一端断开。
///
/// 拷贝缓冲自适应（8KB 起步，长传输 / 大 body 翻倍到 256KB），中间不做额外分配。
/// 返回值附带循环结束时的缓冲大小（字节），供调用方沿用原有日志格式。
///
/// `Completed` 与 `UpstreamClosed` 的区分依据是"是否已向客户端写出过数据"：
/// 前者表示响应体正常收尾，后者表示上游在这次响应里一个字节都没给出。
/// `link` 只影响写客户端失败时的日志标签，判据与结果与链路无关。
pub(super) async fn copy_upstream_to_client<S, T>(
    client: &mut S,
    upstream: &mut T,
    timeout: Duration,
    link: RelayLink,
) -> (RelayOutcome, usize)
where
    S: AsyncWrite + Unpin,
    T: AsyncRead + Unpin,
{
    let mut copy = AdaptiveBuffer::new();
    let mut wrote = false;
    loop {
        copy.prepare();
        match tokio::time::timeout(timeout, upstream.read(copy.as_mut_slice())).await {
            Ok(Ok(0)) => {
                let outcome = if wrote {
                    RelayOutcome::Completed
                } else {
                    RelayOutcome::UpstreamClosed
                };
                return (outcome, copy.current_size());
            }
            Ok(Ok(n)) => {
                copy.note_copied(n);
                // 写方向同样受 `timeout` 约束：对端只连不读时，写阻塞不能无限期占住连接
                if let Err(e) = write_all_with_timeout(
                    client,
                    &copy.as_mut_slice()[..n],
                    timeout,
                    "response to client",
                )
                .await
                {
                    return (outcome_for_client_write_error(&e, link), copy.current_size());
                }
                wrote = true;
            }
            Ok(Err(e)) => return (RelayOutcome::UpstreamError(e), copy.current_size()),
            Err(_) => return (RelayOutcome::TimedOut, copy.current_size()),
        }
    }
}

/// 发送请求失败发生在哪一侧
///
/// 调用方据此决定能否向客户端回写：写上游失败说明目标不可用，可回 502；
/// 与客户端交互失败（应答 `100 Continue`、读请求体）说明客户端已经不可用，
/// 回写没有接收方。原始 io 错误已由 [`log_send_error`] / [`log_body_error`]
/// 在失败点记录，这里只保留方向。
#[derive(Debug)]
pub(super) enum SendRequestError {
    /// 客户端侧失败
    Client,
    /// 上游侧失败
    Upstream,
}

impl From<BodyForwardError> for SendRequestError {
    fn from(e: BodyForwardError) -> Self {
        match e.side {
            BodyFailureSide::Client => SendRequestError::Client,
            BodyFailureSide::Upstream => SendRequestError::Upstream,
        }
    }
}

/// 请求体转发所属链路（日志里用于区分经典代理与路径前缀）
#[derive(Clone, Copy)]
pub(super) enum RelayLink {
    Classic,
    PathPrefix,
}

impl RelayLink {
    pub(super) fn label(self) -> &'static str {
        match self {
            RelayLink::Classic => "classic",
            RelayLink::PathPrefix => "path-proxy",
        }
    }
}

/// 请求体读/写失败时的统一日志：benign 关闭记 debug，其余记 warn
fn log_body_error(link: RelayLink, client_addr: SocketAddr, framing: &str, e: &std::io::Error) {
    if is_benign_close_error(e) {
        debug!(
            "[{}] request body ({} framing) from {} ended: {}",
            link.label(),
            framing,
            client_addr,
            e
        );
    } else {
        warn!(
            "[{}] failed to forward request body ({} framing) from {}: {}",
            link.label(),
            framing,
            client_addr,
            e
        );
    }
}

/// 写上游请求头 / 应答 `100 Continue` 失败时的统一日志
///
/// body 阶段失败已由 [`log_body_error`] 记录，这里只覆盖它没管的两个写点，
/// 避免同一错误被记两遍。写失败（尤其写超时）意味着该连接已不可用：
/// benign 关闭记 debug，其余记 warn，级别口径与 [`log_body_error`] 一致。
fn log_send_error(link: RelayLink, client_addr: SocketAddr, stage: &str, e: &std::io::Error) {
    if is_benign_close_error(e) {
        debug!("[{}] {} for {} ended: {}", link.label(), stage, client_addr, e);
    } else {
        warn!(
            "[{}] failed to send {} for {}: {}",
            link.label(),
            stage,
            client_addr,
            e
        );
    }
}

/// 一次请求体转发的输入参数
///
/// 分帧方式只以 [`UpstreamHead`] 为准，这里不再复制 `content_length` / `chunked`：
/// 同一份事实存两处时，头里声明 chunked、转发却按 CL 处理（或反之）就是请求走私面。
/// 其余字段是调用方上下文（超时、缓冲池、链路标签、客户端地址）；打包成结构体
/// 避免共享实现出现 9 个位置参数。
pub(super) struct RequestBodyForward<'a> {
    /// 已建好的上游请求头（分帧、`Expect` 判断的唯一来源）
    pub head: &'a UpstreamHead,
    /// 已从 socket 读入的 body 前缀（可能已包含完整 body）
    pub buffered: &'a [u8],
    /// 单次读/写的超时
    pub timeout: Duration,
    /// 流式读取时复用的缓冲池
    pub buffer_pool: &'a BufferPool,
    /// 发起本次转发的链路（仅影响日志标签）
    pub link: RelayLink,
    /// 客户端地址（仅用于日志）
    pub client_addr: SocketAddr,
}

/// 转发请求体：已缓冲字节 + 尚未读取的部分（经典代理与路径前缀共用）
///
/// 分帧决策以 [`UpstreamHead`] 为准：
/// - chunked：交给分帧状态机（已缓冲字节必须先过状态机，终止块可能就在缓冲区里）
/// - Content-Length：先发已缓冲部分（截断到 CL，超出的属于管道化的下一个请求），
///   再按剩余长度流式读转
/// - 两者皆无：只转发已缓冲字节（历史行为）
///
/// 返回已向上游写出的 body 字节数（`Content-Length` 路径下可用于判断客户端是否
/// 提前关闭；chunked 路径恒返回 0）。`link` 只影响日志标签，两条链路行为一致。
///
/// 失败时区分 [`SendRequestError::Client`]（读客户端）与
/// [`SendRequestError::Upstream`]（写上游），调用方据此决定是否回 502。
pub(super) async fn forward_request_body<S, T>(
    client: &mut S,
    upstream: &mut T,
    body: RequestBodyForward<'_>,
) -> Result<u64, SendRequestError>
where
    S: AsyncRead + Unpin,
    T: AsyncWrite + Unpin,
{
    let RequestBodyForward {
        head,
        buffered,
        timeout,
        buffer_pool,
        link,
        client_addr,
    } = body;

    if head.chunked {
        return match forward_chunked_body(client, upstream, buffered, timeout, buffer_pool).await {
            Ok(()) => Ok(0),
            Err(e) => {
                log_body_error(link, client_addr, "chunked", &e.error);
                Err(e.into())
            }
        };
    }

    let Some(cl) = head.content_length else {
        // 无 Content-Length 且非 chunked：仅转发已缓冲字节
        if !buffered.is_empty() {
            if let Err(e) = write_all_with_timeout(
                upstream,
                buffered,
                timeout,
                "request body (buffered-only)",
            )
            .await
            {
                log_body_error(link, client_addr, "buffered-only", &e);
                return Err(SendRequestError::Upstream);
            }
        }
        return Ok(buffered.len() as u64);
    };

    match forward_content_length_body(client, upstream, buffered, cl, timeout, buffer_pool).await {
        Ok(sent) if sent < cl => {
            // 客户端提前关闭：body 不完整，但请求头已送达，仍可尝试读响应
            warn!(
                "[{}] client {} closed before sending complete request body ({} / {} bytes)",
                link.label(),
                client_addr,
                sent,
                cl
            );
            Ok(sent)
        }
        Ok(sent) => Ok(sent),
        Err(e) => {
            log_body_error(link, client_addr, "content-length", &e.error);
            Err(e.into())
        }
    }
}

/// 把一次请求发到上游：写请求头 → 需要时自己应答 `100 Continue` → 转发请求体
///
/// 经典代理与路径前缀直连的发送顺序完全一致，差别只在调用方对失败的处理与日志，
/// 因此收敛到这里。返回值是已写出的请求体字节数，含义与 [`forward_request_body`] 相同。
///
/// 100-continue 的时机：`Expect` 已从上游头中剔除，临时响应必须由代理自己给；
/// 否则客户端会等一个永远不会来的 100，直到自己的等待超时才补发 body。
pub(super) async fn send_upstream_request<S, T>(
    client: &mut S,
    upstream: &mut T,
    body: RequestBodyForward<'_>,
) -> Result<u64, SendRequestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncWrite + Unpin,
{
    let timeout = body.timeout;
    let head = body.head;

    if let Err(e) =
        write_all_with_timeout(upstream, head.bytes.as_bytes(), timeout, "request head to upstream")
            .await
    {
        log_send_error(body.link, body.client_addr, "request head to upstream", &e);
        return Err(SendRequestError::Upstream);
    }

    if head.expect_continue {
        if let Err(e) = write_all_with_timeout(
            client,
            b"HTTP/1.1 100 Continue\r\n\r\n",
            timeout,
            "100-continue response",
        )
        .await
        {
            log_send_error(body.link, body.client_addr, "100-continue to client", &e);
            return Err(SendRequestError::Client);
        }
    }

    forward_request_body(client, upstream, body).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }
    /// 客户端只连不读：写方向的阻塞必须被超时打断，不能永久占住连接
    ///
    /// 客户端侧的管道容量只有 8 字节且对端永不读取，上游则持续产出数据：
    /// 拷贝循环的 `write_all` 会永久阻塞在"管道已满"上，函数永不返回，
    /// 服务器端由此一直占着一条连接的并发许可。
    ///
    /// 用例在外层套一个 2 秒的观察窗口：若实现没有给写方向加超时，
    /// 这里会得到 `Err(Elapsed)` 而失败（先红）；加了超时后应很快返回（后绿）。
    #[tokio::test]
    async fn test_copy_upstream_to_client_gives_up_when_client_stops_reading() {
        use tokio::io::AsyncWriteExt;

        let (mut client, client_peer) = tokio::io::duplex(8);
        let (mut upstream_writer, mut upstream) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let chunk = vec![b'x'; 1024];
            while upstream_writer.write_all(&chunk).await.is_ok() {}
        });

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            copy_upstream_to_client(
                &mut client,
                &mut upstream,
                Duration::from_millis(100),
                RelayLink::Classic,
            ),
        )
        .await;

        // 客户端侧永远不读，保持连接直到用例结束，确保"只连不读"的前提成立
        drop(client_peer);
        let (outcome, _) = result.expect(
            "客户端停止读取时，写方向的阻塞必须被超时打断，否则该连接会永久占住并发许可",
        );
        assert!(
            !matches!(outcome, RelayOutcome::Completed),
            "客户端没读完响应，不得报告正常完成：{:?}",
            outcome
        );
    }

    /// 客户端在 `Content-Length` 声明完成前关闭：已转发字节数必须如实返回
    ///
    /// 两条链路共用同一实现，`RelayLink` 只影响日志标签，因此这里对两个标签各跑一遍：
    /// 行为（返回 `Ok(已发送字节)`、不报错、上游收到已发部分）必须完全一致。
    #[tokio::test]
    async fn test_forward_request_body_reports_short_body_on_early_disconnect() {
        use tokio::io::AsyncWriteExt;

        for link in [RelayLink::Classic, RelayLink::PathPrefix] {
            let (mut client, mut peer) = tokio::io::duplex(64);
            let mut upstream: Vec<u8> = Vec::new();
            let pool = BufferPool::new();
            let head = UpstreamHead {
                bytes: String::new(),
                content_length: Some(5),
                chunked: false,
                expect_continue: false,
            };

            peer.write_all(b"abc").await.unwrap();
            drop(peer);

            let sent = forward_request_body(
                &mut client,
                &mut upstream,
                RequestBodyForward {
                    head: &head,
                    buffered: &[],
                    timeout: Duration::from_millis(500),
                    buffer_pool: &pool,
                    link,
                    client_addr: addr(),
                },
            )
            .await
            .expect("客户端提前关闭不是 io 错误，由调用方决定是否继续读响应");

            assert_eq!(sent, 3, "只应报告实际写出的 3 字节（{:?}）", link.label());
            assert_eq!(upstream, b"abc", "已收到的部分必须转发给上游");
        }
    }

    /// 写客户端失败的三类归因：超时 → `ClientStalled`，其余 → `ClientGone`
    ///
    /// 非良性错误（如 `WriteZero`）仍按 `ClientGone` 收尾，但会先记 warn；
    /// 这里只固定"归因不能反过来"，日志级别由 `outcome_for_client_write_error` 内部保证。
    #[test]
    fn test_client_write_error_classification() {
        use std::io::{Error, ErrorKind};

        assert!(
            matches!(
                outcome_for_client_write_error(
                    &Error::new(ErrorKind::TimedOut, "stalled"),
                    RelayLink::Classic
                ),
                RelayOutcome::ClientStalled
            ),
            "写超时必须归为 ClientStalled，否则会把「对端不读」记成正常断开"
        );
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::BrokenPipe,
            ErrorKind::WriteZero,
        ] {
            assert!(
                matches!(
                    outcome_for_client_write_error(&Error::new(kind, "closed"), RelayLink::Classic),
                    RelayOutcome::ClientGone
                ),
                "{:?} 必须归为 ClientGone",
                kind
            );
        }
    }

    /// 上游一个字节都没写就 EOF：必须与「正常收尾」区分开
    ///
    /// `Completed` 的语义是"已向客户端写出过数据且正常结束"；若上游立刻关闭也报
    /// `Completed`，调用方就无法区分空响应与正常响应。
    #[tokio::test]
    async fn test_copy_upstream_to_client_reports_upstream_closed_without_bytes() {
        let mut client: Vec<u8> = Vec::new();
        let mut upstream: &[u8] = b"";

        let (outcome, copy_bytes) = copy_upstream_to_client(
            &mut client,
            &mut upstream,
            Duration::from_millis(100),
            RelayLink::Classic,
        )
        .await;

        assert!(
            matches!(outcome, RelayOutcome::UpstreamClosed),
            "上游零字节 EOF 必须报 UpstreamClosed，实际：{:?}",
            outcome
        );
        assert_eq!(copy_bytes, crate::support::buffer_pool::ADAPTIVE_INITIAL);
        assert!(client.is_empty(), "没有数据可写");
    }

    /// 上游长时间无数据：读方向必须被 `timeout` 打断并报 `TimedOut`
    #[tokio::test]
    async fn test_copy_upstream_to_client_times_out_on_idle_upstream() {
        // 保留写端不写也不关，制造"连接在但上游静默"的场景
        let (mut client, _client_peer) = tokio::io::duplex(64);
        let (_upstream_writer, mut upstream) = tokio::io::duplex(64);

        let (outcome, _) = copy_upstream_to_client(
            &mut client,
            &mut upstream,
            Duration::from_millis(50),
            RelayLink::PathPrefix,
        )
        .await;

        assert!(
            matches!(outcome, RelayOutcome::TimedOut),
            "上游静默必须报 TimedOut，实际：{:?}",
            outcome
        );
    }

    /// 无 `Content-Length` 且非 chunked：只转发已缓冲字节，并如实返回字节数
    #[tokio::test]
    async fn test_forward_request_body_buffered_only_without_framing() {
        let (mut client, _peer) = tokio::io::duplex(64);
        let mut upstream: Vec<u8> = Vec::new();
        let pool = BufferPool::new();
        let head = UpstreamHead {
            bytes: String::new(),
            content_length: None,
            chunked: false,
            expect_continue: false,
        };

        let sent = forward_request_body(
            &mut client,
            &mut upstream,
            RequestBodyForward {
                head: &head,
                buffered: b"abc",
                timeout: Duration::from_millis(100),
                buffer_pool: &pool,
                link: RelayLink::Classic,
                client_addr: addr(),
            },
        )
        .await
        .expect("buffered-only 转发不应读 socket");

        assert_eq!(sent, 3, "返回值应等于已转发的缓冲字节数");
        assert_eq!(upstream, b"abc");
    }

    fn head_with(content_length: Option<u64>, expect_continue: bool) -> UpstreamHead {
        UpstreamHead {
            bytes: "POST / HTTP/1.1\r\nHost: x\r\n\r\n".to_string(),
            content_length,
            chunked: false,
            expect_continue,
        }
    }

    /// 写上游请求头失败 → `Upstream`（调用方据此回 502）
    #[tokio::test]
    async fn test_send_upstream_request_classifies_upstream_write_failure() {
        // 上游对端已丢弃：任何写入都会立刻失败
        let (mut upstream, upstream_peer) = tokio::io::duplex(64);
        drop(upstream_peer);
        let (mut client, _client_peer) = tokio::io::duplex(64);
        let pool = BufferPool::new();
        let head = head_with(None, false);

        let err = send_upstream_request(
            &mut client,
            &mut upstream,
            RequestBodyForward {
                head: &head,
                buffered: b"",
                timeout: Duration::from_millis(200),
                buffer_pool: &pool,
                link: RelayLink::Classic,
                client_addr: addr(),
            },
        )
        .await
        .expect_err("写上游失败必须返回错误");

        assert!(
            matches!(err, SendRequestError::Upstream),
            "写上游失败必须归为 Upstream，实际：{:?}",
            err
        );
    }

    /// 应答 `100 Continue` 时客户端已断开 → `Client`（不得回写 502）
    #[tokio::test]
    async fn test_send_upstream_request_classifies_client_continue_write_failure() {
        let (mut upstream, _upstream_peer) = tokio::io::duplex(1024);
        let (mut client, client_peer) = tokio::io::duplex(64);
        drop(client_peer);
        let pool = BufferPool::new();
        let head = head_with(None, true);

        let err = send_upstream_request(
            &mut client,
            &mut upstream,
            RequestBodyForward {
                head: &head,
                buffered: b"",
                timeout: Duration::from_millis(200),
                buffer_pool: &pool,
                link: RelayLink::PathPrefix,
                client_addr: addr(),
            },
        )
        .await
        .expect_err("100-continue 写客户端失败必须返回错误");

        assert!(
            matches!(err, SendRequestError::Client),
            "客户端侧写失败必须归为 Client，实际：{:?}",
            err
        );
    }

    /// 读请求体超时（客户端连而不发）→ `Client`
    #[tokio::test]
    async fn test_send_upstream_request_classifies_client_body_read_timeout() {
        let (mut client, _client_peer) = tokio::io::duplex(64);
        let (mut upstream, _upstream_peer) = tokio::io::duplex(1024);
        let pool = BufferPool::new();
        let head = head_with(Some(8), false);

        let err = send_upstream_request(
            &mut client,
            &mut upstream,
            RequestBodyForward {
                head: &head,
                buffered: b"",
                timeout: Duration::from_millis(20),
                buffer_pool: &pool,
                link: RelayLink::Classic,
                client_addr: addr(),
            },
        )
        .await
        .expect_err("读请求体超时必须返回错误");

        assert!(
            matches!(err, SendRequestError::Client),
            "读客户端失败必须归为 Client，实际：{:?}",
            err
        );
    }
}
