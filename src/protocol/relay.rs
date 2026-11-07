//! 响应回传与经典转发流水线
//!
//! 经典代理与路径前缀直连共用同一份请求体转发 [`forward_request_body`]（差异只有
//! 日志标签 [`RelayLink`]），以及同一段「读上游 → 写客户端」循环（自适应缓冲、
//! 单次读单次写、不解析响应语义）与结束契约 [`RelayOutcome`]。
//! 各调用点只负责把 outcome 映射成日志级别与自身返回类型，映射规则统一为：
//!
//! | outcome | 日志 | 说明 |
//! | --- | --- | --- |
//! | `Completed` | 调用方的完成日志（debug，含缓冲大小） | 正常收尾 |
//! | `ClientGone` | **不记 error** | 客户端断开，正常下载中断不得刷屏 |
//! | `UpstreamClosed` | debug | 上游未产生数据即关闭 |
//! | `TimedOut` | warn | 读上游超时 |
//! | `UpstreamError` | benign → debug / 其余 → warn | 是否影响响应由调用方决定 |
//!
//! 经典代理的转发流水线（建头 → 转发请求体 → 回传响应）也在这里，
//! 请求编排由 [`crate::protocol::dispatch`] 负责。

use crate::protocol::connect::send_bad_gateway;
use crate::protocol::forward::{ForwardTarget, UpstreamHead};
use crate::protocol::http_body::{forward_chunked_body, forward_content_length_body};
use crate::protocol::http_response::write_response;
use crate::support::buffer_pool::{AdaptiveBuffer, BufferPool};
use crate::support::net::{connect_host, is_benign_close_error};
use anyhow::Result;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// 响应拷贝结束原因（两条链路共用的统一契约）
#[derive(Debug)]
pub(crate) enum RelayOutcome {
    /// 上游 EOF，且已向客户端写出至少一段数据：响应正常收尾
    Completed,
    /// 写客户端失败：客户端已断开（调度方不得记 error，避免正常中断刷屏）
    ClientGone,
    /// 上游在写出任何数据前 EOF
    UpstreamClosed,
    /// 读上游超时
    TimedOut,
    /// 读上游出错；原始错误保留，调用方按 benign 与否决定日志级别
    UpstreamError(std::io::Error),
}

/// 流式转发响应体：一次读上游、一次写客户端，直到上游 EOF 或任一端断开。
///
/// 拷贝缓冲自适应（8KB 起步，长传输 / 大 body 翻倍到 256KB），中间不做额外分配。
/// 返回值附带循环结束时的缓冲大小（字节），供调用方沿用原有日志格式。
///
/// `Completed` 与 `UpstreamClosed` 的区分依据是"是否已向客户端写出过数据"：
/// 前者表示响应体正常收尾，后者表示上游在这次响应里一个字节都没给出。
pub(crate) async fn copy_upstream_to_client<S, T>(
    client: &mut S,
    upstream: &mut T,
    timeout: Duration,
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
                if client
                    .write_all(&copy.as_mut_slice()[..n])
                    .await
                    .is_err()
                {
                    return (RelayOutcome::ClientGone, copy.current_size());
                }
                wrote = true;
            }
            Ok(Err(e)) => return (RelayOutcome::UpstreamError(e), copy.current_size()),
            Err(_) => return (RelayOutcome::TimedOut, copy.current_size()),
        }
    }
}

/// 分帧头自相矛盾（多个不一致的 `Content-Length` / 非数字值）时的 400 响应
///
/// 只能拒绝、不能"挑一个用"：代理与上游对 body 边界的理解一旦不同，
/// 后续字节就会被解释成另一个请求（请求走私）。此处已确认是代理请求，
/// 返回 400 不会暴露代理特征。
async fn send_bad_request<W: AsyncWrite + Unpin>(client: &mut W) {
    write_response(
        client,
        "400 Bad Request",
        &[("Content-Type", "text/plain; charset=utf-8")],
        b"400 Bad Request",
    )
    .await;
}

/// 请求体转发所属链路（日志里用于区分经典代理与路径前缀）
#[derive(Clone, Copy)]
pub(super) enum RelayLink {
    Classic,
    PathPrefix,
}

impl RelayLink {
    fn label(self) -> &'static str {
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

/// 一次请求体转发的输入参数
///
/// 字段与 [`UpstreamHead`] 的产出一一对应，外加调用方上下文（超时、缓冲池、
/// 链路标签、客户端地址）；打包成结构体避免共享实现出现 9 个位置参数。
pub(super) struct RequestBodyForward<'a> {
    /// 已从 socket 读入的 body 前缀（可能已包含完整 body）
    pub buffered: &'a [u8],
    /// 请求头声明的 `Content-Length`（与 `chunked` 互斥）
    pub content_length: Option<u64>,
    /// 请求头声明了 `Transfer-Encoding: chunked`
    pub chunked: bool,
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
pub(super) async fn forward_request_body<S, T>(
    client: &mut S,
    upstream: &mut T,
    body: RequestBodyForward<'_>,
) -> std::io::Result<u64>
where
    S: AsyncRead + Unpin,
    T: AsyncWrite + Unpin,
{
    let RequestBodyForward {
        buffered,
        content_length,
        chunked,
        timeout,
        buffer_pool,
        link,
        client_addr,
    } = body;

    if chunked {
        return match forward_chunked_body(client, upstream, buffered, timeout, buffer_pool).await {
            Ok(()) => Ok(0),
            Err(e) => {
                log_body_error(link, client_addr, "chunked", &e);
                Err(e)
            }
        };
    }

    let Some(cl) = content_length else {
        // 无 Content-Length 且非 chunked：仅转发已缓冲字节
        if !buffered.is_empty() {
            if let Err(e) = upstream.write_all(buffered).await {
                log_body_error(link, client_addr, "buffered-only", &e);
                return Err(e);
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
            log_body_error(link, client_addr, "content-length", &e);
            Err(e)
        }
    }
}

/// 读上游响应并原样转发给客户端
///
/// 拷贝缓冲自适应（8KB 起步，长传输 / 大 body 翻倍到 256KB）：一次读 + 一次写，
/// 中间不做额外分配，也不解析响应语义（代理不关心内容）。
async fn relay_response<S>(
    client: &mut S,
    upstream: &mut TcpStream,
    target: &ForwardTarget<'_>,
    timeout: Duration,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let (outcome, copy_bytes) = copy_upstream_to_client(client, upstream, timeout).await;

    match outcome {
        // 正常收尾：完成日志在下方统一输出
        RelayOutcome::Completed => {}
        // 客户端断开：不记 error，避免正常下载中断刷屏
        RelayOutcome::ClientGone => {}
        RelayOutcome::UpstreamClosed => {
            debug!(
                "Upstream {}:{} closed before sending response body",
                target.connect_host, target.port
            );
        }
        RelayOutcome::TimedOut => {
            warn!("Response from {}:{} timed out", target.connect_host, target.port);
        }
        RelayOutcome::UpstreamError(e) => {
            if is_benign_close_error(&e) {
                debug!("Read from {}:{} ended: {}", target.connect_host, target.port, e);
            } else {
                warn!("Error reading from {}:{}: {}", target.connect_host, target.port, e);
            }
        }
    }

    debug!(
        "Response copy buffer for {}:{} ended at {} KB",
        target.connect_host,
        target.port,
        copy_bytes / 1024
    );

    Ok(())
}
/// 转发一次普通代理请求（认证已在调用前完成）
///
/// 四段流水线，每段可独立阅读与测试：
/// 1. [`ForwardTarget::parse`] —— 请求行 → 目标 host / port / origin-form
/// 2. 连接上游（`connect_host` 统一处理 IPv4 / IPv6 / DNS）
/// 3. [`UpstreamHead::build`] + [`forward_request_body`] —— 建头、转发 body
/// 4. [`relay_response`] —— 回传响应
pub(crate) async fn handle_http_request_generic<S>(
    mut client: S,
    request_data: &[u8],
    head_end: usize,
    client_addr: SocketAddr,
    timeout_duration: Duration,
    buffer_pool: BufferPool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let head_str = String::from_utf8_lossy(&request_data[..head_end]);
    let Some(target) = ForwardTarget::parse(&head_str, client_addr) else {
        return;
    };

    // 经典代理只服务明文 http。`https://` absolute-form 是客户端用错了协议：
    // 访问 https 站点必须先 CONNECT 建隧道、再在隧道内做 TLS，而不是把绝对 URL
    // 直接交给明文代理。这里直接 400，既不连接 443（明文打到 TLS 端口必然失败），
    // 也不假装成功，省掉一次注定失败的上游连接。
    if target.scheme != "http" {
        warn!(
            "{} -> unsupported scheme '{}' in absolute-form (use CONNECT for https)",
            client_addr, target.scheme
        );
        send_bad_request(&mut client).await;
        return;
    }

    info!(
        "{} -> {} {}:{} -> {}",
        client_addr, target.method, target.connect_host, target.port, target.url
    );

    // 先校验分帧头再连上游：畸形请求不该消耗一条到目标的连接（也避免把
    // 走私试探真的打到目标上）。
    let Some(head) = UpstreamHead::build(&target, &head_str) else {
        warn!(
            "{} -> malformed framing headers (conflicting or non-numeric Content-Length)",
            client_addr
        );
        send_bad_request(&mut client).await;
        return;
    };

    let mut upstream = match connect_host(&target.connect_host, target.port, timeout_duration).await {
        Ok(t) => t,
        Err(e) => {
            error!(
                "Failed to connect to {}:{} from {}: {}",
                target.connect_host, target.port, client_addr, e
            );
            send_bad_gateway(&mut client).await;
            return;
        }
    };

    if upstream.write_all(head.bytes.as_bytes()).await.is_err() {
        return;
    }

    // `Expect: 100-continue` 已从上游请求里剔除，临时响应必须由代理自己给：
    // 否则客户端会等一个永远不会来的 100，直到自己的等待超时才补发 body。
    if head.expect_continue
        && client
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .is_err()
    {
        return;
    }

    if forward_request_body(
        &mut client,
        &mut upstream,
        RequestBodyForward {
            buffered: &request_data[head_end..],
            content_length: head.content_length,
            chunked: head.chunked,
            timeout: timeout_duration,
            buffer_pool: &buffer_pool,
            link: RelayLink::Classic,
            client_addr,
        },
    )
    .await
    .is_err()
    {
        return;
    }

    let _ = relay_response(&mut client, &mut upstream, &target, timeout_duration).await;

    info!("Request completed: {} {}", target.method, target.url);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }
    /// `https://` absolute-form 必须以 400 拒绝，且**不能尝试连接上游**
    ///
    /// 用一个不可能连通的 host（`example.com` 的解析在单测里不保证成功，但即使成功
    /// 也会因为 400 提前返回）即可证明"先拒绝、后连接"的顺序：响应在 handler 内部
    /// 立刻写完，不依赖任何网络。
    #[tokio::test]
    async fn test_https_absolute_form_is_rejected_with_400() {
        let (client, mut proxy_side) = tokio::io::duplex(4096);
        let request = b"GET https://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n";

        handle_http_request_generic(
            client,
            request,
            request.len(),
            addr(),
            Duration::from_secs(1),
            BufferPool::new(),
        )
        .await;

        let mut resp = Vec::new();
        proxy_side
            .read_to_end(&mut resp)
            .await
            .expect("read 400 response from handler");

        let status_line = String::from_utf8_lossy(&resp)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string();
        assert_eq!(
            status_line, "HTTP/1.1 400 Bad Request",
            "https absolute-form 必须回 400，实际：{:?}",
            String::from_utf8_lossy(&resp)
        );
        assert!(
            !String::from_utf8_lossy(&resp).contains("Server:"),
            "错误响应不得暴露指纹头"
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

            peer.write_all(b"abc").await.unwrap();
            drop(peer);

            let sent = forward_request_body(
                &mut client,
                &mut upstream,
                RequestBodyForward {
                    buffered: &[],
                    content_length: Some(5),
                    chunked: false,
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
}
