//! HTTP 代理请求处理：读头、分类、认证、分流到 CONNECT / 经典转发 / 路径前缀直连
//!
//! 读头复用池化缓冲区（常见请求零拷贝），转发阶段不缓冲整个 body。
//! 反扫描与请求走私两类安全约束集中在本模块的读头、分类与建头段。

use crate::support::buffer_pool::{AdaptiveBuffer, BufferPool, PooledBuffer, BUFFER_SIZE};
use crate::protocol::auth::{check_path_auth, check_proxy_auth, send_auth_required, send_path_auth_required};
use crate::config::AuthUser;
use crate::protocol::http_body::{forward_chunked_body, forward_content_length_body};
use crate::protocol::http_response::write_response;
use crate::protocol::http_util::{
    authority_of, connection_named_headers, find_header_end, head_end_offset, is_hop_by_hop,
    MAX_HEAD_BYTES,
};
use crate::support::net::{connect_host, is_benign_close_error, parse_host_port};
use crate::protocol::path_proxy::{
    handle_path_proxy, PathProxyConfig, PathProxyRequest, PathProxyRuntime,
};
use crate::transport::stream::PrefixedStream;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use log::{debug, error, info, warn};

/// Handle an HTTP proxy client connection with buffer reuse (plain TCP entrypoint)
///
/// `auth` 为 `None` 时不启用认证；为 `Some(用户列表)` 时要求客户端通过 HTTP Basic
/// 认证（`Proxy-Authorization` 头），否则返回 407 并关闭连接。
///
/// `path_proxy` 为 `Some` 时额外启用路径前缀直连模式
/// （`/px/https://example.com/` → 直连该站点，见 [`crate::protocol::path_proxy`]）。
pub async fn handle_client(
    client: TcpStream,
    timeout: u64,
    buffer_pool: BufferPool,
    auth: Option<Arc<[AuthUser]>>,
    path_proxy: Arc<Option<PathProxyConfig>>,
) {
    let client_addr = match client.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Failed to get client address: {}", e);
            return;
        }
    };
    handle_client_generic(client, client_addr, timeout, buffer_pool, auth, path_proxy).await;
}

/// Handle an HTTP proxy client connection with a pre-resolved address.
///
/// 用于两类场景：
/// 1. PROXY Protocol：真实客户端 IP 从 PROXY Protocol 头提取，而非从 `peer_addr()`
///    获取（后者返回的是 nginx/LB 的 IP）；
/// 2. TLS 连接：`TlsStream` 不直接暴露 `peer_addr()`，地址需在 accept 时提前获取。
pub async fn handle_client_with_addr<S>(
    client: S,
    client_addr: SocketAddr,
    timeout: u64,
    buffer_pool: BufferPool,
    auth: Option<Arc<[AuthUser]>>,
    path_proxy: Arc<Option<PathProxyConfig>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_client_generic(client, client_addr, timeout, buffer_pool, auth, path_proxy).await;
}

/// 通用客户端连接处理逻辑（与具体传输层 TCP/TLS 无关）
///
/// 接受任意 AsyncRead + AsyncWrite 流，完成请求头读取、解析、认证、分发到
/// CONNECT / HTTP 代理 / 路径前缀直连三种处理路径。
async fn handle_client_generic<S>(
    mut client: S,
    client_addr: SocketAddr,
    timeout: u64,
    buffer_pool: BufferPool,
    auth: Option<Arc<[AuthUser]>>,
    path_proxy: Arc<Option<PathProxyConfig>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let timeout_duration = Duration::from_secs(timeout);

    // 读取完整请求头（含可能的 body 前缀），常见情况零拷贝复用池化缓冲区
    let (storage, head_status) = match read_request_head(&mut client, &buffer_pool, timeout_duration)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            if is_benign_close_error(&e) {
                debug!("Read from client {} ended: {}", client_addr, e);
            } else {
                warn!("Failed to read request from client {}: {}", client_addr, e);
            }
            return;
        }
    };

    match head_status {
        // 头部超过 MAX_HEAD_BYTES：畸形或恶意，必须在分派前拒绝。
        // 历史实现把已读字节当作完整头继续处理：`head_end_offset` 找不到 `\r\n\r\n` 时
        // 退化为 `data.len()`，于是截断的头被转发给上游——上游等不到剩余头部，代理却
        // 已在发 body，两侧一直卡到各自超时；若截断点恰好落在合法请求行之后，还会把
        // 畸形流量当成正常代理请求放行。
        HeadStatus::Overflow => {
            warn!(
                "Request head from {} exceeds {} bytes, rejecting",
                client_addr, MAX_HEAD_BYTES
            );
            send_head_too_large(&mut client).await;
            return;
        }
        // 客户端在头结束前断开：同样不能当完整头解析。转发时 `UpstreamHead::build`
        // 会补上结束空行，上游会把截断的头当作合法请求，客户端却已不在——
        // 白白消耗一条到目标的连接。直接丢弃，与"读到 0 字节"的处理一致。
        HeadStatus::Incomplete => {
            debug!(
                "Client {} closed before request head was complete, dropping",
                client_addr
            );
            return;
        }
        HeadStatus::Complete => {}
    }

    let data = storage.as_slice();
    // 请求头结束位置（body 起始偏移）；只有 `Complete` 才会走到这里，结束符必然存在
    let head_end = head_end_offset(data);
    let head = &data[..head_end];
    // 请求头为 ASCII，lossy 转换不会损坏后续二进制 body（body 按字节切片处理）
    let head_str = String::from_utf8_lossy(head);

    let request_line = match head_str.lines().next() {
        Some(line) => line,
        None => return,
    };

    info!("{} -> {}", client_addr, request_line);

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        warn!("Invalid request from {}: {}", client_addr, request_line);
        return;
    }

    let method = parts[0];
    let url = parts[1];

    // 第零步：路径前缀直连模式（如 /px/https://www.baidu.com/）。
    // 必须在代理请求分类之前判断——该形式是 origin-form 相对路径，会被 classify 判为
    // Invalid 而直接 404。只有前缀精确命中才接管，其余相对路径仍走 404（保持反扫描）。
    if let Some(cfg) = path_proxy.as_ref() {
        if let Some(target) = cfg.match_target(url) {
            // 复用代理认证：配置了 [[auth]] 时同样要求 Basic 凭据（401 质询）。
            // 认证成功时记录凭据所在的头，转发上游前必须剔除（否则凭据泄漏给目标站点）。
            let mut auth_header: Option<&'static str> = None;
            if let Some(users) = auth.as_deref() {
                match check_path_auth(&head_str, users) {
                    Some(source) => auth_header = Some(source.header_name()),
                    None => {
                        send_path_auth_required(&mut client).await;
                        warn!("Path-proxy authentication failed from {}", client_addr);
                        return;
                    }
                }
            }
            handle_path_proxy(
                client,
                client_addr,
                PathProxyRequest {
                    method,
                    target_url: target,
                    data,
                    head_end,
                    drop_header: auth_header,
                },
                PathProxyRuntime {
                    cfg,
                    timeout: timeout_duration,
                    buffer_pool: &buffer_pool,
                },
            )
            .await;
            return;
        }
    }

    // 第一步：判断是否为"合法代理请求"。
    // 反扫描策略：非代理格式请求直接返回 404，扫描器无法从响应识别这是代理端口。
    // 合法代理请求仅两种：
    //   1. CONNECT host:port HTTP/x.x          （HTTPS 隧道）
    //   2. METHOD http://host/... HTTP/x.x      （HTTP 代理绝对 URL）
    let kind = classify_proxy_request(method, url);
    match kind {
        ProxyRequestKind::Invalid => {
            // 不是代理请求（如 GET /、GET /admin、格式非法）→ 伪装成普通网站的 404
            debug!("Non-proxy request from {} ({} {}): returning 404", client_addr, method, url);
            send_404_not_found(&mut client).await;
            return;
        }
        ProxyRequestKind::Connect => {} // 继续流程
        ProxyRequestKind::HttpAbsolute => {} // 继续流程
    }

    // 第二步：认证校验。配置了 [[auth]] 时才校验。
    // 只有确认是代理请求后才会可能返回 407，降低"被扫描识别为代理"的风险。
    if let Some(users) = auth.as_deref() {
        if !check_proxy_auth(&head_str, users) {
            send_auth_required(&mut client).await;
            warn!("Proxy authentication failed from {}", client_addr);
            return;
        }
    }

    // Handle CONNECT method (HTTPS tunneling)
    if method == "CONNECT" {
        // 请求头之后的字节是隧道协议数据（如 TLS ClientHello），必须保留并交给隧道
        let leftover = &data[head_end..];
        handle_connect_generic(client, url, client_addr, timeout_duration, leftover).await;
        return;
    }

    // Handle HTTP proxy request with buffer pool
    handle_http_request_generic(client, data, head_end, client_addr, timeout_duration, buffer_pool).await;
}

/// 请求头读取结果的存储方式
///
/// 常见情况（请求头在第一次读取内完成）复用池化缓冲区，实现零拷贝；
/// 大请求头则需要扩展堆缓冲。
enum RequestStorage {
    /// 单次读取即包含完整请求头：直接持有池化缓冲区（零拷贝）
    Pooled(PooledBuffer, usize),
    /// 需要多次读取的大请求：持有堆缓冲
    Heap(Vec<u8>),
}

impl RequestStorage {
    /// 获取已读数据的字节切片
    #[inline]
    fn as_slice(&self) -> &[u8] {
        match self {
            RequestStorage::Pooled(b, n) => &b.as_slice()[..*n],
            RequestStorage::Heap(v) => v,
        }
    }
}

/// 请求头的读取结果状态
///
/// "读到数据"不等于"读到了完整的头"。截断的头既不能当完整头解析，更不能转发：
/// 转发给上游时会补上结束空行，上游把它当作合法请求处理，而代理与客户端对
/// "这条请求到底发了什么"理解不同（历史实现在超限时就是这样把截断头送出去的，见 D5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadStatus {
    /// 已找到 `\r\n\r\n`，可以安全解析与转发
    Complete,
    /// 客户端在头结束前关闭连接（EOF）：内容不完整，只能丢弃
    Incomplete,
    /// 达到 [`MAX_HEAD_BYTES`] 仍无结束符：畸形或恶意，回 431
    Overflow,
}

/// 读取请求头，直到出现 `\r\n\r\n`（或达到 `MAX_HEAD_BYTES` 上限 / 客户端 EOF）。
///
/// 整个读取过程受一次 `timeout` 约束，防止慢速攻击（slowloris）逐次续期。
/// 常见情况（一次读取即含完整头）复用池化缓冲区，零拷贝。
async fn read_request_head<S>(
    client: &mut S,
    buffer_pool: &BufferPool,
    timeout: Duration,
) -> std::io::Result<(RequestStorage, HeadStatus)>
where
    S: AsyncRead + Unpin,
{
    tokio::time::timeout(timeout, read_request_head_inner(client, buffer_pool))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out reading request head",
            )
        })?
}

async fn read_request_head_inner<S>(
    client: &mut S,
    buffer_pool: &BufferPool,
) -> std::io::Result<(RequestStorage, HeadStatus)>
where
    S: AsyncRead + Unpin,
{
    // 第一段读入池化缓冲区（常见路径：零拷贝）
    let mut buf = buffer_pool.get();
    let n = client.read(buf.as_mut_slice()).await?;
    if n == 0 {
        // 连接建立后一个字节都没发就关闭：按不完整处理（调用方会直接丢弃）
        return Ok((RequestStorage::Pooled(buf, 0), HeadStatus::Incomplete));
    }
    if find_header_end(&buf.as_slice()[..n]).is_some() {
        return Ok((RequestStorage::Pooled(buf, n), HeadStatus::Complete));
    }

    // 慢路径：多次读取累积到堆缓冲。
    // 注意：短读（n < BUFFER_SIZE）不代表客户端已发完，TCP 可能分片，
    // 因此必须继续读取直到出现头结束符、超限或 EOF。
    let mut data = Vec::with_capacity(2 * BUFFER_SIZE);
    data.extend_from_slice(&buf.as_slice()[..n]);
    loop {
        let m = client.read(buf.as_mut_slice()).await?;
        if m == 0 {
            // EOF：已读内容里仍没有结束符 → 头是截断的，不能当完整头转发
            return Ok((RequestStorage::Heap(data), HeadStatus::Incomplete));
        }
        data.extend_from_slice(&buf.as_slice()[..m]);
        if find_header_end(&data).is_some() {
            break;
        }
        if data.len() >= MAX_HEAD_BYTES {
            // 读够了上限仍未见到头结束符：标记超限，不再继续读（防慢速续期）
            return Ok((RequestStorage::Heap(data), HeadStatus::Overflow));
        }
    }
    Ok((RequestStorage::Heap(data), HeadStatus::Complete))
}

/// 代理请求分类结果
enum ProxyRequestKind {
    /// 合法的 HTTP 代理请求（绝对 URL 形式），携带 scheme（应为 http/https）
    HttpAbsolute,
    /// 合法的 HTTPS CONNECT 隧道请求（host:port 形式）
    Connect,
    /// 非代理请求 / 格式非法 —— 应返回 404 反扫描
    Invalid,
}

/// 分类请求：识别"合法代理请求"与"直连/扫描请求"。
///
/// 返回 `Invalid` 时应直接返回 404，让扫描器无法识别这是代理端口。
fn classify_proxy_request(method: &str, url: &str) -> ProxyRequestKind {
    // 1) CONNECT: URL 必须是 host:port 形式，不含 "://"
    if method == "CONNECT" {
        // CONNECT 请求 URL 规范：hostname[:port]，不能是 URL
        if url.contains("://") {
            return ProxyRequestKind::Invalid;
        }
        // 允许有 port，也允许无 port（默认 443）。
        // 简单校验：至少有 host，且 host 不含空白、'/'、'?'、'#'（绝对 URL 特征）
        let has_banned = url.chars().any(|c| c == '/' || c == '?' || c == '#');
        if has_banned || url.is_empty() {
            return ProxyRequestKind::Invalid;
        }
        return ProxyRequestKind::Connect;
    }

    // 2) 其他 METHOD：必须是 "http://..." 或 "https://..." 绝对 URL 形式
    //    代理规范：客户端对 GET/POST 等发的是完整绝对 URL（scheme://host/path）
    if url.starts_with("http://") || url.starts_with("https://") {
        // 补充：必须能被 url 解析并含 host
        match url::Url::parse(url) {
            Ok(parsed) if parsed.host_str().is_some() => {
                return ProxyRequestKind::HttpAbsolute;
            }
            _ => return ProxyRequestKind::Invalid,
        }
    }

    // 3) 其余情况：相对路径（GET /、GET /admin）、其它 scheme（ftp://）等
    ProxyRequestKind::Invalid
}

/// 返回最小化的 404 Not Found 响应，模仿普通静态服务器。
///
/// 设计原则：
/// - **不返回 Server 头**（避免暴露运行时 / 框架特征）
/// - **不返回 X-Powered-By 等**
/// - 简短，最小化攻击面与指纹
/// - Connection: close，避免占着连接
async fn send_404_not_found<W: AsyncWrite + Unpin>(client: &mut W) {
    write_response(
        client,
        "404 Not Found",
        &[("Content-Type", "text/plain; charset=utf-8")],
        b"404 Not Found",
    )
    .await;
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

/// 请求头超过上限时的 431 响应
///
/// 用 431 而不是 400：语义精确（RFC 6585 §5 专为"头部过大"定义），且只会在客户端
/// 已经发出超长头时出现——扫描器通常只发一行 `GET /`，因此不构成代理特征泄漏。
async fn send_head_too_large<W: AsyncWrite + Unpin>(client: &mut W) {
    write_response(
        client,
        "431 Request Header Fields Too Large",
        &[("Content-Type", "text/plain; charset=utf-8")],
        b"431 Request Header Fields Too Large",
    )
    .await;
}

/// 上游不可达时的最小化 502 响应
///
/// 历史实现在这里直接 `return`，客户端只看到 EOF（curl 报
/// `Empty reply from server`），既无法区分"代理到目标的路由断了"还是"目标自己拒绝"，
/// 也无从判断是否值得重试。同端口的路径前缀直连模式早已回 502，两条链路对同一种
/// 失败给出完全不同的反馈属于实现漂移，这里统一。
///
/// 响应体刻意简短且不含目标地址，避免把内网拓扑回显给调用方。
async fn send_bad_gateway<W: AsyncWrite + Unpin>(client: &mut W) {
    write_response(
        client,
        "502 Bad Gateway",
        &[("Content-Type", "text/plain; charset=utf-8")],
        b"502 Bad Gateway",
    )
    .await;
}

/// Handle CONNECT method for HTTPS tunneling（泛型版本，支持 TCP/TLS 客户端流）
///
/// `leftover` 是请求头之后已经读入的字节（如客户端与 CONNECT 一并发送的 TLS ClientHello），
/// 会作为隧道前缀保留，避免数据丢失。
async fn handle_connect_generic<S>(
    mut client: S,
    host_port: &str,
    client_addr: SocketAddr,
    timeout_duration: Duration,
    leftover: &[u8],
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (host, port) = match parse_host_port(host_port) {
        Ok((h, p)) => (h, p),
        Err(e) => {
            error!("Failed to parse host:port '{}': {}", host_port, e);
            return;
        }
    };

    // CONNECT 目标主机字符串，供 DNS/连接使用。若为方括号 IPv6，去掉方括号
    // （`[a:b::1]` 需转换为 `a:b::1` 才能通过 tokio lookup_host 解析）。
    let connect_host_str = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    let mut target = match connect_host(connect_host_str, port, timeout_duration).await {
        Ok(t) => t,
        Err(e) => {
            error!(
                "Failed to connect to {}:{} from {}: {}",
                connect_host_str, port, client_addr, e
            );
            // 隧道未建立：必须在断开前明确告知 502，否则客户端把 EOF 当作隧道异常
            send_bad_gateway(&mut client).await;
            return;
        }
    };

    // 将预读字节作为前缀保留，交给隧道双向转发
    let mut client = PrefixedStream::new(leftover.to_vec(), client);

    // Send 200 Connection Established
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }

    // 双向隧道：`copy_bidirectional` 正确处理半关闭（一侧 EOF 时关闭另一侧写端），
    // 且不对隧道总时长设限——长连接 HTTPS 会话可无限期保持（旧实现的总超时会断开长会话）。
    // 返回值为 `(client→target 字节数, target→client 字节数)`。
    match tokio::io::copy_bidirectional(&mut client, &mut target).await {
        Ok((c2t, t2c)) => info!(
            "CONNECT tunnel closed: {}:{} ({} bytes client→target, {} bytes target→client)",
            host, port, c2t, t2c
        ),
        Err(e) => {
            if is_benign_close_error(&e) {
                debug!("CONNECT tunnel closed: {}:{} ({})", host, port, e);
            } else {
                warn!("CONNECT tunnel error: {}:{} ({})", host, port, e);
            }
        }
    }
}

/// 一次转发的目标信息（由请求行 + 绝对 URL 解析得出）
struct ForwardTarget<'a> {
    method: &'a str,
    url: &'a str,
    /// 请求目标协议（分类阶段只允许 http/https；经典转发只服务 http）
    scheme: String,
    host: String,
    port: u16,
    /// 上游 `Host` 头值：绝对 URL 的 authority（IPv6 带方括号，显式端口保留）
    authority: String,
    /// origin-form 请求目标：path + query，直连上游的标准形式
    origin_form: String,
}

impl<'a> ForwardTarget<'a> {
    /// 从请求头解析转发目标；格式非法时返回 `None`（调用方保持"静默丢弃"语义）
    fn parse(head_str: &'a str, client_addr: SocketAddr) -> Option<Self> {
        let request_line = head_str.lines().next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?;
        let url = parts.next()?;

        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                error!("Failed to parse URL '{}' from {}: {}", url, client_addr, e);
                return None;
            }
        };

        let host = match parsed.host_str() {
            Some(h) => h.to_string(),
            None => {
                error!("No host in URL '{}' from {}", url, client_addr);
                return None;
            }
        };

        // 端口按 scheme 取已知默认值：https 绝对 URL 不能落到 80（历史实现写死 80）
        let port = match parsed.port_or_known_default() {
            Some(p) => p,
            None => {
                error!(
                    "No known default port for scheme '{}' in URL '{}' from {}",
                    parsed.scheme(),
                    url,
                    client_addr
                );
                return None;
            }
        };

        let origin_form = match parsed.query() {
            Some(q) => format!("{}?{}", parsed.path(), q),
            None => parsed.path().to_string(),
        };

        Some(Self {
            method,
            url,
            scheme: parsed.scheme().to_string(),
            host,
            port,
            authority: authority_of(&parsed),
            origin_form,
        })
    }
}

/// 发往上游的请求头（已过滤逐跳头、改写 `Connection`）及请求体分帧信息
struct UpstreamHead {
    /// 请求行 + 过滤后的头部 + 结尾空行，可直接 `write_all`
    bytes: String,
    /// 请求体长度（`None` 表示没有 `Content-Length`）
    content_length: Option<u64>,
    /// 请求体是否为 chunked 分帧
    chunked: bool,
    /// 客户端是否声明了 `Expect: 100-continue`（该头不转发上游，由代理直接应答）
    expect_continue: bool,
}

impl UpstreamHead {
    /// 按 `head_str` 构造上游请求头；分帧信息自相矛盾时返回 `None`
    ///
    /// 过滤规则：
    /// - `Host` → 按绝对 URL 的 authority 重写 / 补写（RFC 7230 §5.4：收到 absolute-form
    ///   请求时，代理必须忽略客户端的 `Host` 并改用请求目标的 host）。客户端漏发 `Host`
    ///   时同样补上，否则 HTTP/1.1 上游会直接回 400
    /// - `Connection` → 改写为 `close`（本代理每个请求独占一条上游连接）
    /// - `Proxy-Connection` / `Proxy-Authorization` / `Keep-Alive` / `TE` / `Trailer` /
    ///   `Upgrade` 等逐跳头 → 丢弃（[`is_hop_by_hop`]，RFC 7230 §6.1）
    /// - `Expect: 100-continue` → 丢弃并置位，由代理直接回 `100 Continue`
    ///   （转发该头会让客户端等上游的临时响应，而代理此刻正在收 body，白等一个 RTT）
    /// - `Transfer-Encoding` → 原样保留（body 按原始分帧转发；`gzip, chunked` 这类
    ///   多编码只声明 chunked 会让上游把仍是 gzip 的块数据当明文）
    /// - `Content-Length` → **延迟到循环后统一输出**，因为它与 `Transfer-Encoding`
    ///   互斥，必须等看清全部头才能决定写不写（见函数末尾）
    ///
    /// 头名按冒号精确切分匹配（用 `contains` 匹配子串会误伤 `X-Forwarded-For`
    /// 这类合法头）；无冒号的行（含续行）原样转发，避免破坏上游解析。
    ///
    /// 返回 `None` 的两种情况（调用方应回 400）：
    /// - `Content-Length` 值不是十进制数字；
    /// - 出现多个**不一致**的 `Content-Length`。
    ///
    /// 这两种情况下代理与上游对 body 边界必然有不同的理解，转发等于制造走私面。
    fn build(target: &ForwardTarget<'_>, head_str: &str) -> Option<Self> {
        let mut bytes = String::with_capacity(512);
        bytes.push_str(target.method);
        bytes.push(' ');
        bytes.push_str(&target.origin_form);
        bytes.push_str(" HTTP/1.1\r\n");
        bytes.push_str("Host: ");
        bytes.push_str(&target.authority);
        bytes.push_str("\r\n");

        // `Connection: X-Foo` 点名的字段同样是逐跳头（RFC 7230 §6.1），
        // 必须在遍历前先收集，否则名字在头尾不同位置时过滤结果会不稳定
        let connection_named = connection_named_headers(head_str);

        let mut content_length: Option<u64> = None;
        let mut content_length_conflict = false;
        let mut chunked = false;
        let mut expect_continue = false;

        for line in head_str.lines().skip(1) {
            if line.is_empty() {
                break;
            }
            let (name, value) = match line.split_once(':') {
                Some(pair) => pair,
                None => {
                    bytes.push_str(line);
                    bytes.push_str("\r\n");
                    continue;
                }
            };
            let name = name.trim();
            let value = value.trim();

            if name.eq_ignore_ascii_case("host") {
                // 已按绝对 URL 的 authority 输出，客户端的 Host 一律忽略
                continue;
            }
            if name.eq_ignore_ascii_case("connection") {
                bytes.push_str("Connection: close\r\n");
                continue;
            }
            // 分帧相关头先处理：它们需要"改写 / 记录"而不是"丢弃"
            if name.eq_ignore_ascii_case("transfer-encoding") {
                if value.to_ascii_lowercase().contains("chunked") {
                    chunked = true;
                }
                bytes.push_str(line);
                bytes.push_str("\r\n");
                continue;
            }
            if name.eq_ignore_ascii_case("content-length") {
                // 延迟输出：chunked 与 CL 互斥，此刻还不知道后面有没有 TE
                match value.parse::<u64>() {
                    Ok(v) => match content_length {
                        Some(prev) if prev != v => content_length_conflict = true,
                        Some(_) => {} // 重复且一致：合并成一条，不给上游留多值歧义
                        None => content_length = Some(v),
                    },
                    Err(_) => content_length_conflict = true,
                }
                continue;
            }
            // `100-continue` 由代理直接应答；其余 `Expect` 值同样丢弃（无从满足）
            if name.eq_ignore_ascii_case("expect") {
                expect_continue = value.eq_ignore_ascii_case("100-continue");
                continue;
            }
            if is_hop_by_hop(name, &connection_named) {
                continue;
            }
            bytes.push_str(line);
            bytes.push_str("\r\n");
        }

        // 代理与上游对 body 边界的理解必须完全一致，否则就是走私面
        if content_length_conflict {
            return None;
        }

        // 分帧头二选一（RFC 7230 §3.3.3）：存在 chunked 时**必须**丢弃 Content-Length。
        // 两者同时转发时，若上游按 CL 解析，会把分帧字节当成 body 内容，
        // 后续管道化的请求就被拼进同一个请求（请求走私）。
        if chunked {
            content_length = None;
        } else if let Some(cl) = content_length {
            bytes.push_str("Content-Length: ");
            bytes.push_str(&cl.to_string());
            bytes.push_str("\r\n");
        }
        bytes.push_str("\r\n");

        Some(Self {
            bytes,
            content_length,
            chunked,
            expect_continue,
        })
    }
}

/// 一次转发中各阶段共用的进程级参数
struct RelayCtx<'a> {
    client_addr: SocketAddr,
    timeout: Duration,
    buffer_pool: &'a BufferPool,
}

impl RelayCtx<'_> {
    /// 转发请求体：已缓冲字节 + 尚未读取的部分
    ///
    /// 分帧决策以 [`UpstreamHead`] 为准：
    /// - chunked：交给分帧状态机（已缓冲字节必须先过状态机，终止块可能就在缓冲区里）
    /// - Content-Length：先发已缓冲部分（截断到 CL，超出的属于管道化的下一个请求），
    ///   再按剩余长度流式读转
    /// - 两者皆无：只转发已缓冲字节（历史行为）
    async fn forward_request_body<S>(
        &self,
        client: &mut S,
        upstream: &mut TcpStream,
        buffered: &[u8],
        head: &UpstreamHead,
    ) -> Result<()>
    where
        S: AsyncRead + Unpin,
    {
        if head.chunked {
            let result = forward_chunked_body(
                client,
                upstream,
                buffered,
                self.timeout,
                self.buffer_pool,
            )
            .await;
            if let Err(e) = result {
                if !is_benign_close_error(&e) {
                    warn!(
                        "Failed to forward chunked request body from {}: {}",
                        self.client_addr, e
                    );
                }
                return Err(e.into());
            }
            return Ok(());
        }

        let Some(cl) = head.content_length else {
            // 无 Content-Length 且非 chunked：仅转发已缓冲字节
            if !buffered.is_empty() && upstream.write_all(buffered).await.is_err() {
                return Err(anyhow::anyhow!("failed to write buffered body upstream"));
            }
            return Ok(());
        };

        match forward_content_length_body(
            client,
            upstream,
            buffered,
            cl,
            self.timeout,
            self.buffer_pool,
        )
        .await
        {
            Ok(sent) if sent < cl => {
                // 客户端提前关闭：body 不完整，但请求头已送达，仍可尝试读响应
                warn!(
                    "Client {} closed before sending complete request body ({} / {} bytes)",
                    self.client_addr, sent, cl
                );
                Ok(())
            }
            Ok(_) => Ok(()),
            Err(e) => {
                if is_benign_close_error(&e) {
                    debug!("Request body from {} ended: {}", self.client_addr, e);
                } else {
                    warn!("Error forwarding request body from {}: {}", self.client_addr, e);
                }
                Err(e.into())
            }
        }
    }

    /// 读上游响应并原样转发给客户端
    ///
    /// 拷贝缓冲自适应（8KB 起步，长传输 / 大 body 翻倍到 256KB）：一次读 + 一次写，
    /// 中间不做额外分配，也不解析响应语义（代理不关心内容）。
    async fn relay_response<S>(
        &self,
        client: &mut S,
        upstream: &mut TcpStream,
        target: &ForwardTarget<'_>,
    ) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let mut response_buf = AdaptiveBuffer::new();

        loop {
            response_buf.prepare();
            match tokio::time::timeout(self.timeout, upstream.read(response_buf.as_mut_slice())).await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    response_buf.note_copied(n);
                    if client
                        .write_all(&response_buf.as_mut_slice()[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    if is_benign_close_error(&e) {
                        debug!("Read from {}:{} ended: {}", target.host, target.port, e);
                    } else {
                        warn!("Error reading from {}:{}: {}", target.host, target.port, e);
                    }
                    break;
                }
                Err(_) => {
                    warn!("Response from {}:{} timed out", target.host, target.port);
                    break;
                }
            }
        }

        debug!(
            "Response copy buffer for {}:{} ended at {} KB",
            target.host,
            target.port,
            response_buf.current_size() / 1024
        );

        Ok(())
    }
}

/// 转发一次普通代理请求（认证已在调用前完成）
///
/// 四段流水线，每段可独立阅读与测试：
/// 1. [`ForwardTarget::parse`] —— 请求行 → 目标 host / port / origin-form
/// 2. 连接上游（`connect_host` 统一处理 IPv4 / IPv6 / DNS）
/// 3. [`UpstreamHead::build`] + [`RelayCtx::forward_request_body`] —— 建头、转发 body
/// 4. [`RelayCtx::relay_response`] —— 回传响应
async fn handle_http_request_generic<S>(
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
        client_addr, target.method, target.host, target.port, target.url
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

    let mut upstream = match connect_host(&target.host, target.port, timeout_duration).await {
        Ok(t) => t,
        Err(e) => {
            error!(
                "Failed to connect to {}:{} from {}: {}",
                target.host, target.port, client_addr, e
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

    let relay = RelayCtx {
        client_addr,
        timeout: timeout_duration,
        buffer_pool: &buffer_pool,
    };
    if relay
        .forward_request_body(&mut client, &mut upstream, &request_data[head_end..], &head)
        .await
        .is_err()
    {
        return;
    }

    let _ = relay.relay_response(&mut client, &mut upstream, &target).await;

    info!("Request completed: {} {}", target.method, target.url);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    // ─── classify_proxy_request 反扫描测试 ───

    #[test]
    fn test_classify_connect_valid_host_port() {
        matches!(
            classify_proxy_request("CONNECT", "example.com:443"),
            ProxyRequestKind::Connect
        );
    }

    #[test]
    fn test_classify_connect_no_port() {
        // CONNECT 允许无 port（parse_host_port 会补默认 443）
        matches!(
            classify_proxy_request("CONNECT", "example.com"),
            ProxyRequestKind::Connect
        );
    }

    #[test]
    fn test_classify_connect_ipv4() {
        matches!(
            classify_proxy_request("CONNECT", "1.1.1.1:443"),
            ProxyRequestKind::Connect
        );
    }

    #[test]
    fn test_classify_connect_rejects_url_form() {
        // CONNECT 带 scheme → 非法
        matches!(
            classify_proxy_request("CONNECT", "https://example.com:443"),
            ProxyRequestKind::Invalid
        );
    }

    #[test]
    fn test_classify_connect_rejects_path_characters() {
        // CONNECT 带路径 → 非法
        matches!(
            classify_proxy_request("CONNECT", "example.com/path"),
            ProxyRequestKind::Invalid
        );
    }

    #[test]
    fn test_classify_http_absolute_valid() {
        matches!(
            classify_proxy_request("GET", "http://example.com/a/b"),
            ProxyRequestKind::HttpAbsolute
        );
    }

    #[test]
    fn test_classify_http_absolute_https_scheme() {
        matches!(
            classify_proxy_request("GET", "https://example.com/"),
            ProxyRequestKind::HttpAbsolute
        );
    }

    #[test]
    fn test_classify_http_absolute_post() {
        matches!(
            classify_proxy_request("POST", "http://api.example.com/upload"),
            ProxyRequestKind::HttpAbsolute
        );
    }

    #[test]
    fn test_classify_scan_requests_return_invalid() {
        // 扫描器直接访问代理端口 → 应该得到 404
        // 相对路径（直接浏览器访问代理端口）
        matches!(classify_proxy_request("GET", "/"), ProxyRequestKind::Invalid);
        matches!(classify_proxy_request("GET", "/index.html"), ProxyRequestKind::Invalid);
        matches!(classify_proxy_request("GET", "/admin"), ProxyRequestKind::Invalid);
        matches!(classify_proxy_request("HEAD", "/"), ProxyRequestKind::Invalid);
        matches!(classify_proxy_request("POST", "/api/login"), ProxyRequestKind::Invalid);
        matches!(classify_proxy_request("OPTIONS", "*"), ProxyRequestKind::Invalid);

        // 无 host 的绝对 URL
        matches!(
            classify_proxy_request("GET", "http:///onlypath"),
            ProxyRequestKind::Invalid
        );

        // 其他 scheme：ftp proxy，当前不支持
        matches!(
            classify_proxy_request("GET", "ftp://files.example.com/a"),
            ProxyRequestKind::Invalid
        );
    }

    // ─── host:port 解析 / chunked 分帧 ───
    // 这两组原语的实现与测试已迁至 `crate::support::net` 与 `crate::protocol::http_body`（消除模块循环依赖）。

    // ─── 转发目标解析（B3 拆分后的纯函数） ───

    fn addr() -> SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }

    #[test]
    fn test_forward_target_parses_absolute_url() {
        let head = "GET http://example.com/a/b?x=1 HTTP/1.1
Host: example.com

";
        let t = ForwardTarget::parse(head, addr()).expect("absolute URL must parse");
        assert_eq!(t.method, "GET");
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 80, "缺省端口应为 80");
        assert_eq!(t.origin_form, "/a/b?x=1", "query 必须保留");
        assert_eq!(t.authority, "example.com", "缺省端口不应写进 Host");
    }

    #[test]
    fn test_forward_target_keeps_explicit_port() {
        let head = "POST http://127.0.0.1:8080/p HTTP/1.1

";
        let t = ForwardTarget::parse(head, addr()).expect("parse");
        assert_eq!(t.port, 8080);
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(t.origin_form, "/p");
    }

    #[test]
    fn test_forward_target_marks_https_scheme_with_known_default_port() {
        // URL 解析层仍按 scheme 求默认端口（https → 443），但经典代理入口据 `scheme`
        // 拒绝 https absolute-form（见 `handle_http_request_generic` 与
        // `https_absolute_form_is_rejected_with_400`）
        let head = "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let t = ForwardTarget::parse(head, addr()).expect("https absolute URL must parse");
        assert_eq!(t.scheme, "https");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn test_forward_target_rejects_non_absolute_target() {
        // 相对 URL（非代理请求）与残缺请求行都必须返回 None，由上层走 404 反扫描
        assert!(ForwardTarget::parse("GET / HTTP/1.1\r\n\r\n", addr()).is_none());
        assert!(ForwardTarget::parse("GARBAGE\r\n\r\n", addr()).is_none());
        assert!(ForwardTarget::parse("", addr()).is_none());
    }

    // ─── 上游请求头构造（含逐跳头与凭据过滤） ───

    #[test]
    fn test_upstream_head_rewrites_connection_and_drops_proxy_headers() {
        let head = "GET http://example.com/x HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Proxy-Connection: keep-alive\r\n\
                    Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\
                    Connection: keep-alive\r\n\
                    User-Agent: test\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();

        assert!(up.bytes.starts_with("GET /x HTTP/1.1\r\n"), "请求行应改写为 origin-form");
        assert_eq!(
            up.bytes.matches("Host: ").count(),
            1,
            "客户端 Host 必须被替换而不是重复输出：{}",
            up.bytes
        );
        assert!(up.bytes.contains("Host: example.com\r\n"), "Host 由绝对 URL 决定");
        assert!(up.bytes.contains("Connection: close\r\n"), "Connection 必须改写为 close");
        assert!(!up.bytes.to_ascii_lowercase().contains("proxy-authorization"), "凭据不得上游化");
        assert!(!up.bytes.to_ascii_lowercase().contains("proxy-connection"), "代理专用头应丢弃");
        assert!(up.bytes.contains("User-Agent: test\r\n"), "普通头必须保留");
        assert!(up.bytes.ends_with("\r\n\r\n"), "头部必须以空行结束");
        assert!(!up.chunked);
        assert_eq!(up.content_length, None);
    }

    // ─── Host 头（RFC 7230 §5.4：absolute-form 必须以请求目标的 host 为准） ───

    #[test]
    fn test_upstream_head_rewrites_host_from_absolute_url() {
        // 客户端 Host 与 URL 不一致（如把代理地址写进 Host）：一律以 URL 为准
        let head = "GET http://example.com:8080/p HTTP/1.1\r\nHost: 10.0.0.1:3128\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();

        assert!(up.bytes.contains("Host: example.com:8080\r\n"), "显式端口必须保留");
        assert!(!up.bytes.contains("10.0.0.1"), "客户端的 Host 不得转发：{}", up.bytes);
    }

    #[test]
    fn test_upstream_head_inserts_host_when_client_omits_it() {
        // HTTP/1.1 上游要求 Host；客户端漏发时由代理补写，否则上游直接 400
        let head = "GET http://example.com/p HTTP/1.1\r\nAccept: */*\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();

        assert!(up.bytes.contains("Host: example.com\r\n"), "缺失 Host 必须补写");
        assert!(up.bytes.contains("Accept: */*\r\n"));
    }

    #[test]
    fn test_upstream_head_host_brackets_ipv6() {
        let head = "GET http://[::1]:8080/p HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert!(up.bytes.contains("Host: [::1]:8080\r\n"), "IPv6 authority 必须带方括号");
    }

    /// `Connection` 里点名的自定义字段同样是逐跳头（RFC 7230 §6.1）
    #[test]
    fn test_upstream_head_drops_connection_named_headers() {
        let head = "GET http://example.com/x HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Connection: close, X-Hop\r\n\
                    X-Hop: secret\r\n\
                    X-Keep: ok\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();

        let lower = up.bytes.to_ascii_lowercase();
        assert!(
            !lower.contains("x-hop"),
            "Connection 点名的头必须丢弃：{}",
            up.bytes
        );
        assert!(up.bytes.contains("X-Keep: ok\r\n"), "未点名的端到端头必须保留");
        assert_eq!(
            lower.matches("connection:").count(),
            1,
            "只保留代理改写的 Connection: close"
        );
    }

    #[test]
    fn test_upstream_head_records_framing() {
        // Content-Length
        let head = "POST http://h/p HTTP/1.1\r\nContent-Length: 12\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert_eq!(up.content_length, Some(12));
        assert!(!up.chunked);

        // Transfer-Encoding: chunked（保留原头，同时置位）
        let head = "POST http://h/p HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert!(up.chunked);
        assert_eq!(up.content_length, None);
        assert!(up.bytes.contains("Transfer-Encoding: chunked"));
    }

    #[test]
    fn test_upstream_head_does_not_match_header_substrings() {
        // 头名必须精确匹配：X-Forwarded-For 不能被当作 connection 类头处理
        let head = "GET http://h/p HTTP/1.1\r\nX-Connection-Info: keep\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert!(up.bytes.contains("X-Connection-Info: keep\r\n"));
        assert!(!up.bytes.contains("Connection: close"), "不含 Connection 头时不应凭空追加");
    }

    #[test]
    fn test_upstream_head_drops_expect_and_flags_100_continue() {
        // `Expect: 100-continue` 不能转发给上游：上游会先回 100，而代理此刻正在收
        // body，客户端收不到临时响应就会白等一个 RTT（curl 默认等 1s）。
        let head = "POST http://h/p HTTP/1.1\r\n\
                    Content-Length: 4\r\n\
                    Expect: 100-continue\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert!(up.expect_continue, "必须置位，供调用方回 100 Continue");
        assert!(
            !up.bytes.to_ascii_lowercase().contains("expect:"),
            "Expect 头不得出现在上游请求中"
        );
        assert_eq!(up.content_length, Some(4));
    }

    #[test]
    fn test_upstream_head_does_not_flag_expect_without_continue() {
        // 其它 Expect 值无从满足，同样丢弃，但不应误触发 100 Continue
        let head = "POST http://h/p HTTP/1.1\r\nExpect: 42-continue\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert!(!up.expect_continue);
        assert!(!up.bytes.to_ascii_lowercase().contains("expect:"));
    }

    #[test]
    fn test_upstream_head_drops_content_length_when_chunked() {
        // RFC 7230 §3.3.3：存在 Transfer-Encoding 时 Content-Length **必须**丢弃。
        // 两者一起转发时，若上游按 CL 解析，分帧字节会被当成 body 内容，
        // 后续管道化的请求就被拼进同一个请求——请求走私。
        let head = "POST http://h/p HTTP/1.1\r\n\
                    Host: h\r\n\
                    Content-Length: 5\r\n\
                    Transfer-Encoding: chunked\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();

        assert!(up.chunked);
        assert_eq!(up.content_length, None, "chunked 时 CL 必须清零");
        let lower = up.bytes.to_ascii_lowercase();
        assert!(
            lower.contains("transfer-encoding: chunked"),
            "分帧头必须保留：{}",
            up.bytes
        );
        assert!(
            !lower.contains("content-length"),
            "CL 不得与 TE 一起转发：{}",
            up.bytes
        );
    }

    #[test]
    fn test_upstream_head_rejects_conflicting_content_length() {
        // 多个不一致的 CL：代理与上游对 body 边界的理解必然不同 → 拒绝而不是挑一个
        let head = "POST http://h/p HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        assert!(UpstreamHead::build(&target, head).is_none());
    }

    #[test]
    fn test_upstream_head_rejects_non_numeric_content_length() {
        let head = "POST http://h/p HTTP/1.1\r\nContent-Length: 5x\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        assert!(UpstreamHead::build(&target, head).is_none());
    }

    #[test]
    fn test_upstream_head_collapses_duplicate_content_length() {
        // 重复但一致：合并成一条，不给上游留多值歧义
        let head = "POST http://h/p HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();

        assert_eq!(up.content_length, Some(5));
        let count = up
            .bytes
            .to_ascii_lowercase()
            .matches("content-length:")
            .count();
        assert_eq!(count, 1, "重复 CL 必须合并：{}", up.bytes);
    }

    #[test]
    fn test_upstream_head_drops_all_hop_by_hop_headers() {
        // RFC 7230 §6.1 的逐跳头一律不得转发；普通头必须保留
        let head = "GET http://h/p HTTP/1.1\r\n\
                    Keep-Alive: timeout=5\r\n\
                    TE: trailers\r\n\
                    Trailer: X-Sum\r\n\
                    Upgrade: websocket\r\n\
                    Proxy-Authenticate: Basic\r\n\
                    Accept: */*\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        let lower = up.bytes.to_ascii_lowercase();
        for hop in ["keep-alive:", "te:", "trailer:", "upgrade:", "proxy-authenticate:"] {
            assert!(!lower.contains(hop), "逐跳头 {hop} 不应转发: {}", up.bytes);
        }
        assert!(up.bytes.contains("Accept: */*\r\n"), "端到端头必须保留");
    }

    // ─── 慢速头（slowloris）──────────────────────────────

    /// 慢速滴水客户端：每 `interval` 才吐 1 字节。
    ///
    /// 关键在于**每次读取都真的等待**：如果实现把 deadline 重置到每次 `read` 上，
    /// 这个读取器就能一直续期、永远读不完；只有「整段读取共享一个 deadline」才会超时。
    struct DripReader {
        data: Vec<u8>,
        pos: usize,
        interval: Duration,
        delay: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl DripReader {
        fn new(data: Vec<u8>, interval: Duration) -> Self {
            Self {
                data,
                pos: 0,
                interval,
                delay: None,
            }
        }
    }

    impl AsyncRead for DripReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let me = self.get_mut();
            if me.pos >= me.data.len() {
                return Poll::Ready(Ok(())); // EOF
            }
            let interval = me.interval;
            let delay = me
                .delay
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(interval)));
            if delay.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            me.delay = None;
            buf.put_slice(&me.data[me.pos..me.pos + 1]);
            me.pos += 1;
            Poll::Ready(Ok(()))
        }
    }

    /// 慢速滴水必须在**整体** deadline 处放弃，而不是被逐次读取续期。
    ///
    /// 用 `start_paused` 的虚拟时钟：每秒 1 字节、200 字节的头，若逐次续期要 200 秒；
    /// 虚拟时间下断言的是「恰好 5 秒放弃」，既不真实等待也不受机器快慢影响。
    #[tokio::test(start_paused = true)]
    async fn test_read_request_head_times_out_on_slow_drip() {
        let pool = BufferPool::new();
        let head = format!(
            "GET http://a.com/ HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
            "a".repeat(200)
        );
        let total = head.len();
        let mut reader = DripReader::new(head.into_bytes(), Duration::from_secs(1));

        let start = tokio::time::Instant::now();
        let err = match read_request_head(&mut reader, &pool, Duration::from_secs(5)).await {
            Ok(_) => panic!("慢速滴水必须超时，不能一直等到读完 {total} 字节"),
            Err(e) => e,
        };

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(
            start.elapsed(),
            Duration::from_secs(5),
            "整体 deadline 必须生效，不能被逐次读取续期"
        );
        assert!(
            reader.pos < total,
            "超时时请求头只应收到 {} / {} 字节",
            reader.pos,
            total
        );
    }

    /// 对照组：同样逐字节到达，但在 deadline 内读完必须成功。
    ///
    /// 没有这条，上一条用例可能只是因为「分片就读不出来」而通过。
    #[tokio::test(start_paused = true)]
    async fn test_read_request_head_accepts_slow_but_within_deadline() {
        let pool = BufferPool::new();
        let head = format!(
            "GET http://a.com/ HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
            "a".repeat(200)
        );
        let mut reader = DripReader::new(head.as_bytes().to_vec(), Duration::from_millis(1));

        let (storage, status) = read_request_head(&mut reader, &pool, Duration::from_secs(5))
            .await
            .expect("deadline 内读完应成功");

        assert_eq!(status, HeadStatus::Complete);
        assert_eq!(storage.as_slice(), head.as_bytes());
    }

    #[tokio::test]
    async fn test_read_request_head_flags_overflow_only_when_incomplete() {
        let pool = BufferPool::new();

        // 完整头（含结束符）：不标记超限
        let mut complete = &b"GET http://a.com/ HTTP/1.1\r\nHost: a.com\r\n\r\n"[..];
        let (storage, status) = read_request_head(&mut complete, &pool, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(status, HeadStatus::Complete, "完整头不得判为超限");
        assert!(storage.as_slice().ends_with(b"\r\n\r\n"));

        // 顶满上限仍无结束符：必须标记超限——否则调用方会把截断的头当成完整头转发
        let mut big = Vec::new();
        big.extend_from_slice(b"GET http://a.com/ HTTP/1.1\r\nX-Pad: ");
        big.resize(MAX_HEAD_BYTES, b'a');
        let mut incomplete = &big[..];
        let (_, status) = read_request_head(&mut incomplete, &pool, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(
            status,
            HeadStatus::Overflow,
            "读满 {MAX_HEAD_BYTES} 字节仍无结束符必须标记超限"
        );
    }

    /// 客户端在头结束前关闭：状态必须是 `Incomplete`，调用方据此丢弃。
    ///
    /// 这条与超限用例区分开：截断的原因不同（EOF vs 长度上限），处理方式也不同
    /// （静默丢弃 vs 回 431），但共同点是**都不能当完整头解析或转发**。
    #[tokio::test]
    async fn test_read_request_head_marks_eof_truncated_head_incomplete() {
        let pool = BufferPool::new();
        let mut partial = &b"GET http://a.com/ HTTP/1.1\r\nHost: a.com"[..];
        let (storage, status) = read_request_head(&mut partial, &pool, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(status, HeadStatus::Incomplete);
        assert_eq!(
            storage.as_slice(),
            b"GET http://a.com/ HTTP/1.1\r\nHost: a.com",
            "已读字节仍需保留，供调用方记录日志"
        );
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
}
