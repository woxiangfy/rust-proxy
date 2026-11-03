//! Proxy module containing HTTP proxy request handling logic with zero-copy buffer reuse

use crate::buffer_pool::{AdaptiveBuffer, BufferPool, PooledBuffer, BUFFER_SIZE};
use crate::config::AuthUser;
use crate::http_body::forward_chunked_body;
use crate::http_util::{find_header_end, head_end_offset, MAX_HEAD_BYTES};
use crate::io::PrefixedStream;
use crate::net::{connect_host, is_benign_close_error, parse_host_port, AsyncStream};
use crate::path_proxy::{handle_path_proxy, PathProxyConfig};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::{TlsConnector, native_tls};
use log::{debug, error, info, warn};

/// Handle an HTTP proxy client connection with buffer reuse (plain TCP entrypoint)
///
/// `auth` 为 `None` 时不启用认证；为 `Some(用户列表)` 时要求客户端通过 HTTP Basic
/// 认证（`Proxy-Authorization` 头），否则返回 407 并关闭连接。
///
/// `path_proxy` 为 `Some` 时额外启用路径前缀直连模式
/// （`/px/https://example.com/` → 直连该站点，见 [`crate::path_proxy`]）。
pub async fn handle_client(
    client: TcpStream,
    timeout: u64,
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<AuthUser>>>,
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
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<AuthUser>>>,
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
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<AuthUser>>>,
    path_proxy: Arc<Option<PathProxyConfig>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let timeout_duration = Duration::from_secs(timeout);

    // 读取完整请求头（含可能的 body 前缀），常见情况零拷贝复用池化缓冲区
    let storage = match read_request_head(&mut client, &buffer_pool, timeout_duration).await {
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

    let data = storage.as_slice();
    if data.is_empty() {
        return;
    }

    // 请求头结束位置（body 起始偏移）；未找到头结束符时视为整个数据都是头
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
            if let Some(users) = auth.as_ref() {
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
                method,
                target,
                data,
                head_end,
                cfg,
                timeout_duration,
                &buffer_pool,
                auth_header,
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
    if let Some(users) = auth.as_ref() {
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

/// 读取请求头，直到出现 `\r\n\r\n`（或达到 `MAX_HEAD_BYTES` 上限 / 客户端 EOF）。
///
/// 整个读取过程受一次 `timeout` 约束，防止慢速攻击（slowloris）逐次续期。
/// 常见情况（一次读取即含完整头）复用池化缓冲区，零拷贝。
async fn read_request_head<S>(
    client: &mut S,
    buffer_pool: &BufferPool,
    timeout: Duration,
) -> std::io::Result<RequestStorage>
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
) -> std::io::Result<RequestStorage>
where
    S: AsyncRead + Unpin,
{
    // 第一段读入池化缓冲区（常见路径：零拷贝）
    let mut buf = buffer_pool.get();
    let n = client.read(buf.as_mut_slice()).await?;
    if n == 0 {
        return Ok(RequestStorage::Pooled(buf, 0));
    }
    if find_header_end(&buf.as_slice()[..n]).is_some() {
        return Ok(RequestStorage::Pooled(buf, n));
    }

    // 慢路径：多次读取累积到堆缓冲。
    // 注意：短读（n < BUFFER_SIZE）不代表客户端已发完，TCP 可能分片，
    // 因此必须继续读取直到出现头结束符、超限或 EOF。
    let mut data = Vec::with_capacity(2 * BUFFER_SIZE);
    data.extend_from_slice(&buf.as_slice()[..n]);
    loop {
        let m = client.read(buf.as_mut_slice()).await?;
        if m == 0 {
            break; // EOF：用已有数据返回
        }
        data.extend_from_slice(&buf.as_slice()[..m]);
        if find_header_end(&data).is_some() || data.len() >= MAX_HEAD_BYTES {
            break;
        }
    }
    Ok(RequestStorage::Heap(data))
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
    let body = b"404 Not Found";
    let response = format!(
        "HTTP/1.1 404 Not Found\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = client.write_all(response.as_bytes()).await;
    let _ = client.write_all(body).await;
}

/// 校验请求中的 `Proxy-Authorization` 头是否符合配置的用户列表。
///
/// 实现标准 HTTP Basic 认证（RFC 7617）：从请求头中提取
/// `Proxy-Authorization: Basic <base64(user:pass)>`，解码后与 `users` 比对。
/// 头缺失、方案不符、Base64 解码失败或凭据不匹配均返回 `false`。
fn check_proxy_auth(request_data: &str, users: &[AuthUser]) -> bool {
    match extract_basic_credentials(request_data, "proxy-authorization") {
        Some(creds) => verify_basic_credentials(creds, users),
        None => false,
    }
}

/// 路径前缀直连模式下用于认证的请求头来源。
///
/// 认证成功后需要把该头从转发给上游的请求中剔除，否则代理凭据会泄漏给目标站点。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathAuthSource {
    /// `Authorization`：浏览器/普通客户端收到 401 质询后发送
    Authorization,
    /// `Proxy-Authorization`：脚本或 curl 以代理方式携带凭据
    ProxyAuthorization,
}

impl PathAuthSource {
    /// 该来源对应的请求头名（小写）
    pub(crate) fn header_name(self) -> &'static str {
        match self {
            PathAuthSource::Authorization => "authorization",
            PathAuthSource::ProxyAuthorization => "proxy-authorization",
        }
    }
}

/// 校验路径前缀直连模式的认证凭据。
///
/// 该模式是「直接访问网址」而非「配置代理」，因此优先读取 `Authorization`
/// （浏览器/普通 HTTP 客户端在收到 401 质询后发送），同时也接受
/// `Proxy-Authorization`，便于用脚本或 curl 以代理方式携带凭据。
///
/// 返回实际认证成功的头来源（`None` 表示认证失败），调用方据此把该头从
/// 上游请求中移除——只移除"真正被用来认证"的那一个，另一个可留给目标站点使用。
pub(crate) fn check_path_auth(
    request_data: &str,
    users: &[AuthUser],
) -> Option<PathAuthSource> {
    for source in [
        PathAuthSource::Authorization,
        PathAuthSource::ProxyAuthorization,
    ] {
        if let Some(creds) = extract_basic_credentials(request_data, source.header_name()) {
            if verify_basic_credentials(creds, users) {
                return Some(source);
            }
        }
    }
    None
}

/// 校验 `Basic` 凭据（base64 的 `user:pass`）是否命中用户列表
fn verify_basic_credentials(credentials: &str, users: &[AuthUser]) -> bool {
    // Base64 解码凭据
    let decoded = match BASE64_STANDARD.decode(credentials.trim()) {
        Ok(d) => d,
        Err(_) => return false,
    };

    // 解码结果应为 "username:password"（按第一个冒号拆分，密码中允许包含冒号）
    let decoded_str = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let (username, password) = match decoded_str.split_once(':') {
        Some((u, p)) => (u, p),
        None => return false,
    };

    users
        .iter()
        .any(|u| u.username == username && u.password == password)
}

/// 从原始请求数据中提取 `<header>: Basic <credentials>` 的凭据部分。
///
/// 头名匹配不区分大小写，仅识别 Basic 方案；遇到空行（请求头结束）即停止搜索。
/// 不含冒号的行（如绝对形式的请求行）会被跳过而非导致整体失败。
fn extract_basic_credentials<'a>(request_data: &'a str, header_name: &str) -> Option<&'a str> {
    for line in request_data.lines() {
        if line.is_empty() {
            // 空行标志请求头结束
            break;
        }
        let (name, value) = match line.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        if !name.trim().eq_ignore_ascii_case(header_name) {
            continue;
        }
        let value = value.trim();
        // 格式: "Basic <base64>"
        let (scheme, creds) = match value.split_once(char::is_whitespace) {
            Some(pair) => pair,
            None => continue,
        };
        if scheme.eq_ignore_ascii_case("basic") {
            return Some(creds);
        }
    }
    None
}

/// 向客户端发送 407 Proxy Authentication Required 响应，要求 Basic 认证。
///
/// 泛型版本兼容 TCP 和 TLS 流。
async fn send_auth_required<W: AsyncWrite + Unpin>(client: &mut W) {
    // Connection: close 使客户端重连时携带认证头重试
    let response = "HTTP/1.1 407 Proxy Authentication Required\r\n\
        Proxy-Authenticate: Basic realm=\"rust-proxy\"\r\n\
        Content-Length: 0\r\n\
        Connection: close\r\n\r\n";
    let _ = client.write_all(response.as_bytes()).await;
}

/// 向客户端发送 401 Unauthorized 质询（路径前缀直连模式使用）。
///
/// 该模式下客户端并未「配置代理」，407 + `Proxy-Authenticate` 不会被浏览器处理
/// （只会渲染 407 错误页且不弹登录框）；因此改用 401 + `WWW-Authenticate`，
/// 浏览器会正常弹出 Basic 登录框。
async fn send_path_auth_required<W: AsyncWrite + Unpin>(client: &mut W) {
    let response = "HTTP/1.1 401 Unauthorized\r\n\
        WWW-Authenticate: Basic realm=\"rust-proxy\"\r\n\
        Content-Length: 0\r\n\
        Connection: close\r\n\r\n";
    let _ = client.write_all(response.as_bytes()).await;
}

/// Handle CONNECT method for HTTPS tunneling（泛型版本，支持 TCP/TLS 客户端流）
///
/// `leftover` 是请求头之后已经读入的字节（如客户端与 CONNECT 一并发送的 TLS ClientHello），
/// 会作为隧道前缀保留，避免数据丢失。
async fn handle_connect_generic<S>(
    client: S,
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

/// Handle standard HTTP proxy request with buffer reuse（泛型版本，支持 TCP/TLS 客户端流）
///
/// `request_data` 为已读入的全部数据（头 + 可能的 body 前缀），`head_end` 为 body 起始偏移。
/// 请求行以 origin-form 转发给目标服务器（旧实现遗漏请求行，导致明文 HTTP 代理失效）。
/// body 按 Content-Length / Transfer-Encoding: chunked 流式转发，支持大请求体。
async fn handle_http_request_generic<S>(
    mut client: S,
    request_data: &[u8],
    head_end: usize,
    client_addr: SocketAddr,
    timeout_duration: Duration,
    buffer_pool: Arc<BufferPool>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let head = &request_data[..head_end];
    let head_str = String::from_utf8_lossy(head);
    let mut lines = head_str.lines();

    let request_line = match lines.next() {
        Some(line) => line,
        None => return,
    };

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }

    let method = parts[0];
    let url = parts[1];

    // Parse URL to get host and port
    let parsed_url = match url::Url::parse(url) {
        Ok(u) => u,
        Err(e) => {
            error!("Failed to parse URL '{}' from {}: {}", url, client_addr, e);
            return;
        }
    };

    let host = match parsed_url.host_str() {
        Some(h) => h,
        None => {
            error!("No host in URL '{}' from {}", url, client_addr);
            return;
        }
    };

    let port = parsed_url.port().unwrap_or(80);

    info!("{} -> {} {}:{} -> {}", client_addr, method, host, port, url);

    let mut target = match connect_host(host, port, timeout_duration).await {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to connect to {}:{} from {}: {}", host, port, client_addr, e);
            return;
        }
    };

    // 转发请求行：origin-form（path + query），这是直连目标服务器的标准形式
    let target_path = match parsed_url.query() {
        Some(q) => format!("{}?{}", parsed_url.path(), q),
        None => parsed_url.path().to_string(),
    };
    let mut header_buffer = String::with_capacity(512);
    header_buffer.push_str(method);
    header_buffer.push(' ');
    header_buffer.push_str(&target_path);
    header_buffer.push_str(" HTTP/1.1\r\n");

    // 解析头部并过滤逐跳头（proxy-connection、proxy-authorization，避免凭据泄漏）；
    // 保留 transfer-encoding（body 以原始 chunked 分帧转发）；connection 改写为 close。
    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        // 精确按头名匹配（旧实现用 contains 匹配子串，会误伤合法头）
        let (name, value) = match line.split_once(':') {
            Some(pair) => pair,
            None => {
                // 无冒号的行（如续行）原样转发
                header_buffer.push_str(line);
                header_buffer.push_str("\r\n");
                continue;
            }
        };
        let name = name.trim();
        let value = value.trim();

        if name.eq_ignore_ascii_case("connection") {
            header_buffer.push_str("Connection: close\r\n");
            continue;
        }
        if name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("proxy-authorization")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if value.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
            header_buffer.push_str(line);
            header_buffer.push_str("\r\n");
            continue;
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse::<u64>().ok();
            header_buffer.push_str(line);
            header_buffer.push_str("\r\n");
            continue;
        }
        header_buffer.push_str(line);
        header_buffer.push_str("\r\n");
    }
    header_buffer.push_str("\r\n");

    if target.write_all(header_buffer.as_bytes()).await.is_err() {
        return;
    }

    // 转发 body：按 chunked / Content-Length 流式转发（已缓冲的字节一并交给下游处理）
    let buffered_body = &request_data[head_end..];

    if chunked {
        // 流式转发 chunked 请求体，直到终止块（0\r\n\r\n）。
        // 已缓冲字节必须交给分帧状态机消费——终止块可能就落在缓冲区里，
        // 若先原样写出再读 socket，状态机会永远等不到结束而挂住。
        let result = forward_chunked_body(
            &mut client,
            &mut target,
            buffered_body,
            timeout_duration,
            &buffer_pool,
        )
        .await;
        if let Err(e) = result {
            if !is_benign_close_error(&e) {
                warn!("Failed to forward chunked request body from {}: {}", client_addr, e);
            }
            return;
        }
    } else {
        // 非 chunked：先转发已缓冲字节，超出 Content-Length 的部分属于管道化下一个请求
        let mut buffered = buffered_body;
        if let Some(cl) = content_length {
            if buffered.len() as u64 > cl {
                buffered = &buffered[..cl as usize];
            }
        }
        if !buffered.is_empty() && target.write_all(buffered).await.is_err() {
            return;
        }

        if let Some(cl) = content_length {
            // 按 Content-Length 精确流式转发剩余 body（支持大文件上传）
            let already_sent = buffered.len() as u64;
            if cl > already_sent {
                let mut remaining = cl - already_sent;
                let mut tmp = buffer_pool.get();
                let tmp_slice = tmp.as_mut_slice();
                loop {
                    let want = std::cmp::min(remaining as usize, tmp_slice.len());
                    let m =
                        match tokio::time::timeout(timeout_duration, client.read(&mut tmp_slice[..want]))
                            .await
                        {
                            Ok(Ok(m)) => m,
                            Ok(Err(e)) => {
                                if !is_benign_close_error(&e) {
                                    warn!("Error reading request body from {}: {}", client_addr, e);
                                }
                                return;
                            }
                            Err(_) => {
                                warn!("Timeout reading request body from {}", client_addr);
                                return;
                            }
                        };
                    if m == 0 {
                        // 客户端提前关闭，body 不完整
                        warn!("Client {} closed before sending complete request body", client_addr);
                        break;
                    }
                    if target.write_all(&tmp_slice[..m]).await.is_err() {
                        return;
                    }
                    remaining -= m as u64;
                    if remaining == 0 {
                        break;
                    }
                }
            }
        }
    }
    // 无 Content-Length 且非 chunked：仅转发已缓冲字节（历史行为）

    // 读取响应并转发给客户端：拷贝缓冲自适应（8KB 起步，长传输/大body 翻倍到 256KB）
    let mut response_buf = AdaptiveBuffer::new();

    loop {
        response_buf.prepare();
        match tokio::time::timeout(timeout_duration, target.read(response_buf.as_mut_slice())).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                response_buf.note_copied(n);
                // 直接从缓冲区写到客户端（一次读 + 一次写，零中间分配）
                if client.write_all(&response_buf.as_mut_slice()[..n]).await.is_err() {
                    break;
                }
            }
            Ok(Err(e)) => {
                if is_benign_close_error(&e) {
                    debug!("Read from {}:{} ended: {}", host, port, e);
                } else {
                    warn!("Error reading from {}:{}: {}", host, port, e);
                }
                break;
            }
            Err(_) => {
                warn!("Response from {}:{} timed out", host, port);
                break;
            }
        }
    }

    debug!(
        "Response copy buffer for {}:{} ended at {} KB",
        host,
        port,
        response_buf.current_size() / 1024
    );

    info!("Request completed: {} {}", method, url);
}

/// Extract `(username, password)` from the userinfo component of a proxy URL.
///
/// The `url` crate does not expose passwords by default (security feature),
/// so we manually parse the `user:pass@host` portion from the raw URL string.
///
/// Returns `(None, None)` when no credentials are present.
fn extract_userinfo(proxy_url: &str) -> (Option<String>, Option<String>) {
    // Format: scheme://user:pass@host:port/path
    // We look for '@' that separates userinfo from host, which must appear
    // after "://" and before any '/', '?', or '#' in the authority component.
    let after_scheme = match proxy_url.find("://") {
        Some(idx) => &proxy_url[idx + 3..],
        None => return (None, None),
    };

    // Find the last '@' before the authority ends (i.e. before '/', '?', '#')
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];

    if let Some(at_pos) = authority.rfind('@') {
        let userinfo = &authority[..at_pos];
        if userinfo.is_empty() {
            return (None, None);
        }
        let (user, pass) = match userinfo.split_once(':') {
            Some((u, p)) => (u.to_string(), p.to_string()),
            None => (userinfo.to_string(), String::new()),
        };
        (Some(user), Some(pass))
    } else {
        (None, None)
    }
}

/// Build `Proxy-Authorization: Basic <base64>` header value.
///
/// Credentials are resolved from (highest priority first):
/// 1. Explicit `username`/`password` CLI arguments
/// 2. `user:pass` embedded in the proxy URL (userinfo component)
///
/// Returns `None` when no credentials are provided at all.
fn build_proxy_auth_header(
    proxy_url: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Option<String> {
    let (user, pass) = match (username, password) {
        (Some(u), Some(p)) => (u.to_string(), p.to_string()),
        (Some(u), None) => (u.to_string(), String::new()),
        (None, Some(p)) => {
            // password given without username → empty user (matches curl behavior)
            (String::new(), p.to_string())
        }
        (None, None) => {
            // Fall back to URL userinfo (manual parsing, url crate hides password)
            match extract_userinfo(proxy_url) {
                (Some(u), Some(p)) => (u, p),
                _ => return None,
            }
        }
    };

    // Format: Basic <base64(user:pass)>。空密码也保留冒号，与服务端 `split_once(':')` 解析保持一致。
    let credentials = format!("{}:{}", user, pass);
    let encoded = BASE64_STANDARD.encode(credentials.as_bytes());
    Some(format!("Basic {}", encoded))
}

/// Test a proxy server.
///
/// `proxy_url` 是代理服务器 URL，必须显式包含协议：
///   - `http://host:port` — 通过明文 TCP 连接代理
///   - `https://host:port` — 通过 TLS 连接代理，**跳过证书验证**
///     （等价于 `curl --proxy-insecure`），以支持自签证书场景
///
/// 支持代理认证：
///   - 在 URL 中嵌入：`http://user:pass@host:port`（curl 风格）
///   - 或通过 `--username` / `--password` CLI 参数（优先级高于 URL）
///
/// `test_url` 是目标 URL，必须包含 `http://` 或 `https://` 协议头。
/// 对 HTTPS 目标，会先通过代理建立 CONNECT 隧道，再与目标服务器做 TLS 握手。
pub async fn test_proxy(
    proxy_url: &str,
    test_url: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    // 解析代理 URL，提取协议、主机、端口
    let proxy = url::Url::parse(proxy_url)
        .with_context(|| format!("Invalid proxy URL: {}. Must include http:// or https:// scheme.", proxy_url))?;
    let proxy_scheme = proxy.scheme();
    if proxy_scheme != "http" && proxy_scheme != "https" {
        anyhow::bail!(
            "Proxy URL must start with http:// or https://, got: {}",
            proxy_url
        );
    }
    let proxy_host = proxy.host_str()
        .with_context(|| format!("No host in proxy URL: {}", proxy_url))?
        .to_string();
    let proxy_port = proxy.port()
        .unwrap_or(if proxy_scheme == "https" { 443 } else { 80 });
    let proxy_addr = format!("{}:{}", proxy_host, proxy_port);

    // 解析目标 URL
    let parsed = url::Url::parse(test_url)
        .with_context(|| format!("Invalid test URL: {}", test_url))?;
    let target_scheme = parsed.scheme();
    if target_scheme != "http" && target_scheme != "https" {
        anyhow::bail!(
            "Test URL must start with http:// or https://, got: {}",
            test_url
        );
    }
    let host = parsed.host_str()
        .with_context(|| format!("No host in URL: {}", test_url))?
        .to_string();
    let default_port = if target_scheme == "https" { 443 } else { 80 };
    let port = parsed.port().unwrap_or(default_port);
    let host_header = if port == default_port {
        host.clone()
    } else {
        format!("{}:{}", host, port)
    };

    // 解析代理认证（CLI 参数优先于 URL userinfo）
    let proxy_auth_header = build_proxy_auth_header(proxy_url, username, password);

    let start = std::time::Instant::now();
    let tcp_stream = tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(&proxy_addr))
        .await
        .with_context(|| format!("Timeout connecting to proxy {}", proxy_addr))?
        .with_context(|| format!("Failed to connect to proxy {}", proxy_addr))?;

    // 若代理为 HTTPS：用 TLS 包装 TCP 连接
    // danger_accept_invalid_certs=true 以支持自签证书（等价于 curl --proxy-insecure）
    let proxy_stream: Box<dyn AsyncStream> = if proxy_scheme == "https" {
        let mut tls_builder = native_tls::TlsConnector::builder();
        tls_builder.danger_accept_invalid_certs(true);
        let native_connector = tls_builder.build()?;
        let tls_connector = TlsConnector::from(native_connector);
        Box::new(
            tokio::time::timeout(Duration::from_secs(30), tls_connector.connect(&proxy_host, tcp_stream))
                .await
                .with_context(|| "Timeout during TLS handshake with proxy")?
                .with_context(|| "TLS handshake with proxy failed")?,
        )
    } else {
        Box::new(tcp_stream)
    };

    // 对 HTTPS 目标：通过代理建立 CONNECT 隧道后再做 TLS
    let mut stream: Box<dyn AsyncStream> = if target_scheme == "https" {
            // Build CONNECT request with optional proxy auth header
            let mut connect_req = format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
                host, port, host, port
            );
            if let Some(ref auth) = proxy_auth_header {
                connect_req.push_str(&format!("Proxy-Authorization: {}\r\n", auth));
            }
            connect_req.push_str("\r\n");

            let mut stream = proxy_stream;
            tokio::time::timeout(Duration::from_secs(30), stream.write_all(connect_req.as_bytes()))
                .await
                .with_context(|| "Timeout sending CONNECT")?
                .with_context(|| "Failed to send CONNECT")?;

            // Read until end of CONNECT response headers
            let mut header_buf = [0u8; 4096];
            let mut n = 0;
            loop {
                let r = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut header_buf[n..]))
                    .await
                    .with_context(|| "Timeout reading CONNECT response")?
                    .with_context(|| "Failed to read CONNECT response")?;
                if r == 0 {
                    anyhow::bail!("Proxy closed connection during CONNECT");
                }
                n += r;
                if header_buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if n == header_buf.len() {
                    anyhow::bail!("CONNECT response headers too large");
                }
            }

            let connect_resp = String::from_utf8_lossy(&header_buf[..n]);
            let status_line = connect_resp.lines().next().unwrap_or("");

            // Handle 407: proxy authentication required
            if status_line.starts_with("HTTP/1.1 407") || status_line.starts_with("HTTP/1.0 407") {
                anyhow::bail!(
                    "CONNECT failed: {} — proxy requires authentication. \
                     Provide credentials via URL (http://user:pass@host:port) or --username/--password flags.",
                    status_line
                );
            }
            if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
                anyhow::bail!("CONNECT failed: {}", status_line);
            }

            // Upgrade to TLS (use system CA roots to verify target cert)
            let cx = TlsConnector::from(native_tls::TlsConnector::new()?);
            Box::new(cx.connect(&host, stream).await?)
        } else {
            proxy_stream
        };

    let request_target = if target_scheme == "https" {
        format!(
            "{}{}",
            parsed.path(),
            parsed.query().map(|q| format!("?{}", q)).unwrap_or_default()
        )
    } else {
        test_url.to_string()
    };

    // Build final HTTP request with optional proxy auth header
    let mut request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: rust-proxy/{}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n",
        request_target, host_header, env!("CARGO_PKG_VERSION")
    );
    if let Some(ref auth) = proxy_auth_header {
        request.push_str(&format!("Proxy-Authorization: {}\r\n", auth));
    }
    request.push_str("\r\n");

    tokio::time::timeout(Duration::from_secs(30), stream.write_all(request.as_bytes()))
        .await
        .with_context(|| "Timeout writing request")?
        .with_context(|| "Failed to write request")?;

    let mut buf = Vec::new();
    let mut temp = [0u8; 8192];
    loop {
        match tokio::time::timeout(Duration::from_secs(30), stream.read(&mut temp))
            .await
            .with_context(|| "Timeout reading response")?
        {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&temp[..n]),
            Err(e) => return Err(e.into()),
        }
    }

    let elapsed = start.elapsed();
    let response = String::from_utf8_lossy(&buf);

    println!("Proxy:    {}", proxy_url);
    println!("Test URL: {}", test_url);
    if let Some(ref auth) = proxy_auth_header {
        println!("Auth:     Proxy-Authorization: {}", auth);
    }
    println!("Duration: {:?}", elapsed);
    println!("Response:\n{}", response);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_users() -> Vec<AuthUser> {
        vec![AuthUser {
            username: "admin".into(),
            password: "secret".into(),
        }]
    }

    #[test]
    fn test_auth_valid_basic() {
        // "admin:secret" -> base64 "YWRtaW46c2VjcmV0"
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n\
            Host: example.com\r\n\r\n";
        assert!(check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_missing_header_rejected() {
        let req = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_wrong_password_rejected() {
        // "admin:wrong" -> base64 "YWRtaW46d3Jvbmc="
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic YWRtaW46d3Jvbmc=\r\n\
            Host: example.com\r\n\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_wrong_username_rejected() {
        // "root:secret" -> base64 "cm9vdDpzZWNyZXQ="
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic cm9vdDpzZWNyZXQ=\r\n\
            Host: example.com\r\n\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_non_basic_scheme_rejected() {
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Digest abc123\r\n\
            Host: example.com\r\n\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_invalid_base64_rejected() {
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic !!!not-base64!!!\r\n\
            Host: example.com\r\n\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_header_name_case_insensitive() {
        // 头名小写、方案小写
        let req = "CONNECT example.com:443 HTTP/1.1\r\n\
            proxy-authorization: basic YWRtaW46c2VjcmV0\r\n\
            Host: example.com\r\n\r\n";
        assert!(check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_scheme_case_insensitive() {
        // 方案大写也应识别
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: BASIC YWRtaW46c2VjcmV0\r\n\
            Host: example.com\r\n\r\n";
        assert!(check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_multiple_users_match_any() {
        let users = vec![
            AuthUser {
                username: "admin".into(),
                password: "secret".into(),
            },
            AuthUser {
                username: "guest".into(),
                password: "guest".into(),
            },
        ];
        // "guest:guest" -> base64 "Z3Vlc3Q6Z3Vlc3Q="
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=\r\n\
            Host: example.com\r\n\r\n";
        assert!(check_proxy_auth(req, &users));
    }

    #[test]
    fn test_auth_password_with_colon_supported() {
        // 密码 "p:a:s:s" 按第一个冒号拆分，密码部分为 "a:s:s"
        let users = vec![AuthUser {
            username: "u".into(),
            password: "a:s:s".into(),
        }];
        // "u:a:s:s" -> base64
        let creds = BASE64_STANDARD.encode("u:a:s:s");
        let req = format!(
            "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic {}\r\n\
            Host: example.com\r\n\r\n",
            creds
        );
        assert!(check_proxy_auth(&req, &users));
    }

    #[test]
    fn test_auth_stops_at_empty_line() {
        // 头部以空行结束，之后的 Proxy-Authorization 不应被采纳
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Host: example.com\r\n\r\n\
            Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_extract_authorization_from_connect() {
        let req = "CONNECT example.com:443 HTTP/1.1\r\n\
            Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n\
            Host: example.com:443\r\n\r\n";
        assert_eq!(
            extract_basic_credentials(req, "proxy-authorization"),
            Some("YWRtaW46c2VjcmV0")
        );
    }

    #[test]
    fn test_extract_authorization_none_when_absent() {
        let req = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_basic_credentials(req, "proxy-authorization"), None);
    }

    // ─── 路径前缀直连模式的认证 ───

    #[test]
    fn test_path_auth_accepts_authorization_header() {
        // 浏览器/直连客户端走标准 Authorization 头
        let req = "GET /px/https://example.com/ HTTP/1.1\r\n\
            Authorization: Basic YWRtaW46c2VjcmV0\r\n\
            Host: proxy.local\r\n\r\n";
        // 返回来源头名，供上层转发时剔除（避免凭据泄漏给目标站点）
        assert_eq!(
            check_path_auth(req, &make_users()),
            Some(PathAuthSource::Authorization)
        );
    }

    #[test]
    fn test_path_auth_accepts_proxy_authorization_header() {
        // 脚本/curl 也可能携带 Proxy-Authorization
        let req = "GET /px/https://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n\r\n";
        assert_eq!(
            check_path_auth(req, &make_users()),
            Some(PathAuthSource::ProxyAuthorization)
        );
    }

    #[test]
    fn test_path_auth_rejects_missing_or_wrong_credentials() {
        assert!(check_path_auth(
            "GET /px/https://example.com/ HTTP/1.1\r\nHost: p\r\n\r\n",
            &make_users()
        )
        .is_none());
        // "admin:wrong"
        assert!(check_path_auth(
            "GET /px/https://example.com/ HTTP/1.1\r\n\
             Authorization: Basic YWRtaW46d3Jvbmc=\r\n\r\n",
            &make_users()
        )
        .is_none());
    }

    #[test]
    fn test_path_auth_prefers_verifiable_header() {
        // 两个头同时存在：Authorization 错、Proxy-Authorization 对 → 以能通过认证的为准，
        // 这样目标站点自己的 Authorization 可以保留下来
        let req = "GET /px/https://example.com/ HTTP/1.1\r\n\
            Authorization: Basic YWRtaW46d3Jvbmc=\r\n\
            Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n\r\n";
        assert_eq!(
            check_path_auth(req, &make_users()),
            Some(PathAuthSource::ProxyAuthorization)
        );
    }

    #[test]
    fn test_proxy_auth_does_not_accept_plain_authorization_header() {
        // 经典代理模式只认 Proxy-Authorization，避免把源站凭据当作代理凭据
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Authorization: Basic YWRtaW46c2VjcmV0\r\n\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    // ─── extract_userinfo 测试 ───

    #[test]
    fn test_extract_userinfo_full_credentials() {
        let (user, pass) = extract_userinfo("https://admin:secret@10.66.0.1:1011");
        assert_eq!(user.as_deref(), Some("admin"));
        assert_eq!(pass.as_deref(), Some("secret"));
    }

    #[test]
    fn test_extract_userinfo_username_only() {
        let (user, pass) = extract_userinfo("http://user@proxy.local:8080");
        assert_eq!(user.as_deref(), Some("user"));
        assert_eq!(pass.as_deref(), Some(""));
    }

    #[test]
    fn test_extract_userinfo_no_credentials() {
        let (user, pass) = extract_userinfo("https://proxy.local:1011");
        assert!(user.is_none());
        assert!(pass.is_none());
    }

    #[test]
    fn test_extract_userinfo_empty_at_sign() {
        // 仅 @ 符号，无用户信息
        let (user, pass) = extract_userinfo("http://@proxy.local:8080");
        assert!(user.is_none());
        assert!(pass.is_none());
    }

    #[test]
    fn test_extract_userinfo_with_path() {
        let (user, pass) = extract_userinfo("http://admin:secret@proxy.local:8080/some/path");
        assert_eq!(user.as_deref(), Some("admin"));
        assert_eq!(pass.as_deref(), Some("secret"));
    }

    #[test]
    fn test_extract_userinfo_password_with_colon() {
        // 密码包含冒号，按第一个冒号拆分
        let (user, pass) = extract_userinfo("http://user:pass:word@proxy.local:8080");
        assert_eq!(user.as_deref(), Some("user"));
        assert_eq!(pass.as_deref(), Some("pass:word"));
    }

    // ─── build_proxy_auth_header 测试 ───

    #[test]
    fn test_build_proxy_auth_header_from_url_userinfo() {
        let header = build_proxy_auth_header("http://admin:secret@proxy.local:8080", None, None);
        assert_eq!(header.as_deref(), Some("Basic YWRtaW46c2VjcmV0"));
    }

    #[test]
    fn test_build_proxy_auth_header_cli_overrides_url() {
        // CLI 参数优先级高于 URL userinfo
        let header = build_proxy_auth_header(
            "http://admin:secret@proxy.local:8080",
            Some("root"),
            Some("pass123"),
        );
        assert_eq!(header.as_deref(), Some("Basic cm9vdDpwYXNzMTIz"));
    }

    #[test]
    fn test_build_proxy_auth_header_no_credentials() {
        let header = build_proxy_auth_header("http://proxy.local:8080", None, None);
        assert!(header.is_none());
    }

    #[test]
    fn test_build_proxy_auth_header_partial_cli_no_url() {
        // 仅 --username 无 --password，URL 也无凭证
        let header = build_proxy_auth_header("http://proxy.local:8080", Some("user"), None);
        assert_eq!(header.as_deref(), Some("Basic dXNlcjo="));
    }

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
    // 这两组原语的实现与测试已迁至 `crate::net` 与 `crate::http_body`（消除模块循环依赖）。
}
