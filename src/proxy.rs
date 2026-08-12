//! Proxy module containing HTTP proxy request handling logic with zero-copy optimization and DNS caching

use crate::buffer_pool::BufferPool;
use crate::config::AuthUser;
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::{TlsConnector, native_tls};
use log::{debug, error, info, warn};

/// Combined trait for stream types used by `test_proxy`.
trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Handle an HTTP proxy client connection with buffer reuse (plain TCP entrypoint)
///
/// `auth` 为 `None` 时不启用认证；为 `Some(用户列表)` 时要求客户端通过 HTTP Basic
/// 认证（`Proxy-Authorization` 头），否则返回 407 并关闭连接。
pub async fn handle_client(
    client: TcpStream,
    timeout: u64,
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<AuthUser>>>,
) {
    let client_addr = match client.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Failed to get client address: {}", e);
            return;
        }
    };
    handle_client_generic(client, client_addr, timeout, buffer_pool, auth).await;
}

/// Handle an HTTP proxy client connection over a TLS-wrapped stream
///
/// 参数 `client_addr` 从 accept 时提前获取，因为 TlsStream 不直接暴露 peer_addr。
pub async fn handle_client_tls<S>(
    client: S,
    client_addr: SocketAddr,
    timeout: u64,
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<AuthUser>>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_client_generic(client, client_addr, timeout, buffer_pool, auth).await;
}

/// 通用客户端连接处理逻辑（与具体传输层 TCP/TLS 无关）
///
/// 接受任意 AsyncRead + AsyncWrite 流，完成请求解析、认证、分发到 CONNECT 或 HTTP 处理。
async fn handle_client_generic<S>(
    mut client: S,
    client_addr: SocketAddr,
    timeout: u64,
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<AuthUser>>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let timeout_duration = Duration::from_secs(timeout);

    // Get a buffer from the pool (zero-copy, no allocation if available)
    let mut buf = buffer_pool.get();
    let buf_slice = buf.as_mut_slice();

    // Read request data directly into the pooled buffer
    let n = match tokio::time::timeout(timeout_duration, client.read(buf_slice)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            if is_benign_close_error(&e) {
                debug!("Read from client {} ended: {}", client_addr, e);
            } else {
                warn!("Failed to read from client {}: {}", client_addr, e);
            }
            return;
        }
        Err(_) => {
            warn!("Read from client {} timed out", client_addr);
            return;
        }
    };

    if n == 0 {
        return;
    }

    // Use String::from_utf8_lossy without copying if possible
    let request_data = String::from_utf8_lossy(&buf_slice[..n]);
    let mut lines = request_data.lines();

    let request_line = match lines.next() {
        Some(line) => line,
        None => return,
    };

    info!("{} -> {}", client_addr, request_line);

    // Parse request
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        warn!("Invalid request from {}: {}", client_addr, request_line);
        return;
    }

    let method = parts[0];
    let url = parts[1];

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
        if !check_proxy_auth(&request_data, users) {
            send_auth_required(&mut client).await;
            warn!("Proxy authentication failed from {}", client_addr);
            return;
        }
    }

    // Handle CONNECT method (HTTPS tunneling)
    if method == "CONNECT" {
        handle_connect_generic(client, url, client_addr, timeout_duration).await;
        return;
    }

    // Handle HTTP proxy request with buffer pool
    handle_http_request_generic(client, &request_data, client_addr, timeout_duration, buffer_pool).await;
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
    let credentials = match extract_proxy_authorization(request_data) {
        Some(c) => c,
        None => return false,
    };

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

/// 从原始请求数据中提取 `Proxy-Authorization: Basic <credentials>` 的凭据部分。
///
/// 头名匹配不区分大小写，仅识别 Basic 方案；遇到空行（请求头结束）即停止搜索。
/// 不含冒号的行（如绝对形式的请求行）会被跳过而非导致整体失败。
fn extract_proxy_authorization(request_data: &str) -> Option<&str> {
    for line in request_data.lines() {
        if line.is_empty() {
            // 空行标志请求头结束
            break;
        }
        let (name, value) = match line.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
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

/// Handle CONNECT method for HTTPS tunneling（泛型版本，支持 TCP/TLS 客户端流）
async fn handle_connect_generic<S>(
    client: S,
    host_port: &str,
    client_addr: SocketAddr,
    timeout_duration: Duration,
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

    // 直接使用主机名连接，由操作系统负责 DNS 解析和缓存
    // (&str, u16) 直接实现 ToSocketAddrs，无需额外的 String 分配
    let target = match tokio::time::timeout(timeout_duration, TcpStream::connect((host, port))).await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            error!("Failed to connect to {}:{} from {}: {}", host, port, client_addr, e);
            return;
        }
        Err(_) => {
            error!("Connection to {}:{} timed out", host, port);
            return;
        }
    };

    // 使用 tokio::io::split 将泛型流拆分为读写两半，便于双向 copy
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut target_read, mut target_write) = target.into_split();

    // Send 200 Connection Established
    if client_write.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() {
        return;
    }

    // Tunnel data bidirectionally using tokio::io::copy (zero-copy internally)
    let client_to_target = tokio::io::copy(&mut client_read, &mut target_write);
    let target_to_client = tokio::io::copy(&mut target_read, &mut client_write);

    match tokio::time::timeout(timeout_duration * 2, async {
        let (ct_result, tc_result) = tokio::join!(client_to_target, target_to_client);
        if let Err(e) = ct_result {
            if is_benign_close_error(&e) {
                debug!("Client to target copy ended: {}", e);
            } else {
                warn!("Client to target copy error: {}", e);
            }
        }
        if let Err(e) = tc_result {
            if is_benign_close_error(&e) {
                debug!("Target to client copy ended: {}", e);
            } else {
                warn!("Target to client copy error: {}", e);
            }
        }
    })
    .await
    {
        Ok(_) => info!("CONNECT tunnel closed: {}:{}", host, port),
        Err(_) => debug!("CONNECT tunnel timed out: {}:{}", host, port),
    }
}

/// 判断 IO 错误是否为"对端正常/半正常关闭连接"类（不应记为 ERROR）
///
/// 这些错误在 TLS 隧道场景中极其常见，绝大多数并非代理本身的问题：
/// - `UnexpectedEof`：TLS 对端未发送 close_notify 就关闭连接（浏览器、curl 等常用做法）
/// - `ConnectionReset`：对端发送 TCP RST（移动网络切换、NAT 超时等）
/// - `ConnectionAborted`：本地或对端中止连接
/// - `BrokenPipe`：写入已关闭的管道（对端先关闭，己方仍在写）
fn is_benign_close_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
    )
}

/// Handle standard HTTP proxy request with buffer reuse（泛型版本，支持 TCP/TLS 客户端流）
async fn handle_http_request_generic<S>(
    mut client: S,
    request_data: &str,
    client_addr: SocketAddr,
    timeout_duration: Duration,
    buffer_pool: Arc<BufferPool>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut lines = request_data.lines();
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

    // 直接使用主机名连接，由操作系统负责 DNS 解析和缓存
    let mut target = match tokio::time::timeout(timeout_duration, TcpStream::connect((host, port)))
        .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            error!("Failed to connect to {}:{} from {}: {}", host, port, client_addr, e);
            return;
        }
        Err(_) => {
            error!("Connection to {}:{} timed out", host, port);
            return;
        }
    };

    // Forward request headers without copying when possible
    let mut header_buffer = String::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let line_lower = line.to_ascii_lowercase();
        // 过滤逐跳头：proxy-connection、transfer-encoding，以及携带凭据的
        // proxy-authorization（认证完成后不应转发给目标服务器）
        if !line_lower.contains("proxy-connection")
            && !line_lower.contains("transfer-encoding")
            && !line_lower.contains("proxy-authorization")
        {
            // Modify connection header
            let line_to_send = if line_lower.starts_with("connection:") {
                "Connection: close\r\n"
            } else {
                line
            };
            header_buffer.push_str(line_to_send);
            header_buffer.push_str("\r\n");
        }
    }
    header_buffer.push_str("\r\n");

    // Send headers in one write operation
    if target.write_all(header_buffer.as_bytes()).await.is_err() {
        return;
    }

    // Forward body if present (for POST, PUT, etc.) - zero-copy
    if method == "POST" || method == "PUT" || method == "PATCH" {
        if let Some(body_start) = request_data.find("\r\n\r\n") {
            let body = &request_data[body_start + 4..];
            if !body.is_empty() {
                let _ = target.write_all(body.as_bytes()).await;
            }
        }
    }

    // Read response and forward to client using pooled buffer
    let mut response_buf = buffer_pool.get();
    let response_slice = response_buf.as_mut_slice();

    loop {
        match tokio::time::timeout(timeout_duration, target.read(response_slice)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                // Zero-copy: directly write from buffer to client
                if client.write_all(&response_slice[..n]).await.is_err() {
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

    info!("Request completed: {} {}", method, url);
}

/// Parse host:port string into host and port
fn parse_host_port(host_port: &str) -> Result<(&str, u16), String> {
    let parts: Vec<&str> = host_port.splitn(2, ':').collect();
    if parts.len() == 2 {
        let port = parts[1].parse::<u16>().map_err(|e| e.to_string())?;
        Ok((parts[0], port))
    } else {
        Ok((host_port, 443)) // Default HTTPS port
    }
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

    // Format: Basic <base64(user:pass)>
    let credentials = if pass.is_empty() {
        user.to_string()
    } else {
        format!("{}:{}", user, pass)
    };
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

    #[test]
    fn test_is_benign_close_error_classifies_tls_close_notify_as_benign() {
        // rustls 对端未发送 close_notify 时返回的错误 → 应判定为良性
        let e = std::io::Error::new(std::io::ErrorKind::UnexpectedEof,
            "peer closed connection without sending TLS close_notify");
        assert!(is_benign_close_error(&e),
            "UnexpectedEof (TLS close_notify missing) must be benign");
    }

    #[test]
    fn test_is_benign_close_error_classifies_network_resets_as_benign() {
        // TCP RST / 连接中止 / 管道破裂 → 良性（网络中极常见）
        assert!(is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::ConnectionReset)));
        assert!(is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::ConnectionAborted)));
        assert!(is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::BrokenPipe)));
    }

    #[test]
    fn test_is_benign_close_error_rejects_real_errors() {
        // 真异常不应降级（保留 warn/error 日志通道）
        assert!(!is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)));
        assert!(!is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::AddrInUse)));
        assert!(!is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::TimedOut)));
        assert!(!is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::InvalidData)));
    }

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
            extract_proxy_authorization(req),
            Some("YWRtaW46c2VjcmV0")
        );
    }

    #[test]
    fn test_extract_authorization_none_when_absent() {
        let req = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_proxy_authorization(req), None);
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
        assert_eq!(header.as_deref(), Some("Basic dXNlcg=="));
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
}
