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

    // 认证校验：配置了 [[auth]] 时要求客户端携带合法的 Proxy-Authorization 头。
    // CONNECT 与普通 HTTP 请求均需通过认证。
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

/// Test a proxy server.
///
/// `proxy_url` 是代理服务器 URL，必须显式包含协议：
///   - `http://host:port` — 通过明文 TCP 连接代理
///   - `https://host:port` — 通过 TLS 连接代理，**跳过证书验证**
///     （等价于 `curl --proxy-insecure`），以支持自签证书场景
///
/// `test_url` 是目标 URL，必须包含 `http://` 或 `https://` 协议头。
/// 对 HTTPS 目标，会先通过代理建立 CONNECT 隧道，再与目标服务器做 TLS 握手。
pub async fn test_proxy(proxy_url: &str, test_url: &str) -> Result<()> {
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
            // Establish CONNECT tunnel for HTTPS
            let connect_req = format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                host, port, host, port
            );
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

    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: rust-proxy/{}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\r\n",
        request_target, host_header, env!("CARGO_PKG_VERSION")
    );
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
}
