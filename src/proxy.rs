//! Proxy module containing HTTP proxy request handling logic with zero-copy optimization and DNS caching

use crate::buffer_pool::BufferPool;
use crate::dns_cache::DnsCache;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::{TlsConnector, native_tls};
use tracing::{error, info, warn};

/// Combined trait for stream types used by `test_proxy`.
trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Handle an HTTP proxy client connection with buffer reuse and DNS caching
pub async fn handle_client(
    mut client: TcpStream, 
    timeout: u64, 
    buffer_pool: Arc<BufferPool>,
    dns_cache: Arc<DnsCache>,
) {
    let client_addr = match client.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Failed to get client address: {}", e);
            return;
        }
    };

    let timeout_duration = Duration::from_secs(timeout);
    
    // Get a buffer from the pool (zero-copy, no allocation if available)
    let mut buf = buffer_pool.get().await;
    let buf_slice = buf.as_mut_slice();
    
    // Read request data directly into the pooled buffer
    let n = match tokio::time::timeout(timeout_duration, client.read(buf_slice)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            error!("Failed to read from client {}: {}", client_addr, e);
            return;
        }
        Err(_) => {
            error!("Read from client {} timed out", client_addr);
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

    // Handle CONNECT method (HTTPS tunneling)
    if method == "CONNECT" {
        handle_connect(client, url, client_addr, timeout_duration, dns_cache).await;
        return;
    }

    // Handle HTTP proxy request with buffer pool and DNS caching
    handle_http_request(client, &request_data, client_addr, timeout_duration, buffer_pool, dns_cache).await;
}

/// Handle CONNECT method for HTTPS tunneling with DNS caching
async fn handle_connect(
    client: TcpStream,
    host_port: &str,
    client_addr: SocketAddr,
    timeout_duration: Duration,
    dns_cache: Arc<DnsCache>,
) {
    // Parse host and port from host_port string
    let (host, port) = match parse_host_port(host_port) {
        Ok((h, p)) => (h, p),
        Err(e) => {
            error!("Failed to parse host:port '{}': {}", host_port, e);
            return;
        }
    };

    // Use DNS cache for async DNS resolution
    let ip = match dns_cache.get_or_resolve(host).await {
        Ok(ip) => ip,
        Err(e) => {
            error!("DNS resolution failed for {} from {}: {}", host, client_addr, e);
            return;
        }
    };

    let target_addr = SocketAddr::new(ip, port);

    // Connect to target using resolved IP
    let target = match tokio::time::timeout(timeout_duration, TcpStream::connect(target_addr)).await
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

    let (mut client_read, mut client_write) = client.into_split();
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
            error!("Client to target copy error: {}", e);
        }
        if let Err(e) = tc_result {
            error!("Target to client copy error: {}", e);
        }
    })
    .await
    {
        Ok(_) => info!("CONNECT tunnel closed: {}:{}", host, port),
        Err(_) => error!("CONNECT tunnel timed out: {}:{}", host, port),
    }
}

/// Handle standard HTTP proxy request with buffer reuse and DNS caching
async fn handle_http_request(
    client: TcpStream,
    request_data: &str,
    client_addr: SocketAddr,
    timeout_duration: Duration,
    buffer_pool: Arc<BufferPool>,
    dns_cache: Arc<DnsCache>,
) {
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

    // Use DNS cache for async DNS resolution
    let ip = match dns_cache.get_or_resolve(host).await {
        Ok(ip) => ip,
        Err(e) => {
            error!("DNS resolution failed for {} from {}: {}", host, client_addr, e);
            return;
        }
    };

    let target_addr = SocketAddr::new(ip, port);

    // Connect to target using resolved IP
    let mut target = match tokio::time::timeout(timeout_duration, TcpStream::connect(target_addr))
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
        let line_lower = line.to_lowercase();
        if !line_lower.contains("proxy-connection") && !line_lower.contains("transfer-encoding") {
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
    let mut response_buf = buffer_pool.get().await;
    let response_slice = response_buf.as_mut_slice();
    let mut client = client;

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
                error!("Error reading from {}:{}: {}", host, port, e);
                break;
            }
            Err(_) => {
                error!("Response from {}:{} timed out", host, port);
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
/// For HTTP targets, sends an absolute-form GET request through the proxy.
/// For HTTPS targets, opens a CONNECT tunnel and performs TLS to the origin.
///
/// `proxy_addr` is the proxy host:port, e.g. `10.66.10.53:1010`.
/// `test_url` is the target URL to fetch through the proxy.
pub async fn test_proxy(proxy_addr: &str, test_url: &str) -> Result<()> {
    let parsed = url::Url::parse(test_url)
        .with_context(|| format!("Invalid test URL: {}", test_url))?;
    let host = parsed.host_str()
        .with_context(|| format!("No host in URL: {}", test_url))?
        .to_string();
    let scheme = parsed.scheme();
    let default_port = if scheme == "https" { 443 } else { 80 };
    let port = parsed.port().unwrap_or(default_port);
    let host_header = if port == default_port {
        host.clone()
    } else {
        format!("{}:{}", host, port)
    };

    let start = std::time::Instant::now();
    let stream = tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(proxy_addr))
        .await
        .with_context(|| format!("Timeout connecting to proxy {}", proxy_addr))?
        .with_context(|| format!("Failed to connect to proxy {}", proxy_addr))?;

    let mut stream: Box<dyn AsyncStream> = if scheme == "https" {
            // Establish CONNECT tunnel for HTTPS
            let connect_req = format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                host, port, host, port
            );
            let mut stream = stream;
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

            // Upgrade to TLS
            let cx = TlsConnector::from(native_tls::TlsConnector::new()?);
            Box::new(cx.connect(&host, stream).await?)
        } else {
            Box::new(stream)
        };

    let request_target = if scheme == "https" {
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

    println!("Proxy:    http://{}", proxy_addr);
    println!("Test URL: {}", test_url);
    println!("Duration: {:?}", elapsed);
    println!("Response:\n{}", response);

    Ok(())
}
