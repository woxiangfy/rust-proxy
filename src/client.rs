//! `test-proxy` 子命令的客户端实现
//!
//! 与服务端转发逻辑无关：它扮演"客户端"，按代理协议访问目标 URL，
//! 用于部署后自检（能否连上代理、认证是否生效、CONNECT 隧道是否通）。
//! 与服务端只共享 [`crate::support::net::AsyncStream`] 这一层抽象。
//!
//! 因此它单独成模块：放在 `proxy.rs` 里会让"服务端转发"与"客户端自检"两套
//! 完全不同的代码互相干扰（也各自拖着用不到的依赖）。

use crate::support::net::AsyncStream;
use crate::transport::tls_client::connect_tls;
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
    // insecure=true 以支持自签证书（等价于 curl --proxy-insecure）
    let proxy_stream: Box<dyn AsyncStream> = if proxy_scheme == "https" {
        Box::new(
            connect_tls(tcp_stream, &proxy_host, true, Duration::from_secs(30))
                .await
                .with_context(|| format!("TLS handshake with proxy {} failed", proxy_addr))?,
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

            // Upgrade to TLS：目标站点用系统根证书严格校验（不做 insecure）
            Box::new(
                connect_tls(stream, &host, false, Duration::from_secs(30))
                    .await
                    .with_context(|| format!("TLS handshake with {} failed", host))?,
            )
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
            // 对端直接关 TCP、未发 TLS `close_notify` 时 rustls 会报 UnexpectedEof。
            // 这类"读到连接结尾"与 Ok(0) 语义相同（native-tls 时代就是如此），
            // 自检只需把已收到的响应打印出来，不因此判失败。
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
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

    // ─── TLS 证书校验路径 ───
    //
    // 这两条用例钉住 `connect_tls` 的安全语义，也与 `--proxy-insecure` 的对外承诺一致：
    // 默认（insecure=false）必须拒绝自签证书；显式 insecure 才接受。迁移底层 TLS 栈
    // （native-tls → rustls）时用例保持不动，作为"行为不变"的回归证据。

    /// 生成一份仅对 `localhost` 自签的 rustls 服务端配置（不依赖磁盘证书）
    fn self_signed_server_config() -> std::sync::Arc<rustls::ServerConfig> {
        let key_pair = rcgen::KeyPair::generate().expect("generate key pair");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("build certificate params");
        let cert = params.self_signed(&key_pair).expect("self-sign certificate");

        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialized_der().to_vec())
            .expect("private key DER");
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config");
        std::sync::Arc::new(config)
    }

    /// 起一个只接受一次握手并关闭的本地 TLS 服务端
    async fn spawn_self_signed_tls_server() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind tls server");
        let addr = listener.local_addr().expect("tls server local_addr");
        let acceptor = tokio_rustls::TlsAcceptor::from(self_signed_server_config());

        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                // 客户端拒绝时这里会返回 Err，正是"默认校验生效"的旁证
                let _ = acceptor.accept(tcp).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_connect_tls_rejects_self_signed_by_default() {
        let addr = spawn_self_signed_tls_server().await;
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect tls server");

        let result = connect_tls(tcp, "localhost", false, Duration::from_secs(5)).await;
        assert!(
            result.is_err(),
            "默认配置必须拒绝自签证书（系统根证书 + 主机名校验）"
        );
    }

    #[tokio::test]
    async fn test_connect_tls_accepts_self_signed_when_insecure() {
        let addr = spawn_self_signed_tls_server().await;
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect tls server");

        let result = connect_tls(tcp, "localhost", true, Duration::from_secs(5)).await;
        assert!(
            result.is_ok(),
            "insecure 必须接受自签证书（HTTPS 代理接入场景），实际错误：{:?}",
            result.err()
        );
    }
}
