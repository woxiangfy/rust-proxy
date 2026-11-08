//! 路径前缀直连：上游连接建立
//!
//! 建头与请求发送均与经典代理共用 [`crate::protocol::forward`] 与
//! `crate::protocol::relay::send_upstream_request`；本模块只负责
//! 「连上上游（http 明文 / https TLS）」。

use super::PathProxyConfig;
use crate::protocol::forward::ForwardTarget;
use crate::support::net::{connect_host, AsyncStream};
use anyhow::{Context, Result};
use log::debug;
use std::time::Duration;

/// 连接上游：http 直连，https 在 TCP 之上做 TLS 握手。
///
/// `connect_host` 已在 [`ForwardTarget`] 里去掉 IPv6 方括号，DNS 与 SNI 直接可用。
pub(super) async fn connect_upstream(
    target: &ForwardTarget<'_>,
    cfg: &PathProxyConfig,
    timeout: Duration,
) -> Result<Box<dyn AsyncStream>> {
    let host = target.connect_host.as_str();
    let port = target.port;

    let tcp = connect_host(host, port, timeout)
        .await
        .with_context(|| format!("cannot connect to {}:{}", host, port))?;
    // 小包（HTTP 头）立即发出，降低下载类请求的首字节延迟
    let _ = tcp.set_nodelay(true);

    if target.scheme == "https" {
        // 客户端 TLS 统一走 rustls（见 tls_client 模块）：
        // 默认系统根证书严格校验，`path_proxy_insecure_tls` 才跳过链/主机名校验
        let tls = crate::transport::tls_client::connect_tls(tcp, host, cfg.insecure_tls, timeout)
            .await
            .with_context(|| format!("TLS handshake with {} failed", host))?;
        debug!("[path-proxy] TLS established with {}:{}", host, port);
        Ok(Box::new(tls))
    } else {
        Ok(Box::new(tcp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    // `connect_tls` 自身的证书校验语义已由 client.rs 的用例覆盖（默认拒绝自签、
    // insecure 接受自签）。这里补的是 `connect_upstream` 的 https 分支：确认它
    // 真的按 `PathProxyConfig::insecure_tls` 选择校验策略，而不是把开关漏传。

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
    async fn spawn_self_signed_tls_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind tls server");
        let addr = listener.local_addr().expect("tls server local_addr");
        let acceptor = tokio_rustls::TlsAcceptor::from(self_signed_server_config());

        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                let _ = acceptor.accept(tcp).await;
            }
        });
        addr
    }

    /// 用 IP 直连（避免 localhost 解析到 ::1 而服务端只监听 127.0.0.1）
    fn https_target(addr: SocketAddr) -> ForwardTarget<'static> {
        ForwardTarget {
            method: "GET",
            url: "https://127.0.0.1/",
            scheme: "https".to_string(),
            authority: format!("127.0.0.1:{}", addr.port()),
            connect_host: "127.0.0.1".to_string(),
            port: addr.port(),
            origin_form: "/".to_string(),
        }
    }

    #[tokio::test]
    async fn test_connect_upstream_https_rejects_self_signed_by_default() {
        let addr = spawn_self_signed_tls_server().await;
        let cfg = PathProxyConfig::new("px", false, false).expect("config");
        let target = https_target(addr);

        let result = connect_upstream(&target, &cfg, Duration::from_secs(5)).await;
        assert!(
            result.is_err(),
            "insecure_tls=false 时必须拒绝自签证书（系统根证书校验）"
        );
    }

    #[tokio::test]
    async fn test_connect_upstream_https_accepts_self_signed_when_insecure() {
        let addr = spawn_self_signed_tls_server().await;
        let cfg = PathProxyConfig::new("px", true, false).expect("config");
        let target = https_target(addr);

        let result = connect_upstream(&target, &cfg, Duration::from_secs(5)).await;
        assert!(
            result.is_ok(),
            "insecure_tls=true 时必须接受自签证书，实际错误：{:?}",
            result.err()
        );
    }
}
