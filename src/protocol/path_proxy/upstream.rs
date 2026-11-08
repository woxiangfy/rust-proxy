//! 路径前缀直连：上游连接建立
//!
//! 建头与请求体转发均与经典代理共用 [`crate::protocol::forward`] 与
//! [`crate::protocol::relay::forward_request_body`]；本模块只负责
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
