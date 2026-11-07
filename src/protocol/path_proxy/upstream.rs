//! 路径前缀直连：上游连接建立与请求体转发
//!
//! 建头本身与经典代理共用 [`crate::protocol::forward`]；本模块只负责
//! 「连上上游（http 明文 / https TLS）」与「把请求体流式送出去」。

use super::PathProxyConfig;
use crate::protocol::forward::ForwardTarget;
use crate::protocol::http_body::{forward_chunked_body, forward_content_length_body};
use crate::support::buffer_pool::BufferPool;
use crate::support::net::{connect_host, AsyncStream};
use anyhow::{Context, Result};
use log::debug;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
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
        debug!("Path-proxy: TLS established with {}:{}", host, port);
        Ok(Box::new(tls))
    } else {
        Ok(Box::new(tcp))
    }
}

/// 转发请求体：先发已缓冲字节，再按 Content-Length / chunked 流式转发。
///
/// 返回已向上游写出的 body 字节数（`Content-Length` 路径下可用于判断客户端是否
/// 提前关闭；chunked 路径恒返回 0，分帧本身已能自证结束位置）。
pub(super) async fn forward_request_body<S, T>(
    client: &mut S,
    upstream: &mut T,
    buffered: &[u8],
    content_length: Option<u64>,
    chunked: bool,
    timeout: Duration,
    buffer_pool: &BufferPool,
) -> std::io::Result<u64>
where
    S: AsyncRead + Unpin,
    T: AsyncWrite + Unpin,
{
    // chunked：已缓冲字节属于分帧的一部分，必须交给状态机消费（否则会挂住等结束块）
    if chunked {
        forward_chunked_body(client, upstream, buffered, timeout, buffer_pool).await?;
        return Ok(0);
    }

    match content_length {
        Some(cl) => {
            forward_content_length_body(client, upstream, buffered, cl, timeout, buffer_pool).await
        }
        None => {
            // 既无 Content-Length 也非 chunked：只能转发已缓冲字节
            if !buffered.is_empty() {
                upstream.write_all(buffered).await?;
            }
            Ok(buffered.len() as u64)
        }
    }
}
