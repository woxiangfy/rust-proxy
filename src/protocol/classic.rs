//! 经典代理转发流水线（建头 → 转发请求体 → 回传响应）
//!
//! 本模块只做编排，请求分类与入口在 [`crate::protocol::dispatch`]；
//! 发送序列、请求体转发与响应拷贝循环是两条链路共用的原语，留在
//! [`crate::protocol::relay`]。流水线四段，每段可独立阅读与测试：
//! 1. [`ForwardTarget::parse`] —— 请求行 → 目标 host / port / origin-form
//! 2. 连接上游（`connect_host` 统一处理 IPv4 / IPv6 / DNS）
//! 3. [`UpstreamHead::build`] + 请求体转发 —— 建头、转发 body
//! 4. [`relay_response`] —— 回传响应

use crate::protocol::forward::{ForwardTarget, UpstreamHead};
use crate::protocol::http_response::send_error;
use crate::protocol::relay::{
    copy_upstream_to_client, send_upstream_request, RelayLink, RelayOutcome, RequestBodyForward,
    SendRequestError,
};
use crate::support::buffer_pool::BufferPool;
use crate::support::net::{connect_host, is_benign_close_error};
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// 读上游响应并原样转发给客户端
///
/// 拷贝缓冲自适应（8KB 起步，长传输 / 大 body 翻倍到 256KB）：一次读 + 一次写，
/// 中间不做额外分配，也不解析响应语义（代理不关心内容）。
async fn relay_response<S>(
    client: &mut S,
    upstream: &mut TcpStream,
    target: &ForwardTarget<'_>,
    timeout: Duration,
) where
    S: AsyncWrite + Unpin,
{
    let (outcome, copy_bytes) =
        copy_upstream_to_client(client, upstream, timeout, RelayLink::Classic).await;

    match outcome {
        // 正常收尾：完成日志在下方统一输出
        RelayOutcome::Completed => {}
        // 客户端断开：不记 error，避免正常下载中断刷屏
        RelayOutcome::ClientGone => {}
        // 客户端只连不读：连接已按超时结束，但对端仍是"异常"状态，记 warn 便于定位
        RelayOutcome::ClientStalled => {
            warn!(
                "Client stopped reading response from {}:{}, closing connection after timeout",
                target.connect_host, target.port
            );
        }
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
}

/// 转发一次普通代理请求（认证已在调用前完成）
///
/// 四段流水线，每段可独立阅读与测试：
/// 1. [`ForwardTarget::parse`] —— 请求行 → 目标 host / port / origin-form
/// 2. 连接上游（`connect_host` 统一处理 IPv4 / IPv6 / DNS）
/// 3. [`UpstreamHead::build`] + 请求体转发 —— 建头、转发 body
/// 4. [`relay_response`] —— 回传响应
pub(super) async fn handle_http_request_generic<S>(
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
        send_error(&mut client, 400, "Bad Request", "400 Bad Request", timeout_duration).await;
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
        send_error(&mut client, 400, "Bad Request", "400 Bad Request", timeout_duration).await;
        return;
    };

    let mut upstream = match connect_host(&target.connect_host, target.port, timeout_duration).await {
        Ok(t) => t,
        Err(e) => {
            error!(
                "Failed to connect to {}:{} from {}: {}",
                target.connect_host, target.port, client_addr, e
            );
            send_error(&mut client, 502, "Bad Gateway", "502 Bad Gateway", timeout_duration).await;
            return;
        }
    };

    match send_upstream_request(
        &mut client,
        &mut upstream,
        RequestBodyForward {
            head: &head,
            buffered: &request_data[head_end..],
            timeout: timeout_duration,
            buffer_pool: &buffer_pool,
            link: RelayLink::Classic,
            client_addr,
        },
    )
    .await
    {
        Ok(_) => {}
        // 写上游失败：目标已不可用，响应还没开始，给客户端一个明确的 502
        Err(SendRequestError::Upstream) => {
            send_error(&mut client, 502, "Bad Gateway", "502 Bad Gateway", timeout_duration).await;
            return;
        }
        // 客户端侧失败（应答 100 / 读请求体）：客户端已不可用，回写没有接收方
        Err(SendRequestError::Client) => return,
    }

    relay_response(&mut client, &mut upstream, &target, timeout_duration).await;

    info!("Request completed: {} {}", target.method, target.url);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

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
}
