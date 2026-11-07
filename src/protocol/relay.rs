//! 响应回传与经典转发流水线
//!
//! 经典代理与路径前缀直连共用同一段「读上游 → 写客户端」循环（自适应缓冲、
//! 单次读单次写、不解析响应语义），差异只在**如何解释结束原因**：
//! 经典代理把所有结束都视为正常收尾，路径前缀直连需要把读错误/超时上抛给调用方。
//! 因此拷贝循环只返回中性的 [`CopyOutcome`]，由各调用点自行映射回原有契约与日志。
//!
//! 经典代理的转发流水线（建头 → 转发请求体 → 回传响应）也在这里，
//! 请求编排由 [`crate::protocol::dispatch`] 负责。

use crate::protocol::connect::send_bad_gateway;
use crate::protocol::forward::{ForwardTarget, UpstreamHead};
use crate::protocol::http_body::{forward_chunked_body, forward_content_length_body};
use crate::protocol::http_response::write_response;
use crate::support::buffer_pool::{AdaptiveBuffer, BufferPool};
use crate::support::net::{connect_host, is_benign_close_error};
use anyhow::Result;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
/// 响应拷贝循环的结束原因（中性描述，不含任何日志或返回类型决策）
#[derive(Debug)]
pub(crate) enum CopyOutcome {
    /// 上游正常关闭（读到 EOF）
    Eof,
    /// 读上游出错；原始错误保留给调用方判断是否等价于正常关闭
    ReadError(std::io::Error),
    /// 读上游超时
    TimedOut,
    /// 写客户端失败：客户端已断开
    ClientClosed,
}

/// 流式转发响应体：一次读上游、一次写客户端，直到上游 EOF 或任一端断开。
///
/// 拷贝缓冲自适应（8KB 起步，长传输 / 大 body 翻倍到 256KB），中间不做额外分配。
/// 返回值附带循环结束时的缓冲大小（字节），供调用方沿用原有日志格式。
pub(crate) async fn copy_upstream_to_client<S, T>(
    client: &mut S,
    upstream: &mut T,
    timeout: Duration,
) -> (CopyOutcome, usize)
where
    S: AsyncWrite + Unpin,
    T: AsyncRead + Unpin,
{
    let mut copy = AdaptiveBuffer::new();
    loop {
        copy.prepare();
        match tokio::time::timeout(timeout, upstream.read(copy.as_mut_slice())).await {
            Ok(Ok(0)) => return (CopyOutcome::Eof, copy.current_size()),
            Ok(Ok(n)) => {
                copy.note_copied(n);
                if client
                    .write_all(&copy.as_mut_slice()[..n])
                    .await
                    .is_err()
                {
                    return (CopyOutcome::ClientClosed, copy.current_size());
                }
            }
            Ok(Err(e)) => return (CopyOutcome::ReadError(e), copy.current_size()),
            Err(_) => return (CopyOutcome::TimedOut, copy.current_size()),
        }
    }
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
        let (outcome, copy_bytes) =
            copy_upstream_to_client(client, upstream, self.timeout).await;

        match outcome {
            CopyOutcome::Eof | CopyOutcome::ClientClosed => {}
            CopyOutcome::ReadError(e) => {
                if is_benign_close_error(&e) {
                    debug!("Read from {}:{} ended: {}", target.connect_host, target.port, e);
                } else {
                    warn!("Error reading from {}:{}: {}", target.connect_host, target.port, e);
                }
            }
            CopyOutcome::TimedOut => {
                warn!("Response from {}:{} timed out", target.connect_host, target.port);
            }
        }

        debug!(
            "Response copy buffer for {}:{} ended at {} KB",
            target.connect_host,
            target.port,
            copy_bytes / 1024
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
pub(crate) async fn handle_http_request_generic<S>(
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
        client_addr, target.method, target.connect_host, target.port, target.url
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

    let mut upstream = match connect_host(&target.connect_host, target.port, timeout_duration).await {
        Ok(t) => t,
        Err(e) => {
            error!(
                "Failed to connect to {}:{} from {}: {}",
                target.connect_host, target.port, client_addr, e
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
