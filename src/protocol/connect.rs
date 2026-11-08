//! CONNECT 隧道：建立到目标的 TCP 连接并在客户端与目标之间双向转发
//!
//! 与经典/路径前缀转发不同，CONNECT 之后不再解析任何 HTTP 语义——握手成功后
//! 连接成为纯字节管道。请求头之后已读入的字节（如 TLS ClientHello）必须先于
//! 后续读取写出，否则会被丢掉。

use crate::protocol::http_response::send_bad_gateway;
use crate::support::net::{connect_host, is_benign_close_error, parse_host_port, strip_brackets};
use crate::transport::stream::PrefixedStream;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Handle CONNECT method for HTTPS tunneling（泛型版本，支持 TCP/TLS 客户端流）
///
/// `leftover` 是请求头之后已经读入的字节（如客户端与 CONNECT 一并发送的 TLS ClientHello），
/// 会作为隧道前缀保留，避免数据丢失。
pub(super) async fn handle_connect_generic<S>(
    mut client: S,
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

    // CONNECT 目标主机字符串，供 DNS/连接使用。`parse_host_port` 对 IPv6 保留
    // 方括号形式（`[a:b::1]`），而 socket/DNS 只接受裸地址，剥离逻辑统一在
    // [`crate::support::net::strip_brackets`]。
    let connect_host_str = strip_brackets(host);

    let mut target = match connect_host(connect_host_str, port, timeout_duration).await {
        Ok(t) => t,
        Err(e) => {
            error!(
                "Failed to connect to {}:{} from {}: {}",
                connect_host_str, port, client_addr, e
            );
            // 隧道未建立：必须在断开前明确告知 502，否则客户端把 EOF 当作隧道异常
            send_bad_gateway(&mut client).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn fake_client_addr() -> SocketAddr {
        "127.0.0.1:54321".parse().expect("client addr")
    }

    /// 目标无法解析时，当前实现只记日志并静默关闭（不向客户端回任何字节）。
    /// 用例钉住这一现状，避免后续重构无意中改变客户端的可观测行为。
    #[tokio::test]
    async fn test_connect_target_parse_failure_closes_without_response() {
        let (client, mut peer) = tokio::io::duplex(1024);

        handle_connect_generic(
            client,
            "example.com:not-a-port",
            fake_client_addr(),
            Duration::from_secs(1),
            &[],
        )
        .await;

        let mut buf = Vec::new();
        peer.read_to_end(&mut buf).await.expect("read client side");
        assert!(
            buf.is_empty(),
            "解析失败应静默关闭（不写 200/502），实际收到：{:?}",
            String::from_utf8_lossy(&buf)
        );
    }

    /// 上游不可达时必须在断开前回 502，否则客户端只能把 EOF 当作隧道异常。
    #[tokio::test]
    async fn test_connect_unreachable_upstream_returns_502() {
        // 先绑定再释放：得到一个确定无人监听的本地端口
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind probe port");
        let target_addr = listener.local_addr().expect("probe local_addr");
        drop(listener);

        let (client, mut peer) = tokio::io::duplex(2048);
        handle_connect_generic(
            client,
            &target_addr.to_string(),
            fake_client_addr(),
            Duration::from_millis(500),
            &[],
        )
        .await;

        let mut buf = Vec::new();
        peer.read_to_end(&mut buf).await.expect("read client side");
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "上游不可达必须回 502，实际响应：{text}"
        );
    }
}
