//! CONNECT 隧道：建立到目标的 TCP 连接并在客户端与目标之间双向转发
//!
//! 与经典/路径前缀转发不同，CONNECT 之后不再解析任何 HTTP 语义——握手成功后
//! 连接成为纯字节管道。请求头之后已读入的字节（如 TLS ClientHello）必须先于
//! 后续读取写出，否则会被丢掉。

use crate::protocol::http_response::write_response;
use crate::support::net::{connect_host, is_benign_close_error, parse_host_port, strip_brackets};
use crate::transport::stream::PrefixedStream;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// 上游不可达时的最小化 502 响应
///
/// 历史实现在这里直接 `return`，客户端只看到 EOF（curl 报
/// `Empty reply from server`），既无法区分"代理到目标的路由断了"还是"目标自己拒绝"，
/// 也无从判断是否值得重试。同端口的路径前缀直连模式早已回 502，两条链路对同一种
/// 失败给出完全不同的反馈属于实现漂移，这里统一。
///
/// 响应体刻意简短且不含目标地址，避免把内网拓扑回显给调用方。
pub(crate) async fn send_bad_gateway<W: AsyncWrite + Unpin>(client: &mut W) {
    write_response(
        client,
        "502 Bad Gateway",
        &[("Content-Type", "text/plain; charset=utf-8")],
        b"502 Bad Gateway",
    )
    .await;
}

/// Handle CONNECT method for HTTPS tunneling（泛型版本，支持 TCP/TLS 客户端流）
///
/// `leftover` 是请求头之后已经读入的字节（如客户端与 CONNECT 一并发送的 TLS ClientHello），
/// 会作为隧道前缀保留，避免数据丢失。
pub(crate) async fn handle_connect_generic<S>(
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
