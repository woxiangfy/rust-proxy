//! HTTP 响应报文构造
//!
//! 代理自己产生的响应：反扫描 404/431、代理认证 401/407、经典代理 400/502、
//! 路径前缀直连 400/502。
//! 它们的骨架完全一致（状态行 → 附加头 → `Content-Length` → `Connection: close` → body），
//! 差别只在状态行、质询头与 body，因此收敛成一个写入函数；经典代理与路径代理的
//! 错误响应都走这里，不再各自手写字符串。
//!
//! 收敛的理由不只是"少写几行"：这类响应是**机器可读的协议输出**，多处手写字符串时
//! 任何一处漏写 `Content-Length` 或 `Connection: close` 都会造成客户端挂起，
//! 而单点构造可以一次性保证形状，并用一个测试固定下来。
//!
//! 依赖方向：本模块只依赖 tokio 的 `AsyncWrite` 与写超时原语
//! [`crate::support::net::write_all_with_timeout`]，不引用任何业务模块。

use std::time::Duration;
use tokio::io::AsyncWrite;

use crate::support::net::write_all_with_timeout;

/// 写入一条完整响应
///
/// - `status`：状态行中的状态码与原因短语（如 `"404 Not Found"`）
/// - `extra_headers`：附加头（如认证质询、`Content-Type`），按给定顺序输出
/// - `body`：响应体（空切片表示无 body，输出 `Content-Length: 0`）
/// - `timeout`：写客户端超时（与读方向共用 `timeout` 配置，见
///   [`crate::support::net::write_all_with_timeout`]）
///
/// 写失败（含超时）一律忽略：调用点都是"错误路径上顺手回一句"，连接可能已经断了
/// 或对端根本不读，此时再上报错误没有意义（与既有行为一致）。
pub(super) async fn write_response<W>(
    stream: &mut W,
    status: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
    timeout: Duration,
) where
    W: AsyncWrite + Unpin,
{
    let mut head = String::with_capacity(192);
    head.push_str("HTTP/1.1 ");
    head.push_str(status);
    head.push_str("\r\n");
    for (name, value) in extra_headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("Content-Length: ");
    head.push_str(&body.len().to_string());
    head.push_str("\r\nConnection: close\r\n\r\n");

    if write_all_with_timeout(stream, head.as_bytes(), timeout, "response head")
        .await
        .is_err()
    {
        return;
    }
    if !body.is_empty() {
        let _ = write_all_with_timeout(stream, body, timeout, "response body").await;
    }
}

/// 发送最小化错误响应（状态行 + 纯文本 body）
///
/// 报文骨架统一由 [`write_response`] 构造，调用方只给状态码、原因短语与 body。
/// 用数值状态码而不是整条状态行，避免调用点在字符串里写错状态码与原因短语的搭配；
/// 经典代理、CONNECT 与路径前缀直连的 400/502 都走这一个入口。
pub(super) async fn send_error<W: AsyncWrite + Unpin>(
    client: &mut W,
    code: u16,
    reason: &str,
    msg: &str,
    timeout: Duration,
) {
    write_response(
        client,
        &format!("{} {}", code, reason),
        &[("Content-Type", "text/plain; charset=utf-8")],
        msg.as_bytes(),
        timeout,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timeout() -> Duration {
        Duration::from_millis(500)
    }

    #[tokio::test]
    async fn test_write_response_with_body() {
        let mut out = Vec::new();
        write_response(
            &mut out,
            "404 Not Found",
            &[("Content-Type", "text/plain; charset=utf-8")],
            b"404 Not Found",
            timeout(),
        )
        .await;

        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "HTTP/1.1 404 Not Found\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Length: 13\r\n\
             Connection: close\r\n\
             \r\n\
             404 Not Found"
        );
    }

    #[tokio::test]
    async fn test_write_response_without_body() {
        let mut out = Vec::new();
        write_response(
            &mut out,
            "407 Proxy Authentication Required",
            &[("Proxy-Authenticate", "Basic realm=\"rust-proxy\"")],
            b"",
            timeout(),
        )
        .await;

        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"));
        assert!(text.contains("Proxy-Authenticate: Basic realm=\"rust-proxy\"\r\n"));
        assert!(text.contains("Content-Length: 0\r\n"), "空 body 必须给出 CL: 0");
        assert!(text.ends_with("\r\n\r\n"), "无 body 时响应止于空行");
        assert!(!text.contains("Server:"), "错误响应不得暴露 Server 头");
    }
}
