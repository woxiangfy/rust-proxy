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
//! 依赖方向：本模块是叶节点（仅依赖 tokio 的 AsyncWrite），不引用任何业务模块。

use tokio::io::{AsyncWrite, AsyncWriteExt};

/// 写入一条完整响应
///
/// - `status`：状态行中的状态码与原因短语（如 `"404 Not Found"`）
/// - `extra_headers`：附加头（如认证质询、`Content-Type`），按给定顺序输出
/// - `body`：响应体（空切片表示无 body，输出 `Content-Length: 0`）
///
/// 写失败一律忽略：调用点都是"错误路径上顺手回一句"，连接可能已经断了，
/// 此时再上报错误没有意义（与既有行为一致）。
pub(crate) async fn write_response<W>(
    stream: &mut W,
    status: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
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

    if stream.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    if !body.is_empty() {
        let _ = stream.write_all(body).await;
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_write_response_with_body() {
        let mut out = Vec::new();
        write_response(
            &mut out,
            "404 Not Found",
            &[("Content-Type", "text/plain; charset=utf-8")],
            b"404 Not Found",
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
