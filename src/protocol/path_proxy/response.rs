//! 路径前缀直连：上游响应头读取与重建（含 Location 重写）
//!
//! 响应头阶段与经典代理刻意不共用：路径前缀模式需要把 3xx 的 `Location` 重写回
//! 本代理前缀，并在响应头缺失/超限时原样透传；body 阶段复用
//! [`crate::protocol::relay::copy_upstream_to_client`]。

use super::PathProxyConfig;
use crate::protocol::http_util::{find_header_end, MAX_HEAD_BYTES};
use crate::protocol::relay::{copy_upstream_to_client, RelayOutcome};
use crate::support::buffer_pool::BufferPool;
use log::{debug, warn};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
/// 读取上游响应头（可能连带读到 body 前缀），可选重写 Location，随后流式转发 body。
pub(super) async fn forward_response<S, T>(
    client: &mut S,
    upstream: &mut T,
    cfg: &PathProxyConfig,
    base: &url::Url,
    timeout: Duration,
    buffer_pool: &BufferPool,
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
    T: AsyncRead + Unpin,
{
    let mut buf = buffer_pool.get();
    let slice = buf.as_mut_slice();

    // ── 读响应头 ──
    let mut head_data: Vec<u8> = Vec::with_capacity(2048);
    let mut head_end: Option<usize> = None;
    loop {
        let n = match tokio::time::timeout(timeout, upstream.read(slice)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timeout reading upstream response head",
                ))
            }
        };
        if n == 0 {
            break; // 上游直接关闭：下面按已读内容原样透传
        }
        head_data.extend_from_slice(&slice[..n]);
        if let Some(p) = find_header_end(&head_data) {
            head_end = Some(p);
            break;
        }
        if head_data.len() >= MAX_HEAD_BYTES {
            // 响应头异常大：不改写，原样透传（此处 break 时 head_end 仍为 None）
            warn!("Path-proxy: upstream response head exceeds {} bytes, passing through", MAX_HEAD_BYTES);
            break;
        }
    }

    if head_data.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "upstream closed without any response",
        ));
    }

    match head_end {
        Some(p) => {
            let status = parse_status_code(&head_data[..p]);
            let new_head = rebuild_response_head(&head_data[..p], status, cfg, base);
            if client.write_all(new_head.as_bytes()).await.is_err() {
                return Ok(());
            }
            if p < head_data.len() && client.write_all(&head_data[p..]).await.is_err() {
                return Ok(());
            }
        }
        None => {
            // 头不完整（超限或上游提前关闭）：原样写出，避免破坏字节流
            if client.write_all(&head_data).await.is_err() {
                return Ok(());
            }
        }
    }

    // ── 流式转发 body：保持 chunked / gzip 等原始编码不变 ──
    // 头部读完即归还池化缓冲区，body 阶段改用自适应缓冲（与经典代理共用同一循环）
    drop(buf);
    let (outcome, copy_bytes) = copy_upstream_to_client(client, upstream, timeout).await;
    match outcome {
        RelayOutcome::Completed => {
            debug!(
                "Path-proxy: response done, copy buffer {} KB",
                copy_bytes / 1024
            );
            Ok(())
        }
        // 客户端断开：不记 error，正常下载中断不得刷屏
        RelayOutcome::ClientGone => Ok(()),
        RelayOutcome::UpstreamClosed => {
            debug!("Path-proxy: upstream closed before sending response body");
            Ok(())
        }
        RelayOutcome::TimedOut => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout reading upstream response body",
        )),
        RelayOutcome::UpstreamError(e) => Err(e),
    }
}

/// 从状态行解析状态码（`HTTP/1.1 200 OK` → `Some(200)`）
fn parse_status_code(head: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(head);
    let first = text.lines().next()?;
    first.split_whitespace().nth(1)?.parse::<u16>().ok()
}

/// 重建响应头：Connection 改 close；3xx 时按需把 Location 重写回本代理前缀。
fn rebuild_response_head(
    head: &[u8],
    status: Option<u16>,
    cfg: &PathProxyConfig,
    base: &url::Url,
) -> String {
    let text = String::from_utf8_lossy(head);
    let mut out = String::with_capacity(head.len() + 64);

    let mut lines = text.split("\r\n");
    if let Some(first) = lines.next() {
        out.push_str(first);
        out.push_str("\r\n");
    }

    let rewrite = cfg.rewrite_location
        && matches!(status, Some(301) | Some(302) | Some(303) | Some(307) | Some(308));
    let mut connection_written = false;

    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = match line.split_once(':') {
            Some(pair) => pair,
            None => {
                out.push_str(line);
                out.push_str("\r\n");
                continue;
            }
        };
        if name.trim().eq_ignore_ascii_case("connection") {
            if !connection_written {
                out.push_str("Connection: close\r\n");
                connection_written = true;
            }
            continue;
        }
        if rewrite && name.trim().eq_ignore_ascii_case("location") {
            if let Some(new_loc) = rewrite_location(value.trim(), cfg, base) {
                out.push_str("Location: ");
                out.push_str(&new_loc);
                out.push_str("\r\n");
                continue;
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
    }

    // 上游未声明 Connection 时也要显式告知客户端：本响应结束后连接即关闭
    if !connection_written {
        out.push_str("Connection: close\r\n");
    }

    out.push_str("\r\n");
    out
}

/// 把上游返回的 Location 重写为 `/<prefix>/<绝对URL>`。
///
/// 相对路径按目标 URL 解析为绝对 URL（`/a` 与 `//host/a` 都支持）；
/// 非 http(s) 协议（如 `mailto:`）不重写，返回 `None` 保持原值。
fn rewrite_location(location: &str, cfg: &PathProxyConfig, base: &url::Url) -> Option<String> {
    if location.is_empty() {
        return None;
    }
    let abs = base.join(location).ok()?;
    if !matches!(abs.scheme(), "http" | "https") {
        return None;
    }
    Some(format!("/{}/{}", cfg.prefix(), abs.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PathProxyConfig {
        PathProxyConfig::new("px", false, true).unwrap()
    }
    // ─── 响应头重写 ───

    fn base() -> url::Url {
        url::Url::parse("https://example.com/dir/file").unwrap()
    }

    #[test]
    fn test_parse_status_code() {
        assert_eq!(parse_status_code(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status_code(b"HTTP/1.0 404 Not Found\r\n"), Some(404));
        assert_eq!(parse_status_code(b"garbage"), None);
    }

    #[test]
    fn test_rebuild_response_head_rewrites_absolute_location() {
        let head = b"HTTP/1.1 302 Found\r\n\
                     Location: https://cdn.example.com/x.zip\r\n\
                     Content-Length: 0\r\n\r\n";
        let out = rebuild_response_head(head, Some(302), &cfg(), &base());
        assert!(
            out.contains("Location: /px/https://cdn.example.com/x.zip\r\n"),
            "got: {}",
            out
        );
        assert!(out.contains("Connection: close\r\n"));
    }

    #[test]
    fn test_rebuild_response_head_resolves_relative_location() {
        let head = b"HTTP/1.1 301 Moved\r\nLocation: /other\r\n\r\n";
        let out = rebuild_response_head(head, Some(301), &cfg(), &base());
        assert!(out.contains("Location: /px/https://example.com/other\r\n"), "got: {}", out);
    }

    #[test]
    fn test_rebuild_response_head_keeps_location_when_disabled() {
        let c = PathProxyConfig::new("px", false, false).unwrap();
        let head = b"HTTP/1.1 302 Found\r\nLocation: https://cdn.example.com/x\r\n\r\n";
        let out = rebuild_response_head(head, Some(302), &c, &base());
        assert!(out.contains("Location: https://cdn.example.com/x\r\n"));
    }

    #[test]
    fn test_rebuild_response_head_ignores_location_on_200() {
        let head = b"HTTP/1.1 200 OK\r\nLocation: https://cdn.example.com/x\r\n\r\n";
        let out = rebuild_response_head(head, Some(200), &cfg(), &base());
        assert!(out.contains("Location: https://cdn.example.com/x\r\n"));
    }

    #[test]
    fn test_rewrite_location_skips_non_http_scheme() {
        let base_url = base();
        assert!(rewrite_location("mailto:a@b.com", &cfg(), &base_url).is_none());
    }
}
