//! 请求编排：读头 → 分类 → 认证 → 分流到 CONNECT / 经典转发 / 路径前缀直连
//!
//! 本模块只决定"一条客户端连接上发生什么、按什么顺序"，具体转发实现在
//! [`crate::protocol::connect`] 与 [`crate::protocol::classic`]。

use crate::config::AuthUser;
use crate::protocol::auth::{check_path_auth, check_proxy_auth, send_auth_required, send_path_auth_required};
use crate::protocol::classic::handle_http_request_generic;
use crate::protocol::connect::handle_connect_generic;
use crate::protocol::http_response::{send_404_not_found, send_head_too_large};
use crate::protocol::http_util::{head_end_offset, MAX_HEAD_BYTES};
use crate::protocol::path_proxy::{
    handle_path_proxy, PathProxyConfig, PathProxyRequest, PathProxyRuntime,
};
use crate::protocol::request::{read_request_head, HeadStatus};
use crate::support::buffer_pool::BufferPool;
use crate::support::net::is_benign_close_error;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Handle an HTTP proxy client connection with buffer reuse (plain TCP entrypoint)
///
/// `auth` 为 `None` 时不启用认证；为 `Some(用户列表)` 时要求客户端通过 HTTP Basic
/// 认证（`Proxy-Authorization` 头），否则返回 407 并关闭连接。
///
/// `path_proxy` 为 `Some` 时额外启用路径前缀直连模式
/// （`/px/https://example.com/` → 直连该站点，见 [`crate::protocol::path_proxy`]）。
pub async fn handle_client(
    client: TcpStream,
    timeout: u64,
    buffer_pool: BufferPool,
    auth: Option<Arc<[AuthUser]>>,
    path_proxy: Arc<Option<PathProxyConfig>>,
) {
    let client_addr = match client.peer_addr() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Failed to get client address: {}", e);
            return;
        }
    };
    handle_client_generic(client, client_addr, timeout, buffer_pool, auth, path_proxy).await;
}

/// Handle an HTTP proxy client connection with a pre-resolved address.
///
/// 用于两类场景：
/// 1. PROXY Protocol：真实客户端 IP 从 PROXY Protocol 头提取，而非从 `peer_addr()`
///    获取（后者返回的是 nginx/LB 的 IP）；
/// 2. TLS 连接：`TlsStream` 不直接暴露 `peer_addr()`，地址需在 accept 时提前获取。
pub async fn handle_client_with_addr<S>(
    client: S,
    client_addr: SocketAddr,
    timeout: u64,
    buffer_pool: BufferPool,
    auth: Option<Arc<[AuthUser]>>,
    path_proxy: Arc<Option<PathProxyConfig>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_client_generic(client, client_addr, timeout, buffer_pool, auth, path_proxy).await;
}

/// 通用客户端连接处理逻辑（与具体传输层 TCP/TLS 无关）
///
/// 接受任意 AsyncRead + AsyncWrite 流，完成请求头读取、解析、认证、分发到
/// CONNECT / HTTP 代理 / 路径前缀直连三种处理路径。
async fn handle_client_generic<S>(
    mut client: S,
    client_addr: SocketAddr,
    timeout: u64,
    buffer_pool: BufferPool,
    auth: Option<Arc<[AuthUser]>>,
    path_proxy: Arc<Option<PathProxyConfig>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let timeout_duration = Duration::from_secs(timeout);

    // 读取完整请求头（含可能的 body 前缀），常见情况零拷贝复用池化缓冲区
    let (storage, head_status) = match read_request_head(&mut client, &buffer_pool, timeout_duration)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            if is_benign_close_error(&e) {
                debug!("Read from client {} ended: {}", client_addr, e);
            } else {
                warn!("Failed to read request from client {}: {}", client_addr, e);
            }
            return;
        }
    };

    match head_status {
        // 头部超过 MAX_HEAD_BYTES：畸形或恶意，必须在分派前拒绝。
        // 历史实现把已读字节当作完整头继续处理：`head_end_offset` 找不到 `\r\n\r\n` 时
        // 退化为 `data.len()`，于是截断的头被转发给上游——上游等不到剩余头部，代理却
        // 已在发 body，两侧一直卡到各自超时；若截断点恰好落在合法请求行之后，还会把
        // 畸形流量当成正常代理请求放行。
        HeadStatus::Overflow => {
            warn!(
                "Request head from {} exceeds {} bytes, rejecting",
                client_addr, MAX_HEAD_BYTES
            );
            send_head_too_large(&mut client, timeout_duration).await;
            return;
        }
        // 客户端在头结束前断开：同样不能当完整头解析。转发时 `UpstreamHead::build`
        // 会补上结束空行，上游会把截断的头当作合法请求，客户端却已不在——
        // 白白消耗一条到目标的连接。直接丢弃，与"读到 0 字节"的处理一致。
        HeadStatus::Incomplete => {
            debug!(
                "Client {} closed before request head was complete, dropping",
                client_addr
            );
            return;
        }
        HeadStatus::Complete => {}
    }

    let data = storage.as_slice();
    // 请求头结束位置（body 起始偏移）；只有 `Complete` 才会走到这里，结束符必然存在
    let head_end = head_end_offset(data);
    let head = &data[..head_end];
    // 请求头为 ASCII，lossy 转换不会损坏后续二进制 body（body 按字节切片处理）
    let head_str = String::from_utf8_lossy(head);

    let request_line = match head_str.lines().next() {
        Some(line) => line,
        None => return,
    };

    info!("{} -> {}", client_addr, request_line);

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        warn!("Invalid request from {}: {}", client_addr, request_line);
        return;
    }

    let method = parts[0];
    let url = parts[1];

    // 第零步：路径前缀直连模式（如 /px/https://www.baidu.com/）。
    // 必须在代理请求分类之前判断——该形式是 origin-form 相对路径，会被 classify 判为
    // Invalid 而直接 404。只有前缀精确命中才接管，其余相对路径仍走 404（保持反扫描）。
    if let Some(cfg) = path_proxy.as_ref() {
        if let Some(target) = cfg.match_target(url) {
            // 复用代理认证：配置了 [[auth]] 时同样要求 Basic 凭据（401 质询）。
            // 认证成功时记录凭据所在的头，转发上游前必须剔除（否则凭据泄漏给目标站点）。
            let mut auth_header: Option<&'static str> = None;
            if let Some(users) = auth.as_deref() {
                match check_path_auth(&head_str, users) {
                    Some(source) => auth_header = Some(source.header_name()),
                    None => {
                        send_path_auth_required(&mut client, timeout_duration).await;
                        warn!("[path-proxy] authentication failed from {}", client_addr);
                        return;
                    }
                }
            }
            handle_path_proxy(
                client,
                client_addr,
                PathProxyRequest {
                    method,
                    target_url: target,
                    data,
                    head_end,
                    drop_header: auth_header,
                },
                PathProxyRuntime {
                    cfg,
                    timeout: timeout_duration,
                    buffer_pool: &buffer_pool,
                },
            )
            .await;
            return;
        }
    }

    // 第一步：判断是否为"合法代理请求"。
    // 反扫描策略：非代理格式请求直接返回 404，扫描器无法从响应识别这是代理端口。
    // 合法代理请求仅两种：
    //   1. CONNECT host:port HTTP/x.x          （HTTPS 隧道）
    //   2. METHOD http://host/... HTTP/x.x      （HTTP 代理绝对 URL）
    let kind = classify_proxy_request(method, url);
    match kind {
        ProxyRequestKind::Invalid => {
            // 不是代理请求（如 GET /、GET /admin、格式非法）→ 伪装成普通网站的 404
            debug!("Non-proxy request from {} ({} {}): returning 404", client_addr, method, url);
            send_404_not_found(&mut client, timeout_duration).await;
            return;
        }
        ProxyRequestKind::Connect => {} // 继续流程
        ProxyRequestKind::HttpAbsolute => {} // 继续流程
    }

    // 第二步：认证校验。配置了 [[auth]] 时才校验。
    // 只有确认是代理请求后才会可能返回 407，降低"被扫描识别为代理"的风险。
    if let Some(users) = auth.as_deref() {
        if !check_proxy_auth(&head_str, users) {
            send_auth_required(&mut client, timeout_duration).await;
            warn!("Proxy authentication failed from {}", client_addr);
            return;
        }
    }

    // Handle CONNECT method (HTTPS tunneling)
    if method == "CONNECT" {
        // 请求头之后的字节是隧道协议数据（如 TLS ClientHello），必须保留并交给隧道
        let leftover = &data[head_end..];
        handle_connect_generic(client, url, client_addr, timeout_duration, leftover).await;
        return;
    }

    // Handle HTTP proxy request with buffer pool
    handle_http_request_generic(client, data, head_end, client_addr, timeout_duration, buffer_pool).await;
}

/// 代理请求分类结果
enum ProxyRequestKind {
    /// 合法的 HTTP 代理请求（绝对 URL 形式），携带 scheme（应为 http/https）
    HttpAbsolute,
    /// 合法的 HTTPS CONNECT 隧道请求（host:port 形式）
    Connect,
    /// 非代理请求 / 格式非法 —— 应返回 404 反扫描
    Invalid,
}

/// 分类请求：识别"合法代理请求"与"直连/扫描请求"。
///
/// 返回 `Invalid` 时应直接返回 404，让扫描器无法识别这是代理端口。
fn classify_proxy_request(method: &str, url: &str) -> ProxyRequestKind {
    // 1) CONNECT: URL 必须是 host:port 形式，不含 "://"
    if method == "CONNECT" {
        // CONNECT 请求 URL 规范：hostname[:port]，不能是 URL
        if url.contains("://") {
            return ProxyRequestKind::Invalid;
        }
        // 允许有 port，也允许无 port（默认 443）。
        // 简单校验：至少有 host，且 host 不含空白、'/'、'?'、'#'（绝对 URL 特征）
        let has_banned = url.chars().any(|c| c == '/' || c == '?' || c == '#');
        if has_banned || url.is_empty() {
            return ProxyRequestKind::Invalid;
        }
        return ProxyRequestKind::Connect;
    }

    // 2) 其他 METHOD：必须是 "http://..." 或 "https://..." 绝对 URL 形式
    //    代理规范：客户端对 GET/POST 等发的是完整绝对 URL（scheme://host/path）
    if url.starts_with("http://") || url.starts_with("https://") {
        // 补充：必须能被 url 解析并含 host
        match url::Url::parse(url) {
            Ok(parsed) if parsed.host_str().is_some() => {
                return ProxyRequestKind::HttpAbsolute;
            }
            _ => return ProxyRequestKind::Invalid,
        }
    }

    // 3) 其余情况：相对路径（GET /、GET /admin）、其它 scheme（ftp://）等
    ProxyRequestKind::Invalid
}

#[cfg(test)]
mod tests {
    use super::*;
    // ─── classify_proxy_request 反扫描测试 ───

    #[test]
    fn test_classify_connect_valid_host_port() {
        matches!(
            classify_proxy_request("CONNECT", "example.com:443"),
            ProxyRequestKind::Connect
        );
    }

    #[test]
    fn test_classify_connect_no_port() {
        // CONNECT 允许无 port（parse_host_port 会补默认 443）
        matches!(
            classify_proxy_request("CONNECT", "example.com"),
            ProxyRequestKind::Connect
        );
    }

    #[test]
    fn test_classify_connect_ipv4() {
        matches!(
            classify_proxy_request("CONNECT", "1.1.1.1:443"),
            ProxyRequestKind::Connect
        );
    }

    #[test]
    fn test_classify_connect_rejects_url_form() {
        // CONNECT 带 scheme → 非法
        matches!(
            classify_proxy_request("CONNECT", "https://example.com:443"),
            ProxyRequestKind::Invalid
        );
    }

    #[test]
    fn test_classify_connect_rejects_path_characters() {
        // CONNECT 带路径 → 非法
        matches!(
            classify_proxy_request("CONNECT", "example.com/path"),
            ProxyRequestKind::Invalid
        );
    }

    #[test]
    fn test_classify_http_absolute_valid() {
        matches!(
            classify_proxy_request("GET", "http://example.com/a/b"),
            ProxyRequestKind::HttpAbsolute
        );
    }

    #[test]
    fn test_classify_http_absolute_https_scheme() {
        matches!(
            classify_proxy_request("GET", "https://example.com/"),
            ProxyRequestKind::HttpAbsolute
        );
    }

    #[test]
    fn test_classify_http_absolute_post() {
        matches!(
            classify_proxy_request("POST", "http://api.example.com/upload"),
            ProxyRequestKind::HttpAbsolute
        );
    }

    #[test]
    fn test_classify_scan_requests_return_invalid() {
        // 扫描器直接访问代理端口 → 应该得到 404
        // 相对路径（直接浏览器访问代理端口）
        matches!(classify_proxy_request("GET", "/"), ProxyRequestKind::Invalid);
        matches!(classify_proxy_request("GET", "/index.html"), ProxyRequestKind::Invalid);
        matches!(classify_proxy_request("GET", "/admin"), ProxyRequestKind::Invalid);
        matches!(classify_proxy_request("HEAD", "/"), ProxyRequestKind::Invalid);
        matches!(classify_proxy_request("POST", "/api/login"), ProxyRequestKind::Invalid);
        matches!(classify_proxy_request("OPTIONS", "*"), ProxyRequestKind::Invalid);

        // 无 host 的绝对 URL
        matches!(
            classify_proxy_request("GET", "http:///onlypath"),
            ProxyRequestKind::Invalid
        );

        // 其他 scheme：ftp proxy，当前不支持
        matches!(
            classify_proxy_request("GET", "ftp://files.example.com/a"),
            ProxyRequestKind::Invalid
        );
    }
}
