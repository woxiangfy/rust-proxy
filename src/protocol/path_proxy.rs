//! 路径前缀直连模式（Path-Prefix Direct Proxy）
//!
//! 让代理服务器同时充当「URL 前缀网关」（类似 gh-proxy.com 的用法）：
//! 客户端把目标完整 URL 拼在前缀路径之后，由代理服务器直连上游并原样回传内容。
//!
//! ```text
//! GET http://1.2.3.4:80/px/https://www.baidu.com/   ⟶   实际访问 https://www.baidu.com/
//! GET http://1.2.3.4:80/px/http://example.com/a.txt ⟶   实际访问 http://example.com/a.txt
//! ```
//!
//! 前缀 `px` 由配置文件 `path_proxy_prefix`（或命令行 `--path-proxy-prefix`）定义。
//!
//! 与既有 HTTP 代理模式的区别：
//! - 普通代理模式：客户端必须把代理地址配置为 HTTP 代理，请求行是绝对 URL 或 CONNECT
//! - 本模式：客户端**完全无感知**，直接请求形如 `http://proxy/px/<目标URL>` 的普通网址即可
//!
//! 设计要点：
//! 1. **仅当前缀精确匹配时才接管**，其余相对路径请求仍返回 404（保持反扫描特性，
//!    前缀本身即相当于一个「路径口令」）。
//! 2. 支持 http / https 上游：https 上游使用系统 CA 校验证书（可用 `path_proxy_insecure_tls`
//!    关闭校验，适合自签内网站点）。
//! 3. 请求头过滤逐跳头（Connection / Proxy-* / Upgrade / Expect 等），Host 重写为上游主机，
//!    body 按 Content-Length / chunked 流式转发，不缓冲整个请求体。
//! 4. 响应按原始字节流式转发（chunked / gzip 保持原样），仅在 3xx 时按需把 `Location`
//!    重写为 `/<prefix>/<绝对URL>`，使重定向后的请求继续走本代理。
//! 5. 上游建头与经典代理共用 [`crate::protocol::forward`]：畸形/冲突 `Content-Length`
//!    统一返回 400，`Transfer-Encoding` 整行原样转发（不折叠编码声明）。
//!
//! 文件布局：本文件保留配置、前缀匹配与请求编排；上游连接在 [`upstream`]，
//! 请求发送与经典代理共用 `crate::protocol::relay::send_upstream_request`
//! （写头 → 应答 100-continue → 转发请求体），响应头读取与重建在 [`response`]。

use crate::protocol::forward::{ForwardTarget, UpstreamHead};
use crate::protocol::http_response::write_response;
use crate::support::buffer_pool::BufferPool;
use crate::support::net::is_benign_close_error;
use anyhow::Result;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

mod response;
mod upstream;

use crate::protocol::relay::{send_upstream_request, RelayLink, RequestBodyForward};
use response::forward_response;
use upstream::connect_upstream;
/// 路径前缀直连模式配置
#[derive(Debug, Clone)]
pub struct PathProxyConfig {
    /// 路径前缀（不含 `/`），如 `px` → `/px/https://example.com/`
    prefix: String,
    /// 是否跳过上游 TLS 证书校验（自签证书场景）
    pub insecure_tls: bool,
    /// 是否把 3xx 响应的 `Location` 重写为 `/<prefix>/<绝对URL>`
    pub rewrite_location: bool,
}

impl PathProxyConfig {
    /// 构造配置并校验前缀合法性。
    ///
    /// 前缀会自动去除首尾空白与 `/`；仅允许 ASCII 字母、数字、`-`、`_`、`.`。
    /// 其它字符（空白、`/`、`?`、`#`、`%`、非 ASCII）会破坏路径匹配的确定性，
    /// 或被客户端 percent-encode 后导致匹配不到。
    pub fn new(prefix: &str, insecure_tls: bool, rewrite_location: bool) -> Result<Self> {
        let p = prefix.trim().trim_matches('/');
        if p.is_empty() {
            anyhow::bail!("path proxy prefix must not be empty");
        }
        if let Some(c) = p
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        {
            anyhow::bail!(
                "invalid character '{}' in path proxy prefix '{}' (allowed: ASCII letters, digits, '-', '_', '.')",
                c,
                p
            );
        }
        Ok(Self {
            prefix: p.to_string(),
            insecure_tls,
            rewrite_location,
        })
    }

    #[inline]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// 判断请求目标是否命中前缀，命中则返回去掉前缀后的目标 URL。
    ///
    /// 例如前缀为 `px` 且请求目标为 `/px/https://a.com/b` → 返回 `https://a.com/b`。
    /// 未命中（含 `/px` 自身、`/pxx/...`）返回 `None`。
    pub fn match_target<'a>(&self, request_target: &'a str) -> Option<&'a str> {
        let rest = request_target.strip_prefix('/')?;
        let rest = rest.strip_prefix(self.prefix.as_str())?;
        // 前缀后必须紧跟 '/'，避免 `/pxx/` 被误判为 `/px`
        let rest = rest.strip_prefix('/')?;
        if rest.is_empty() {
            None
        } else {
            Some(rest)
        }
    }
}

/// 一次路径前缀直连请求的输入（调用方已从报文中解析出的请求描述）
///
/// 把这些字段打包，一是为了压住参数个数，二是让"哪些是逐请求的、哪些是进程级的"
/// 在签名上显式可见（后者见 [`PathProxyRuntime`]）。
pub(super) struct PathProxyRequest<'a> {
    /// 请求方法（GET / POST / ...）
    pub method: &'a str,
    /// 目标 URL（含 scheme），由 [`PathProxyConfig::match_target`] 解析得到
    pub target_url: &'a str,
    /// 已读入的原始数据（头 + 可能的 body 前缀），保持与普通代理一致的零拷贝思路
    pub data: &'a [u8],
    /// body 起始偏移（`data` 中头结束位置）
    pub head_end: usize,
    /// 本次用于认证的请求头名；认证成功后转发上游前必须剔除，避免凭据泄漏
    pub drop_header: Option<&'static str>,
}

/// 路径前缀直连的运行期参数（与单次请求无关，整个进程共用）
#[derive(Clone, Copy)]
pub(super) struct PathProxyRuntime<'a> {
    pub cfg: &'a PathProxyConfig,
    pub timeout: Duration,
    pub buffer_pool: &'a BufferPool,
}

/// 处理一次路径前缀直连请求。
pub(super) async fn handle_path_proxy<S>(
    mut client: S,
    client_addr: SocketAddr,
    req: PathProxyRequest<'_>,
    rt: PathProxyRuntime<'_>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // 解构后沿用原有变量名，函数体无需改动
    let PathProxyRequest {
        method,
        target_url,
        data: request_data,
        head_end,
        drop_header,
    } = req;
    let PathProxyRuntime {
        cfg,
        timeout,
        buffer_pool,
    } = rt;

    // ── 1. 解析目标 URL ──
    let parsed = match url::Url::parse(target_url) {
        Ok(u) => u,
        Err(e) => {
            warn!(
                "[path-proxy] invalid target URL '{}' from {}: {}",
                target_url, client_addr, e
            );
            send_error(
                &mut client,
                400,
                "Bad Request",
                &format!("invalid target URL, expected /{}/http://host/path", cfg.prefix()),
            )
            .await;
            return;
        }
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        send_error(
            &mut client,
            400,
            "Bad Request",
            "only http and https targets are supported",
        )
        .await;
        return;
    }
    if parsed.host_str().is_none() {
        send_error(&mut client, 400, "Bad Request", "target URL has no host").await;
        return;
    }

    // 与经典代理共用同一份目标解析：authority（Host 头，IPv6 带方括号）与
    // connect_host（socket/SNI，IPv6 去方括号）在这里一次算清。
    let target = match ForwardTarget::from_url(method, target_url, &parsed) {
        Some(t) => t,
        None => {
            send_error(&mut client, 400, "Bad Request", "target URL has no known port").await;
            return;
        }
    };

    info!(
        "{} -> PATH {} {} (prefix /{}/)",
        client_addr,
        method,
        target_url,
        cfg.prefix()
    );

    // ── 2. 连接上游（http 明文 / https TLS）──
    let mut upstream = match connect_upstream(&target, cfg, timeout).await {
        Ok(s) => s,
        Err(e) => {
            error!(
                "[path-proxy] failed to connect upstream '{}' for {}: {:#}",
                target_url, client_addr, e
            );
            send_error(&mut client, 502, "Bad Gateway", "upstream connection failed").await;
            return;
        }
    };

    // ── 3. 重写并发送请求头（与经典代理共用同一份建头实现）──
    let request_head = String::from_utf8_lossy(&request_data[..head_end]).to_string();
    let head = match UpstreamHead::build_filtered(&target, &request_head, drop_header) {
        Some(h) => h,
        None => {
            // 非数字或互相冲突的 Content-Length：代理与上游会对 body 边界产生不同
            // 理解，只能 fail-closed。这是相对旧实现的**有意收紧**（旧实现静默丢 CL）。
            warn!(
                "[path-proxy] malformed framing headers from {} for '{}', rejecting",
                client_addr, target_url
            );
            send_error(
                &mut client,
                400,
                "Bad Request",
                "conflicting or non-numeric Content-Length",
            )
            .await;
            return;
        }
    };

    // ── 4. 转发请求（写头 → 按需应答 100-continue → 转发 body）──
    // 与经典代理共用 relay::send_upstream_request，仅用 RelayLink 区分日志来源
    let buffered_body = &request_data[head_end..];
    if send_upstream_request(
        &mut client,
        &mut upstream,
        &head,
        RequestBodyForward {
            buffered: buffered_body,
            content_length: head.content_length,
            chunked: head.chunked,
            timeout,
            buffer_pool,
            link: RelayLink::PathPrefix,
            client_addr,
        },
    )
    .await
    .is_err()
    {
        return;
    }

    // ── 5. 回传响应（必要时重写 Location）──
    match forward_response(&mut client, &mut upstream, cfg, &parsed, timeout, buffer_pool).await {
        Ok(()) => info!("[path-proxy] completed: {} {}", method, target_url),
        Err(e) if is_benign_close_error(&e) => {
            debug!("[path-proxy] response ended early: {}", e)
        }
        Err(e) => warn!("[path-proxy] response error for '{}': {}", target_url, e),
    }
}

/// 发送最小化错误响应（用于 400 / 502，不暴露运行时细节）
///
/// 报文骨架统一交给 [`write_response`] 构造（`Content-Type` → `Content-Length` →
/// `Connection: close`），本模块不再手写字符串：这类响应是机器可读的协议输出，
/// 漏写 `Content-Length` 或 `Connection: close` 都会让客户端挂起。
async fn send_error<W: AsyncWrite + Unpin>(client: &mut W, code: u16, reason: &str, msg: &str) {
    write_response(
        client,
        &format!("{} {}", code, reason),
        &[("Content-Type", "text/plain; charset=utf-8")],
        msg.as_bytes(),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PathProxyConfig {
        PathProxyConfig::new("px", false, true).unwrap()
    }

    // ─── 前缀匹配 ───

    #[test]
    fn test_match_target_basic() {
        assert_eq!(
            cfg().match_target("/px/https://www.baidu.com/"),
            Some("https://www.baidu.com/")
        );
    }

    #[test]
    fn test_match_target_with_query_and_anchor() {
        assert_eq!(
            cfg().match_target("/px/http://a.com/b?x=1&y=2#frag"),
            Some("http://a.com/b?x=1&y=2#frag")
        );
    }

    #[test]
    fn test_match_target_rejects_other_prefixes() {
        // 前缀必须精确，`/pxx/` 与 `/p/` 都不应命中
        assert!(cfg().match_target("/pxx/https://a.com/").is_none());
        assert!(cfg().match_target("/p/https://a.com/").is_none());
        assert!(cfg().match_target("/https://a.com/").is_none());
        // 前缀自身、前缀+斜杠
        assert!(cfg().match_target("/px").is_none());
        assert!(cfg().match_target("/px/").is_none());
        // 普通相对路径仍需返回 None（保持 404 反扫描）
        assert!(cfg().match_target("/").is_none());
        assert!(cfg().match_target("/index.html").is_none());
    }

    #[test]
    fn test_match_target_requires_leading_slash() {
        assert!(cfg().match_target("px/https://a.com/").is_none());
    }

    // ─── 配置校验 ───

    #[test]
    fn test_config_trims_slashes_and_space() {
        let c = PathProxyConfig::new("  /px/  ", false, true).unwrap();
        assert_eq!(c.prefix(), "px");
    }

    #[test]
    fn test_config_rejects_invalid_prefix() {
        assert!(PathProxyConfig::new("", false, true).is_err());
        assert!(PathProxyConfig::new("   ", false, true).is_err());
        assert!(PathProxyConfig::new("p/x", false, true).is_err());
        assert!(PathProxyConfig::new("p x", false, true).is_err());
        assert!(PathProxyConfig::new("p%x", false, true).is_err());
        assert!(PathProxyConfig::new("p?x", false, true).is_err());
        // 非 ASCII：客户端会 percent-encode，导致前缀永远匹配不上
        assert!(PathProxyConfig::new("代理", false, true).is_err());
        assert!(PathProxyConfig::new("pé", false, true).is_err());
    }

    #[test]
    fn test_config_accepts_common_prefixes() {
        for p in ["px", "gh-proxy", "dl_2024", "v1.2", "PX9"] {
            assert!(PathProxyConfig::new(p, false, true).is_ok(), "{} should be valid", p);
        }
    }

    // ─── 请求头构造（与经典代理共用 protocol::forward） ───

    fn target<'a>(method: &'a str, raw: &'a str) -> ForwardTarget<'a> {
        let u = url::Url::parse(raw).unwrap();
        ForwardTarget::from_url(method, raw, &u).unwrap()
    }

    #[test]
    fn test_upstream_head_rewrites_request_line_and_host() {
        let t = target("POST", "https://example.com/a/b?q=1");
        let head = "POST /px/https://example.com/a/b?q=1 HTTP/1.1\r\n\
                    Host: 1.2.3.4\r\n\
                    User-Agent: curl\r\n\
                    Connection: keep-alive\r\n\
                    Content-Length: 5\r\n\r\n";
        let req = UpstreamHead::build_filtered(&t, head, None).expect("valid framing headers");
        let out = &req.bytes;
        assert!(out.starts_with("POST /a/b?q=1 HTTP/1.1\r\n"), "got: {}", out);
        assert!(out.contains("Host: example.com\r\n"));
        assert!(!out.contains("1.2.3.4"), "proxy host must be replaced");
        assert!(out.contains("User-Agent: curl\r\n"));
        assert_eq!(out.matches("Connection: close").count(), 1);
        assert_eq!(req.content_length, Some(5));
        assert!(!req.chunked);
        assert!(!req.expect_continue);
    }

    #[test]
    fn test_upstream_head_drops_hop_by_hop_headers() {
        let t = target("GET", "http://example.com/");
        let head = "GET /px/http://example.com/ HTTP/1.1\r\n\
                    Host: 1.2.3.4\r\n\
                    Proxy-Authorization: Basic xxxx\r\n\
                    Proxy-Connection: keep-alive\r\n\
                    Connection: keep-alive\r\n\
                    Upgrade: websocket\r\n\
                    Expect: 100-continue\r\n\
                    Accept: */*\r\n\r\n";
        let req = UpstreamHead::build_filtered(&t, head, None).expect("valid framing headers");
        let lower = req.bytes.to_ascii_lowercase();
        assert!(!lower.contains("proxy-authorization"), "credentials must not leak");
        assert!(!lower.contains("proxy-connection"));
        assert!(!lower.contains("upgrade:"));
        assert!(!lower.contains("expect:"), "100-continue is answered by the proxy");
        assert_eq!(lower.matches("connection:").count(), 1, "only the rewritten Connection header");
        assert!(req.bytes.contains("Accept: */*"));
        assert!(req.expect_continue, "must remember to answer 100-continue");
    }

    /// `Connection` 里点名的自定义字段同样不得转发（RFC 7230 §6.1）
    #[test]
    fn test_upstream_head_drops_connection_named_headers() {
        let t = target("GET", "http://example.com/");
        let head = "GET /px/http://example.com/ HTTP/1.1\r\n\
                    Host: 1.2.3.4\r\n\
                    Connection: close, X-Hop\r\n\
                    X-Hop: secret\r\n\
                    X-Keep: ok\r\n\r\n";
        let req = UpstreamHead::build_filtered(&t, head, None).expect("valid framing headers");

        let lower = req.bytes.to_ascii_lowercase();
        assert!(!lower.contains("x-hop"), "Connection 点名的头必须丢弃：{}", req.bytes);
        assert!(req.bytes.contains("X-Keep: ok"), "未点名的端到端头必须保留");
    }

    /// 用于认证的 `Authorization` 头不得转发给目标站点（凭据泄漏）。
    #[test]
    fn test_upstream_head_drops_authorization_used_for_auth() {
        let t = target("GET", "http://example.com/");
        let head = "GET /px/http://example.com/ HTTP/1.1\r\n\
                    Host: 1.2.3.4\r\n\
                    Authorization: Basic dTpw\r\n\r\n";
        let req = UpstreamHead::build_filtered(&t, head, Some("authorization")).expect("valid framing headers");
        assert!(
            !req.bytes.to_ascii_lowercase().contains("authorization"),
            "proxy credentials leaked: {}",
            req.bytes
        );
        let req2 = UpstreamHead::build_filtered(&t, head, Some("proxy-authorization")).expect("valid framing headers");
        assert!(req2.bytes.contains("Authorization: Basic dTpw\r\n"));
    }

    #[test]
    fn test_upstream_head_chunked_drops_content_length() {
        let t = target("POST", "http://example.com/up");
        let head = "POST /px/http://example.com/up HTTP/1.1\r\n\
                    Host: 1.2.3.4\r\n\
                    Content-Length: 3\r\n\
                    Transfer-Encoding: chunked\r\n\r\n";
        let req = UpstreamHead::build_filtered(&t, head, None).expect("valid framing headers");
        assert!(req.chunked);
        assert_eq!(req.content_length, None);
        assert!(req.bytes.contains("Transfer-Encoding: chunked\r\n"));
        assert!(!req.bytes.contains("Content-Length"), "must not send both framings");
        assert!(req.bytes.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_upstream_head_preserves_unsupported_te_line() {
        // 行为变更：旧实现会丢弃非 chunked 的 Transfer-Encoding 行；
        // 统一后整行原样保留，由上游按其声明的编码链处理 body。
        let t = target("POST", "http://example.com/up");
        let head = "POST /px/http://example.com/up HTTP/1.1\r\n\
                    Host: 1.2.3.4\r\n\
                    Transfer-Encoding: gzip\r\n\
                    Content-Length: 3\r\n\r\n";
        let req = UpstreamHead::build_filtered(&t, head, None).expect("valid framing headers");
        assert!(!req.chunked);
        assert!(req.bytes.contains("Transfer-Encoding: gzip\r\n"));
        assert_eq!(req.content_length, Some(3));
    }

    // ─── 错误响应 ───

    #[tokio::test]
    async fn test_send_error_uses_shared_response_skeleton() {
        // 错误响应必须与 http_response::write_response 完全一致（含 CL 与 Connection: close），
        // 否则客户端可能因为缺少分帧信息而挂起
        let mut out = Vec::new();
        send_error(&mut out, 400, "Bad Request", "bad path").await;

        let mut expected = Vec::new();
        write_response(
            &mut expected,
            "400 Bad Request",
            &[("Content-Type", "text/plain; charset=utf-8")],
            b"bad path",
        )
        .await;

        assert_eq!(out, expected);
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(!text.contains("Server:"), "错误响应不得暴露 Server 头");
    }
}
