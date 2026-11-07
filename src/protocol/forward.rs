//! 转发目标解析与上游请求头构造
//!
//! 经典 HTTP 代理（absolute-form）与路径前缀直连（origin-form）在语义上是同一件事：
//! 把客户端请求改写成一条 origin-form 的上游请求。因此建头规则只允许在这里实现一份，
//! 否则两条链路的 `Host` / `Content-Length` / `Transfer-Encoding` 语义会各自漂移，
//! 而任何一次漂移都是请求走私或内容解码错误的入口。
//!
//! 本模块只做纯函数，不建立连接、不读写 socket；调用方负责 400/502 等响应。

use crate::protocol::http_util::{authority_of, connection_named_headers, is_hop_by_hop};
use log::error;
use std::net::SocketAddr;

/// 一次转发的目标信息（由请求行 + 绝对 URL 解析得出）
///
/// `authority` 与 `connect_host` 都来自同一次 `url::Url` 解析：
/// - `authority`：写进上游 `Host` 头，IPv6 保留方括号（`[::1]:8080`）
/// - `connect_host`：交给 `lookup_host` / TLS SNI，IPv6 去掉方括号（`::1`）
///
/// 把两种形式在同一次解析里分开保存，避免每个调用点各自处理方括号。
pub(crate) struct ForwardTarget<'a> {
    pub(crate) method: &'a str,
    pub(crate) url: &'a str,
    /// 请求目标协议（分类阶段只允许 http/https；经典转发只服务 http）
    pub(crate) scheme: String,
    /// 上游 `Host` 头值：绝对 URL 的 authority（IPv6 带方括号，显式端口保留）
    pub(crate) authority: String,
    /// 用于 socket 连接 / DNS 解析 / TLS SNI 的主机名（IPv6 不带方括号）
    pub(crate) connect_host: String,
    pub(crate) port: u16,
    /// origin-form 请求目标：path + query，直连上游的标准形式
    pub(crate) origin_form: String,
}

impl<'a> ForwardTarget<'a> {
    /// 从请求头解析转发目标；格式非法时返回 `None`（调用方保持"静默丢弃"语义）
    pub(crate) fn parse(head_str: &'a str, client_addr: SocketAddr) -> Option<Self> {
        let request_line = head_str.lines().next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?;
        let url = parts.next()?;

        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                error!("Failed to parse URL '{}' from {}: {}", url, client_addr, e);
                return None;
            }
        };

        let host = match parsed.host_str() {
            Some(h) => h,
            None => {
                error!("No host in URL '{}' from {}", url, client_addr);
                return None;
            }
        };

        // 端口按 scheme 取已知默认值：https 绝对 URL 不能落到 80（历史实现写死 80）
        let port = match parsed.port_or_known_default() {
            Some(p) => p,
            None => {
                error!(
                    "No known default port for scheme '{}' in URL '{}' from {}",
                    parsed.scheme(),
                    url,
                    client_addr
                );
                return None;
            }
        };

        Some(Self::assemble(method, url, &parsed, host, port))
    }

    /// 从已解析的 URL 构造（路径前缀直连在完成 scheme/host 校验后调用）
    pub(crate) fn from_url(method: &'a str, raw_url: &'a str, parsed: &url::Url) -> Option<Self> {
        let host = parsed.host_str()?;
        let port = parsed.port_or_known_default()?;
        Some(Self::assemble(method, raw_url, parsed, host, port))
    }

    fn assemble(
        method: &'a str,
        url: &'a str,
        parsed: &url::Url,
        host: &str,
        port: u16,
    ) -> Self {
        let origin_form = match parsed.query() {
            Some(q) => format!("{}?{}", parsed.path(), q),
            None => parsed.path().to_string(),
        };
        Self {
            method,
            url,
            scheme: parsed.scheme().to_string(),
            authority: authority_of(parsed),
            connect_host: strip_brackets(host).to_string(),
            port,
            origin_form,
        }
    }
}

/// IPv6 字面量在 URL 里是 `[::1]`，而 socket/DNS/SNI 只接受 `::1`
fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// 发往上游的请求头（已过滤逐跳头、改写 `Connection`）及请求体分帧信息
pub(crate) struct UpstreamHead {
    /// 请求行 + 过滤后的头部 + 结尾空行，可直接 `write_all`
    pub(crate) bytes: String,
    /// 请求体长度（`None` 表示没有 `Content-Length`）
    pub(crate) content_length: Option<u64>,
    /// 请求体是否为 chunked 分帧
    pub(crate) chunked: bool,
    /// 客户端是否声明了 `Expect: 100-continue`（该头不转发上游，由代理直接应答）
    pub(crate) expect_continue: bool,
}

impl UpstreamHead {
    /// 构造上游请求头（不剔除额外的认证头）
    pub(crate) fn build(target: &ForwardTarget<'_>, head_str: &str) -> Option<Self> {
        Self::build_filtered(target, head_str, None)
    }

    /// 构造上游请求头，并额外剔除 `drop_header` 指定的一次性认证头
    ///
    /// `drop_header` 是路径前缀模式用于本代理认证的请求头名（`Authorization` /
    /// `Proxy-Authorization`）；认证成功后必须从上游请求中移除，避免凭据泄漏给目标站点。
    ///
    /// 过滤规则：
    /// - `Host` → 按目标 URL 的 authority 重写 / 补写（RFC 7230 §5.4：收到 absolute-form
    ///   请求时，代理必须忽略客户端的 `Host` 并改用请求目标的 host）。客户端漏发 `Host`
    ///   时同样补上，否则 HTTP/1.1 上游会直接回 400
    /// - `Connection` → 改写成一条 `close`，放在它首次出现的位置（本代理每个请求独占
    ///   一条上游连接）；客户端完全没发 `Connection` 时不凭空追加，保持历史行为
    /// - `Proxy-Connection` / `Proxy-Authorization` / `Keep-Alive` / `TE` / `Trailer` /
    ///   `Upgrade` 等逐跳头 → 丢弃（[`is_hop_by_hop`]，RFC 7230 §6.1）
    /// - `Expect: 100-continue` → 丢弃并置位，由代理直接回 `100 Continue`
    ///   （转发该头会让客户端等上游的临时响应，而代理此刻正在收 body，白等一个 RTT）
    /// - `Transfer-Encoding` → **整行原样保留**（body 按原始分帧转发；把
    ///   `gzip, chunked` 折叠成只有 `chunked` 会让上游把仍是 gzip 的块数据当明文）
    /// - `Content-Length` → **延迟到循环后统一输出**，因为它与 `Transfer-Encoding`
    ///   互斥，必须等看清全部头才能决定写不写（见函数末尾）
    ///
    /// 头名按冒号精确切分匹配（用 `contains` 匹配子串会误伤 `X-Forwarded-For`
    /// 这类合法头）。无冒号的行（含折行续行）**丢弃**：这类字节无法归属到任何已知
    /// 头，原样转发可能被上游当作折行或第二个请求行，等同于把未经校验的字节塞进头部；
    /// 直接 400 又会改变既有客户端行为，而丢弃既不影响已识别头与分帧，也不会放大攻击面。
    ///
    /// 返回 `None` 的两种情况（调用方应回 400）：
    /// - `Content-Length` 值不是十进制数字；
    /// - 出现多个**不一致**的 `Content-Length`。
    ///
    /// 这两种情况下代理与上游对 body 边界必然有不同的理解，转发等于制造走私面。
    pub(crate) fn build_filtered(
        target: &ForwardTarget<'_>,
        head_str: &str,
        drop_header: Option<&str>,
    ) -> Option<Self> {
        let mut bytes = String::with_capacity(head_str.len() + 64);
        bytes.push_str(target.method);
        bytes.push(' ');
        bytes.push_str(&target.origin_form);
        bytes.push_str(" HTTP/1.1\r\n");
        bytes.push_str("Host: ");
        bytes.push_str(&target.authority);
        bytes.push_str("\r\n");

        // `Connection: X-Foo` 点名的字段同样是逐跳头（RFC 7230 §6.1），
        // 必须在遍历前先收集，否则名字在头尾不同位置时过滤结果会不稳定
        let connection_named = connection_named_headers(head_str);

        let mut content_length: Option<u64> = None;
        let mut content_length_conflict = false;
        let mut chunked = false;
        let mut expect_continue = false;
        let mut connection_written = false;

        for line in head_str.lines().skip(1) {
            if line.is_empty() {
                break;
            }
            let (name, value) = match line.split_once(':') {
                Some(pair) => pair,
                // 无冒号的非法行（含折行续行）无法归属到任何头，直接丢弃
                None => continue,
            };
            let name = name.trim();
            let value = value.trim();

            if name.eq_ignore_ascii_case("host") {
                // 已按目标 URL 的 authority 输出，客户端的 Host 一律忽略
                continue;
            }
            if name.eq_ignore_ascii_case("connection") {
                if !connection_written {
                    bytes.push_str("Connection: close\r\n");
                    connection_written = true;
                }
                continue;
            }
            // 分帧相关头先处理：它们需要"改写 / 记录"而不是"丢弃"
            if name.eq_ignore_ascii_case("transfer-encoding") {
                // 只按逗号分隔的 token 判定 chunked；整行仍原样转发
                chunked = value
                    .split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("chunked"));
                bytes.push_str(line);
                bytes.push_str("\r\n");
                continue;
            }
            if name.eq_ignore_ascii_case("content-length") {
                // 延迟输出：chunked 与 CL 互斥，此刻还不知道后面有没有 TE
                match value.parse::<u64>() {
                    Ok(v) => match content_length {
                        Some(prev) if prev != v => content_length_conflict = true,
                        Some(_) => {} // 重复且一致：合并成一条，不给上游留多值歧义
                        None => content_length = Some(v),
                    },
                    Err(_) => content_length_conflict = true,
                }
                continue;
            }
            // `100-continue` 由代理直接应答；其余 `Expect` 值同样丢弃（无从满足）
            if name.eq_ignore_ascii_case("expect") {
                expect_continue = value.eq_ignore_ascii_case("100-continue");
                continue;
            }
            if is_hop_by_hop(name, &connection_named) {
                continue;
            }
            if drop_header.is_some_and(|h| name.eq_ignore_ascii_case(h)) {
                continue;
            }
            bytes.push_str(line);
            bytes.push_str("\r\n");
        }

        // 代理与上游对 body 边界的理解必须完全一致，否则就是走私面
        if content_length_conflict {
            return None;
        }

        // 分帧头二选一（RFC 7230 §3.3.3）：存在 chunked 时**必须**丢弃 Content-Length。
        // 两者同时转发时，若上游按 CL 解析，会把分帧字节当成 body 内容，
        // 后续管道化的请求就被拼进同一个请求（请求走私）。
        if chunked {
            content_length = None;
        } else if let Some(cl) = content_length {
            bytes.push_str("Content-Length: ");
            bytes.push_str(&cl.to_string());
            bytes.push_str("\r\n");
        }
        bytes.push_str("\r\n");

        Some(Self {
            bytes,
            content_length,
            chunked,
            expect_continue,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }

    #[test]
    fn test_forward_target_splits_ipv6_authority_and_connect_host() {
        let head = "GET http://[::1]:8080/p HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
        let t = ForwardTarget::parse(head, addr()).unwrap();
        assert_eq!(t.authority, "[::1]:8080", "Host 头必须保留方括号");
        assert_eq!(t.connect_host, "::1", "socket/DNS 层必须去掉方括号");
        assert_eq!(t.port, 8080);
    }

    #[test]
    fn test_upstream_head_drops_lines_without_colon() {
        // 无冒号的行既可能是畸形头，也可能是折行注入；两条链路统一丢弃
        let head = "GET http://example.com/x HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    broken-line\r\n\
                    X-Keep: ok\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert!(
            !up.bytes.contains("broken-line"),
            "无冒号行不得转发：{}",
            up.bytes
        );
        assert!(up.bytes.contains("X-Keep: ok\r\n"), "合法头必须保留");
    }

    #[test]
    fn test_upstream_head_preserves_multi_coding_transfer_encoding() {
        let head = "POST http://h/p HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert!(up.chunked, "chunked token 必须被识别");
        assert_eq!(up.content_length, None);
        assert!(
            up.bytes.contains("Transfer-Encoding: gzip, chunked\r\n"),
            "整行编码声明必须原样保留：{}",
            up.bytes
        );
        assert!(!up.bytes.contains("Content-Length"), "TE 与 CL 不得同时转发");
    }

    #[test]
    fn test_upstream_head_drop_header_removes_credentials() {
        let head = "GET http://h/p HTTP/1.1\r\nAuthorization: Bearer secret\r\nX-Keep: ok\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build_filtered(&target, head, Some("Authorization")).unwrap();
        assert!(!up.bytes.contains("secret"), "认证头不得上游化：{}", up.bytes);
        assert!(up.bytes.contains("X-Keep: ok\r\n"));
    }

    // ─── host:port 解析 / chunked 分帧 ───
    // 这两组原语的实现与测试已迁至 `crate::support::net` 与 `crate::protocol::http_body`（消除模块循环依赖）。

    // ─── 转发目标解析（B3 拆分后的纯函数） ───

    #[test]
    fn test_forward_target_parses_absolute_url() {
        let head = "GET http://example.com/a/b?x=1 HTTP/1.1
Host: example.com

";
        let t = ForwardTarget::parse(head, addr()).expect("absolute URL must parse");
        assert_eq!(t.method, "GET");
        assert_eq!(t.connect_host, "example.com");
        assert_eq!(t.port, 80, "缺省端口应为 80");
        assert_eq!(t.origin_form, "/a/b?x=1", "query 必须保留");
        assert_eq!(t.authority, "example.com", "缺省端口不应写进 Host");
    }

    #[test]
    fn test_forward_target_keeps_explicit_port() {
        let head = "POST http://127.0.0.1:8080/p HTTP/1.1

";
        let t = ForwardTarget::parse(head, addr()).expect("parse");
        assert_eq!(t.port, 8080);
        assert_eq!(t.connect_host, "127.0.0.1");
        assert_eq!(t.origin_form, "/p");
    }

    #[test]
    fn test_forward_target_marks_https_scheme_with_known_default_port() {
        // URL 解析层仍按 scheme 求默认端口（https → 443），但经典代理入口据 `scheme`
        // 拒绝 https absolute-form（见 `handle_http_request_generic` 与
        // `https_absolute_form_is_rejected_with_400`）
        let head = "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let t = ForwardTarget::parse(head, addr()).expect("https absolute URL must parse");
        assert_eq!(t.scheme, "https");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn test_forward_target_rejects_non_absolute_target() {
        // 相对 URL（非代理请求）与残缺请求行都必须返回 None，由上层走 404 反扫描
        assert!(ForwardTarget::parse("GET / HTTP/1.1\r\n\r\n", addr()).is_none());
        assert!(ForwardTarget::parse("GARBAGE\r\n\r\n", addr()).is_none());
        assert!(ForwardTarget::parse("", addr()).is_none());
    }

    // ─── 上游请求头构造（含逐跳头与凭据过滤） ───

    #[test]
    fn test_upstream_head_rewrites_connection_and_drops_proxy_headers() {
        let head = "GET http://example.com/x HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Proxy-Connection: keep-alive\r\n\
                    Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\
                    Connection: keep-alive\r\n\
                    User-Agent: test\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();

        assert!(up.bytes.starts_with("GET /x HTTP/1.1\r\n"), "请求行应改写为 origin-form");
        assert_eq!(
            up.bytes.matches("Host: ").count(),
            1,
            "客户端 Host 必须被替换而不是重复输出：{}",
            up.bytes
        );
        assert!(up.bytes.contains("Host: example.com\r\n"), "Host 由绝对 URL 决定");
        assert!(up.bytes.contains("Connection: close\r\n"), "Connection 必须改写为 close");
        assert!(!up.bytes.to_ascii_lowercase().contains("proxy-authorization"), "凭据不得上游化");
        assert!(!up.bytes.to_ascii_lowercase().contains("proxy-connection"), "代理专用头应丢弃");
        assert!(up.bytes.contains("User-Agent: test\r\n"), "普通头必须保留");
        assert!(up.bytes.ends_with("\r\n\r\n"), "头部必须以空行结束");
        assert!(!up.chunked);
        assert_eq!(up.content_length, None);
    }

    // ─── Host 头（RFC 7230 §5.4：absolute-form 必须以请求目标的 host 为准） ───

    #[test]
    fn test_upstream_head_rewrites_host_from_absolute_url() {
        // 客户端 Host 与 URL 不一致（如把代理地址写进 Host）：一律以 URL 为准
        let head = "GET http://example.com:8080/p HTTP/1.1\r\nHost: 10.0.0.1:3128\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();

        assert!(up.bytes.contains("Host: example.com:8080\r\n"), "显式端口必须保留");
        assert!(!up.bytes.contains("10.0.0.1"), "客户端的 Host 不得转发：{}", up.bytes);
    }

    #[test]
    fn test_upstream_head_inserts_host_when_client_omits_it() {
        // HTTP/1.1 上游要求 Host；客户端漏发时由代理补写，否则上游直接 400
        let head = "GET http://example.com/p HTTP/1.1\r\nAccept: */*\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();

        assert!(up.bytes.contains("Host: example.com\r\n"), "缺失 Host 必须补写");
        assert!(up.bytes.contains("Accept: */*\r\n"));
    }

    #[test]
    fn test_upstream_head_host_brackets_ipv6() {
        let head = "GET http://[::1]:8080/p HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert!(up.bytes.contains("Host: [::1]:8080\r\n"), "IPv6 authority 必须带方括号");
    }

    /// `Connection` 里点名的自定义字段同样是逐跳头（RFC 7230 §6.1）
    #[test]
    fn test_upstream_head_drops_connection_named_headers() {
        let head = "GET http://example.com/x HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Connection: close, X-Hop\r\n\
                    X-Hop: secret\r\n\
                    X-Keep: ok\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();

        let lower = up.bytes.to_ascii_lowercase();
        assert!(
            !lower.contains("x-hop"),
            "Connection 点名的头必须丢弃：{}",
            up.bytes
        );
        assert!(up.bytes.contains("X-Keep: ok\r\n"), "未点名的端到端头必须保留");
        assert_eq!(
            lower.matches("connection:").count(),
            1,
            "只保留代理改写的 Connection: close"
        );
    }

    #[test]
    fn test_upstream_head_records_framing() {
        // Content-Length
        let head = "POST http://h/p HTTP/1.1\r\nContent-Length: 12\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert_eq!(up.content_length, Some(12));
        assert!(!up.chunked);

        // Transfer-Encoding: chunked（保留原头，同时置位）
        let head = "POST http://h/p HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert!(up.chunked);
        assert_eq!(up.content_length, None);
        assert!(up.bytes.contains("Transfer-Encoding: chunked"));
    }

    #[test]
    fn test_upstream_head_does_not_match_header_substrings() {
        // 头名必须精确匹配：X-Forwarded-For 不能被当作 connection 类头处理
        let head = "GET http://h/p HTTP/1.1\r\nX-Connection-Info: keep\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert!(up.bytes.contains("X-Connection-Info: keep\r\n"));
        assert!(!up.bytes.contains("Connection: close"), "不含 Connection 头时不应凭空追加");
    }

    #[test]
    fn test_upstream_head_drops_expect_and_flags_100_continue() {
        // `Expect: 100-continue` 不能转发给上游：上游会先回 100，而代理此刻正在收
        // body，客户端收不到临时响应就会白等一个 RTT（curl 默认等 1s）。
        let head = "POST http://h/p HTTP/1.1\r\n\
                    Content-Length: 4\r\n\
                    Expect: 100-continue\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert!(up.expect_continue, "必须置位，供调用方回 100 Continue");
        assert!(
            !up.bytes.to_ascii_lowercase().contains("expect:"),
            "Expect 头不得出现在上游请求中"
        );
        assert_eq!(up.content_length, Some(4));
    }

    #[test]
    fn test_upstream_head_does_not_flag_expect_without_continue() {
        // 其它 Expect 值无从满足，同样丢弃，但不应误触发 100 Continue
        let head = "POST http://h/p HTTP/1.1\r\nExpect: 42-continue\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        assert!(!up.expect_continue);
        assert!(!up.bytes.to_ascii_lowercase().contains("expect:"));
    }

    #[test]
    fn test_upstream_head_drops_content_length_when_chunked() {
        // RFC 7230 §3.3.3：存在 Transfer-Encoding 时 Content-Length **必须**丢弃。
        // 两者一起转发时，若上游按 CL 解析，分帧字节会被当成 body 内容，
        // 后续管道化的请求就被拼进同一个请求——请求走私。
        let head = "POST http://h/p HTTP/1.1\r\n\
                    Host: h\r\n\
                    Content-Length: 5\r\n\
                    Transfer-Encoding: chunked\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();

        assert!(up.chunked);
        assert_eq!(up.content_length, None, "chunked 时 CL 必须清零");
        let lower = up.bytes.to_ascii_lowercase();
        assert!(
            lower.contains("transfer-encoding: chunked"),
            "分帧头必须保留：{}",
            up.bytes
        );
        assert!(
            !lower.contains("content-length"),
            "CL 不得与 TE 一起转发：{}",
            up.bytes
        );
    }

    #[test]
    fn test_upstream_head_rejects_conflicting_content_length() {
        // 多个不一致的 CL：代理与上游对 body 边界的理解必然不同 → 拒绝而不是挑一个
        let head = "POST http://h/p HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        assert!(UpstreamHead::build(&target, head).is_none());
    }

    #[test]
    fn test_upstream_head_rejects_non_numeric_content_length() {
        let head = "POST http://h/p HTTP/1.1\r\nContent-Length: 5x\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        assert!(UpstreamHead::build(&target, head).is_none());
    }

    #[test]
    fn test_upstream_head_collapses_duplicate_content_length() {
        // 重复但一致：合并成一条，不给上游留多值歧义
        let head = "POST http://h/p HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();

        assert_eq!(up.content_length, Some(5));
        let count = up
            .bytes
            .to_ascii_lowercase()
            .matches("content-length:")
            .count();
        assert_eq!(count, 1, "重复 CL 必须合并：{}", up.bytes);
    }

    #[test]
    fn test_upstream_head_drops_all_hop_by_hop_headers() {
        // RFC 7230 §6.1 的逐跳头一律不得转发；普通头必须保留
        let head = "GET http://h/p HTTP/1.1\r\n\
                    Keep-Alive: timeout=5\r\n\
                    TE: trailers\r\n\
                    Trailer: X-Sum\r\n\
                    Upgrade: websocket\r\n\
                    Proxy-Authenticate: Basic\r\n\
                    Accept: */*\r\n\r\n";
        let target = ForwardTarget::parse(head, addr()).unwrap();
        let up = UpstreamHead::build(&target, head).unwrap();
        let lower = up.bytes.to_ascii_lowercase();
        for hop in ["keep-alive:", "te:", "trailer:", "upgrade:", "proxy-authenticate:"] {
            assert!(!lower.contains(hop), "逐跳头 {hop} 不应转发: {}", up.bytes);
        }
        assert!(up.bytes.contains("Accept: */*\r\n"), "端到端头必须保留");
    }
}
