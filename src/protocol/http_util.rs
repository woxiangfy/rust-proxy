//! HTTP 报文解析与改写原语
//!
//! 这里只放"与业务无关"的纯函数：头部结束位置查找、逐跳头判定、authority 构造。
//! 它们同时被经典代理（[`crate::protocol::proxy`]）与路径前缀直连（[`crate::protocol::path_proxy`]）
//! 使用。历史上这些函数在两处各写一份（`MAX_HEADER_BYTES` / `MAX_HEAD_BYTES`
//! 名字不同但值相同），改动时容易只改一边，因此统一收敛到此叶模块。
//!
//! 依赖方向：`proxy → http_util`、`path_proxy → http_util`，本模块不依赖任何业务模块。

/// 请求头 / 响应头最大字节数：超过即视为畸形或恶意（防御超大头攻击）
///
/// 64KB 足够容纳任何正常浏览器的请求头（含超长 Cookie），同时限制单连接内存占用。
pub(crate) const MAX_HEAD_BYTES: usize = 64 * 1024;

/// 查找头部结束位置（首个 `\r\n\r\n` 之后的偏移），未找到返回 `None`
///
/// 返回的是 **body 起始偏移**（已越过空行），因此可直接用作切片边界：
/// `&data[..p]` 为头部，`&data[p..]` 为 body 前缀。
pub(crate) fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

/// 头部结束位置；未找到结束符（头不完整 / 超限被截断）时退化为 `data.len()`，
/// 即把全部已读字节视作头部。
pub(crate) fn head_end_offset(data: &[u8]) -> usize {
    find_header_end(data).unwrap_or(data.len())
}

/// 逐跳头（RFC 7230 §6.1）与仅对代理有意义的头：不得转发给上游。
///
/// 两个头**故意不在此列**，因为它们需要"改写"而非"丢弃"，由调用方单独处理：
/// - `transfer-encoding`：body 需按原始分帧转发，且与 `content-length` 互斥；
/// - `connection`：代理统一改写为 `Connection: close`，直接丢弃会丢失该语义。
///
/// `connection_named` 是 [`connection_named_headers`] 的解析结果：RFC 7230 §6.1 要求
/// 代理同时丢弃 `Connection: X-Foo` 里点名的字段，仅靠固定名单会漏掉自定义逐跳头。
pub(crate) fn is_hop_by_hop(name: &str, connection_named: &[String]) -> bool {
    const NAMES: [&str; 8] = [
        "keep-alive",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "upgrade",
        "expect",
    ];
    NAMES.iter().any(|n| name.eq_ignore_ascii_case(n))
        || connection_named.iter().any(|n| name.eq_ignore_ascii_case(n))
}

/// 解析 `Connection` 头里点名的逐跳字段（小写、去重）
///
/// 支持多个 `Connection` 头与逗号分隔列表。以下字段被**刻意忽略**，因为它们由
/// 调用方单独处理、不能因 token 而丢弃：
/// - `connection`：本身要改写成 `Connection: close`；
/// - `content-length` / `transfer-encoding`：分帧头，丢一条就会让代理与上游的
///   body 边界不一致（请求走私面），必须保留原生处理逻辑；
/// - `host`：由代理按绝对 URL 重写 / 补写。
pub(crate) fn connection_named_headers(head_str: &str) -> Vec<String> {
    const PROTECTED: [&str; 4] = ["connection", "content-length", "transfer-encoding", "host"];

    let mut names: Vec<String> = Vec::new();
    for line in head_str.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("connection") {
            continue;
        }
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() || PROTECTED.iter().any(|p| token.eq_ignore_ascii_case(p)) {
                continue;
            }
            let lower = token.to_ascii_lowercase();
            if !names.contains(&lower) {
                names.push(lower);
            }
        }
    }
    names
}

/// 上游 authority（Host 头值）：域名/裸 IP 直接拼端口，IPv6 需补方括号。
///
/// `url` crate 对 IPv6 字面量已返回带方括号的 host（`[::1]`），需避免重复包裹。
pub(crate) fn authority_of(u: &url::Url) -> String {
    let host = u.host_str().unwrap_or_default();
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };
    match u.port() {
        Some(p) => format!("{}:{}", host, p),
        None => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_header_end_returns_body_offset() {
        // 返回值是 body 起始偏移（越过 \r\n\r\n），不是空行起点
        assert_eq!(
            find_header_end(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nBODY"),
            Some(27),
            "offset must point past the blank line"
        );
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\nHost: a\r\n"), None);
        assert_eq!(find_header_end(b""), None);
    }

    #[test]
    fn test_find_header_end_picks_first_occurrence() {
        // 只认首个结束符：后续字节（可能是 body 内的二进制）不参与判断
        let data = b"A\r\n\r\nB\r\n\r\n";
        assert_eq!(find_header_end(data), Some(5));
    }

    #[test]
    fn test_head_end_offset_falls_back_to_len() {
        // 头不完整时把已读字节全当头部，避免 body 切片越界
        assert_eq!(head_end_offset(b"GET / HT"), 8);
        assert_eq!(head_end_offset(b"GET / HTTP/1.1\r\n\r\nX"), 18);
    }

    #[test]
    fn test_is_hop_by_hop_matches_case_insensitively() {
        // 头名大小写不敏感（HTTP/1.1 客户端可任意大小写）
        assert!(is_hop_by_hop("Keep-Alive", &[]));
        assert!(is_hop_by_hop("keep-alive", &[]));
        assert!(is_hop_by_hop("Proxy-Connection", &[]));
        assert!(is_hop_by_hop("Proxy-Authorization", &[]));
        assert!(is_hop_by_hop("UPGRADE", &[]));
        assert!(is_hop_by_hop("expect", &[]));
    }

    #[test]
    fn test_is_hop_by_hop_leaves_rewrite_headers_to_caller() {
        // connection / transfer-encoding 需改写而非丢弃，必须不被黑名单命中，
        // 否则调用方的 rewrite 分支永远不会执行（这是曾经踩过的坑）
        assert!(!is_hop_by_hop("connection", &[]));
        assert!(!is_hop_by_hop("transfer-encoding", &[]));
    }

    #[test]
    fn test_is_hop_by_hop_allows_end_to_end_headers() {
        // 端到端头必须保留，尤其 transfer-encoding / content-length 由分帧逻辑单独处理
        assert!(!is_hop_by_hop("host", &[]));
        assert!(!is_hop_by_hop("content-type", &[]));
        assert!(!is_hop_by_hop("transfer-encoding", &[]));
        assert!(!is_hop_by_hop("content-length", &[]));
        assert!(!is_hop_by_hop("authorization", &[]));
    }

    #[test]
    fn test_connection_named_headers_parses_multiple_values() {
        // RFC 7230 §6.1：Connection 里点名的字段也是逐跳头；多个头 + 逗号列表都要覆盖
        let head = "GET / HTTP/1.1\r\n\
                    Connection: keep-alive, X-Foo\r\n\
                    Connection: x-bar , Keep-Alive\r\n\
                    Host: a\r\n\r\n";
        let names = connection_named_headers(head);
        assert_eq!(
            names,
            vec!["keep-alive".to_string(), "x-foo".to_string(), "x-bar".to_string()],
            "应按出现顺序小写去重：{:?}",
            names
        );
        assert!(is_hop_by_hop("X-Foo", &names));
        assert!(is_hop_by_hop("x-bar", &names));
        assert!(!is_hop_by_hop("X-Other", &names));
    }

    #[test]
    fn test_connection_named_headers_ignores_protected_fields() {
        // 分帧头与 Host 不能因 Connection 点名而被丢弃：否则 body 边界会不一致
        // （请求走私面），Host 也会失去重写结果
        let head = "GET / HTTP/1.1\r\n\
                    Connection: close, Content-Length, Transfer-Encoding, Host\r\n\r\n";
        let names = connection_named_headers(head);
        assert_eq!(names, vec!["close".to_string()]);
    }

    #[test]
    fn test_connection_named_headers_ignores_non_connection_headers() {
        // 只解析 Connection 行，其他头里的同名 token 不能被误当成逐跳字段
        let head = "GET / HTTP/1.1\r\nX-Trace: Connection: X-Foo\r\n\r\n";
        assert!(connection_named_headers(head).is_empty());
    }

    #[test]
    fn test_authority_of_adds_port_and_brackets_ipv6() {
        let a = url::Url::parse("http://example.com/").unwrap();
        assert_eq!(authority_of(&a), "example.com");
        let b = url::Url::parse("http://example.com:8080/").unwrap();
        assert_eq!(authority_of(&b), "example.com:8080");
        let c = url::Url::parse("http://[::1]:8080/").unwrap();
        assert_eq!(authority_of(&c), "[::1]:8080");
    }
}
