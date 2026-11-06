//! 代理认证：HTTP Basic 凭据校验与 407 / 401 质询响应
//!
//! 两种模式共用同一套凭据校验，但质询方式不同：
//! - 经典代理（客户端显式配置了代理）→ `407` + `Proxy-Authenticate`
//! - 路径前缀直连（直接访问网址）→ `401` + `WWW-Authenticate`，浏览器才会弹登录框
//!
//! 凭据比较是等时的（[`constant_time_eq`]），避免通过响应时间推测用户名/密码前缀。

use crate::config::AuthUser;
use crate::protocol::http_response::write_response;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use tokio::io::AsyncWrite;

/// 校验请求中的 `Proxy-Authorization` 头是否符合配置的用户列表。
///
/// 实现标准 HTTP Basic 认证（RFC 7617）：从请求头中提取
/// `Proxy-Authorization: Basic <base64(user:pass)>`，解码后与 `users` 比对。
/// 头缺失、方案不符、Base64 解码失败或凭据不匹配均返回 `false`。
pub(crate) fn check_proxy_auth(request_data: &str, users: &[AuthUser]) -> bool {
    match extract_basic_credentials(request_data, "proxy-authorization") {
        Some(creds) => verify_basic_credentials(creds, users),
        None => false,
    }
}

/// 路径前缀直连模式下用于认证的请求头来源。
///
/// 认证成功后需要把该头从转发给上游的请求中剔除，否则代理凭据会泄漏给目标站点。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathAuthSource {
    /// `Authorization`：浏览器/普通客户端收到 401 质询后发送
    Authorization,
    /// `Proxy-Authorization`：脚本或 curl 以代理方式携带凭据
    ProxyAuthorization,
}

impl PathAuthSource {
    /// 该来源对应的请求头名（小写）
    pub(crate) fn header_name(self) -> &'static str {
        match self {
            PathAuthSource::Authorization => "authorization",
            PathAuthSource::ProxyAuthorization => "proxy-authorization",
        }
    }
}

/// 校验路径前缀直连模式的认证凭据。
///
/// 该模式是「直接访问网址」而非「配置代理」，因此优先读取 `Authorization`
/// （浏览器/普通 HTTP 客户端在收到 401 质询后发送），同时也接受
/// `Proxy-Authorization`，便于用脚本或 curl 以代理方式携带凭据。
///
/// 返回实际认证成功的头来源（`None` 表示认证失败），调用方据此把该头从
/// 上游请求中移除——只移除"真正被用来认证"的那一个，另一个可留给目标站点使用。
pub(crate) fn check_path_auth(
    request_data: &str,
    users: &[AuthUser],
) -> Option<PathAuthSource> {
    for source in [
        PathAuthSource::Authorization,
        PathAuthSource::ProxyAuthorization,
    ] {
        if let Some(creds) = extract_basic_credentials(request_data, source.header_name()) {
            if verify_basic_credentials(creds, users) {
                return Some(source);
            }
        }
    }
    None
}

/// 校验 `Basic` 凭据（base64 的 `user:pass`）是否命中用户列表
fn verify_basic_credentials(credentials: &str, users: &[AuthUser]) -> bool {
    // Base64 解码凭据
    let decoded = match BASE64_STANDARD.decode(credentials.trim()) {
        Ok(d) => d,
        Err(_) => return false,
    };

    // 解码结果应为 "username:password"（按第一个冒号拆分，密码中允许包含冒号）
    let decoded_str = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let (username, password) = match decoded_str.split_once(':') {
        Some((u, p)) => (u, p),
        None => return false,
    };

    // 用非短路的 `&` 逐个候选比对：`&&` 会在用户名不匹配时跳过密码比较，
    // 攻击者可借响应时间推断"用户名是否存在"。两个字段都用等时比较。
    users.iter().any(|u| {
        constant_time_eq(u.username.as_bytes(), username.as_bytes())
            & constant_time_eq(u.password.as_bytes(), password.as_bytes())
    })
}

/// 凭据的等时比较
///
/// 直接 `==` 会在第一个不同字节处提前返回，逐字节耗时差可被用于推测密码前缀。
/// 这里固定遍历全部字节再判零；长度差异无法隐藏（直接判否），但"长度一致时逐位比较"
/// 已能消除前缀推断这条路。
///
/// `black_box` 用于阻止编译器把循环重新优化成 `memcmp` 之类的提前退出实现。
fn constant_time_eq(expected: &[u8], provided: &[u8]) -> bool {
    if expected.len() != provided.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(provided.iter()) {
        diff |= a ^ b;
        std::hint::black_box(diff);
    }
    diff == 0
}

/// 从原始请求数据中提取 `<header>: Basic <credentials>` 的凭据部分。
///
/// 头名匹配不区分大小写，仅识别 Basic 方案；遇到空行（请求头结束）即停止搜索。
/// 不含冒号的行（如绝对形式的请求行）会被跳过而非导致整体失败。
fn extract_basic_credentials<'a>(request_data: &'a str, header_name: &str) -> Option<&'a str> {
    for line in request_data.lines() {
        if line.is_empty() {
            // 空行标志请求头结束
            break;
        }
        let (name, value) = match line.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        if !name.trim().eq_ignore_ascii_case(header_name) {
            continue;
        }
        let value = value.trim();
        // 格式: "Basic <base64>"
        let (scheme, creds) = match value.split_once(char::is_whitespace) {
            Some(pair) => pair,
            None => continue,
        };
        if scheme.eq_ignore_ascii_case("basic") {
            return Some(creds);
        }
    }
    None
}

/// 向客户端发送 407 Proxy Authentication Required 响应，要求 Basic 认证。
///
/// 泛型版本兼容 TCP 和 TLS 流。
pub(crate) async fn send_auth_required<W: AsyncWrite + Unpin>(client: &mut W) {
    // Connection: close 使客户端重连时携带认证头重试
    write_response(
        client,
        "407 Proxy Authentication Required",
        &[("Proxy-Authenticate", "Basic realm=\"rust-proxy\"")],
        b"",
    )
    .await;
}

/// 向客户端发送 401 Unauthorized 质询（路径前缀直连模式使用）。
///
/// 该模式下客户端并未「配置代理」，407 + `Proxy-Authenticate` 不会被浏览器处理
/// （只会渲染 407 错误页且不弹登录框）；因此改用 401 + `WWW-Authenticate`，
/// 浏览器会正常弹出 Basic 登录框。
pub(crate) async fn send_path_auth_required<W: AsyncWrite + Unpin>(client: &mut W) {
    write_response(
        client,
        "401 Unauthorized",
        &[("WWW-Authenticate", "Basic realm=\"rust-proxy\"")],
        b"",
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_users() -> Vec<AuthUser> {
        vec![AuthUser {
            username: "admin".into(),
            password: "secret".into(),
        }]
    }

    #[test]
    fn test_auth_valid_basic() {
        // "admin:secret" -> base64 "YWRtaW46c2VjcmV0"
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n\
            Host: example.com\r\n\r\n";
        assert!(check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_missing_header_rejected() {
        let req = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_wrong_password_rejected() {
        // "admin:wrong" -> base64 "YWRtaW46d3Jvbmc="
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic YWRtaW46d3Jvbmc=\r\n\
            Host: example.com\r\n\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_wrong_username_rejected() {
        // "root:secret" -> base64 "cm9vdDpzZWNyZXQ="
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic cm9vdDpzZWNyZXQ=\r\n\
            Host: example.com\r\n\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_non_basic_scheme_rejected() {
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Digest abc123\r\n\
            Host: example.com\r\n\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_invalid_base64_rejected() {
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic !!!not-base64!!!\r\n\
            Host: example.com\r\n\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_rejects_malformed_credentials() {
        // 风险：畸形 Basic 凭据必须失败关闭，且解析过程不能 panic。
        // (a) base64 合法但解码后没有 "user:pass" 分隔符
        let no_colon = BASE64_STANDARD.encode("alicesecret");
        let req = format!(
            "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic {}\r\n\r\n",
            no_colon
        );
        assert!(!check_proxy_auth(&req, &make_users()));

        // (b) base64 合法但解码结果不是 UTF-8
        let non_utf8 = BASE64_STANDARD.encode([0xff, 0xfe, b':', b'x']);
        let req = format!(
            "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic {}\r\n\r\n",
            non_utf8
        );
        assert!(!check_proxy_auth(&req, &make_users()));

        // (c) 只有方案、没有凭据（含尾随空格）
        assert!(!check_proxy_auth(
            "GET http://example.com/ HTTP/1.1\r\nProxy-Authorization: Basic\r\n\r\n",
            &make_users()
        ));
        assert!(!check_proxy_auth(
            "GET http://example.com/ HTTP/1.1\r\nProxy-Authorization: Basic \r\n\r\n",
            &make_users()
        ));
    }

    #[test]
    fn test_auth_header_name_case_insensitive() {
        // 头名小写、方案小写
        let req = "CONNECT example.com:443 HTTP/1.1\r\n\
            proxy-authorization: basic YWRtaW46c2VjcmV0\r\n\
            Host: example.com\r\n\r\n";
        assert!(check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_scheme_case_insensitive() {
        // 方案大写也应识别
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: BASIC YWRtaW46c2VjcmV0\r\n\
            Host: example.com\r\n\r\n";
        assert!(check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_auth_multiple_users_match_any() {
        let users = vec![
            AuthUser {
                username: "admin".into(),
                password: "secret".into(),
            },
            AuthUser {
                username: "guest".into(),
                password: "guest".into(),
            },
        ];
        // "guest:guest" -> base64 "Z3Vlc3Q6Z3Vlc3Q="
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=\r\n\
            Host: example.com\r\n\r\n";
        assert!(check_proxy_auth(req, &users));
    }

    #[test]
    fn test_auth_password_with_colon_supported() {
        // 密码 "p:a:s:s" 按第一个冒号拆分，密码部分为 "a:s:s"
        let users = vec![AuthUser {
            username: "u".into(),
            password: "a:s:s".into(),
        }];
        // "u:a:s:s" -> base64
        let creds = BASE64_STANDARD.encode("u:a:s:s");
        let req = format!(
            "GET http://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic {}\r\n\
            Host: example.com\r\n\r\n",
            creds
        );
        assert!(check_proxy_auth(&req, &users));
    }

    #[test]
    fn test_auth_stops_at_empty_line() {
        // 头部以空行结束，之后的 Proxy-Authorization 不应被采纳
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Host: example.com\r\n\r\n\
            Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    #[test]
    fn test_extract_authorization_from_connect() {
        let req = "CONNECT example.com:443 HTTP/1.1\r\n\
            Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n\
            Host: example.com:443\r\n\r\n";
        assert_eq!(
            extract_basic_credentials(req, "proxy-authorization"),
            Some("YWRtaW46c2VjcmV0")
        );
    }

    #[test]
    fn test_extract_authorization_none_when_absent() {
        let req = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_basic_credentials(req, "proxy-authorization"), None);
    }

    // ─── 路径前缀直连模式的认证 ───

    #[test]
    fn test_path_auth_accepts_authorization_header() {
        // 浏览器/直连客户端走标准 Authorization 头
        let req = "GET /px/https://example.com/ HTTP/1.1\r\n\
            Authorization: Basic YWRtaW46c2VjcmV0\r\n\
            Host: proxy.local\r\n\r\n";
        // 返回来源头名，供上层转发时剔除（避免凭据泄漏给目标站点）
        assert_eq!(
            check_path_auth(req, &make_users()),
            Some(PathAuthSource::Authorization)
        );
    }

    #[test]
    fn test_path_auth_accepts_proxy_authorization_header() {
        // 脚本/curl 也可能携带 Proxy-Authorization
        let req = "GET /px/https://example.com/ HTTP/1.1\r\n\
            Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n\r\n";
        assert_eq!(
            check_path_auth(req, &make_users()),
            Some(PathAuthSource::ProxyAuthorization)
        );
    }

    #[test]
    fn test_path_auth_rejects_missing_or_wrong_credentials() {
        assert!(check_path_auth(
            "GET /px/https://example.com/ HTTP/1.1\r\nHost: p\r\n\r\n",
            &make_users()
        )
        .is_none());
        // "admin:wrong"
        assert!(check_path_auth(
            "GET /px/https://example.com/ HTTP/1.1\r\n\
             Authorization: Basic YWRtaW46d3Jvbmc=\r\n\r\n",
            &make_users()
        )
        .is_none());
    }

    #[test]
    fn test_path_auth_prefers_verifiable_header() {
        // 两个头同时存在：Authorization 错、Proxy-Authorization 对 → 以能通过认证的为准，
        // 这样目标站点自己的 Authorization 可以保留下来
        let req = "GET /px/https://example.com/ HTTP/1.1\r\n\
            Authorization: Basic YWRtaW46d3Jvbmc=\r\n\
            Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n\r\n";
        assert_eq!(
            check_path_auth(req, &make_users()),
            Some(PathAuthSource::ProxyAuthorization)
        );
    }

    #[test]
    fn test_proxy_auth_does_not_accept_plain_authorization_header() {
        // 经典代理模式只认 Proxy-Authorization，避免把源站凭据当作代理凭据
        let req = "GET http://example.com/ HTTP/1.1\r\n\
            Authorization: Basic YWRtaW46c2VjcmV0\r\n\r\n";
        assert!(!check_proxy_auth(req, &make_users()));
    }

    // ─── 凭据等时比较 ───

    #[test]
    fn test_constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        // 长度不同直接判否（长度本身不可避免会泄漏）
        assert!(!constant_time_eq(b"secret", b"secre"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_auth_requires_both_username_and_password() {
        let users = vec![AuthUser {
            username: "alice".into(),
            password: "s3cret".into(),
        }];
        // 用户名对、密码错 → 拒绝
        assert!(!verify_basic_credentials(
            &BASE64_STANDARD.encode("alice:wrong"),
            &users
        ));
        // 密码对、用户名错 → 拒绝
        assert!(!verify_basic_credentials(
            &BASE64_STANDARD.encode("bob:s3cret"),
            &users
        ));
        // 两者都对 → 通过
        assert!(verify_basic_credentials(
            &BASE64_STANDARD.encode("alice:s3cret"),
            &users
        ));
    }
}
