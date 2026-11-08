//! 网络传输原语：异步连接、`host:port` 解析、IO 错误分类
//!
//! 这些原语同时被经典转发（`crate::protocol::connect`、`crate::protocol::forward`、
//! `crate::protocol::classic`、`crate::protocol::relay`、`crate::protocol::dispatch`）与路径前缀直连
//! （[`crate::protocol::path_proxy`]）复用。历史上它们定义在 `proxy.rs` 内，
//! 导致 `path_proxy` 必须反向依赖 `proxy`，与 `proxy → path_proxy` 共同构成模块级循环依赖。
//! 独立成叶模块后依赖方向变为单向：
//!
//! ```text
//! connect / forward / classic / relay / dispatch ──┐
//!                                                   ├──→ net
//! path_proxy ───────────────────────────────────────┘
//! ```

use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// 传输流的统一约束：可读、可写、可移动、可跨线程，用于 `Box<dyn AsyncStream>` 装箱。
pub(crate) trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// 异步 DNS 解析并连接目标主机
///
/// 与直接 `TcpStream::connect((host, port))` 不同，`lookup_host` 是异步的，
/// 不会在 Tokio 运行时内执行阻塞的 `getaddrinfo`（同步 DNS 会阻塞工作线程）。
/// 对解析出的多个地址（多 A/AAAA 记录）依次尝试，直到连接成功。
pub(crate) async fn connect_host(host: &str, port: u16, timeout: Duration) -> std::io::Result<TcpStream> {
    let addrs = match tokio::time::timeout(timeout, tokio::net::lookup_host((host, port))).await {
        Ok(res) => res.map_err(std::io::Error::other)?,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("DNS lookup timed out for {}:{}", host, port),
            ))
        }
    };

    let mut last_err: Option<std::io::Error> = None;
    for addr in addrs {
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => {
                last_err = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("Connection to {}:{} timed out", host, port),
                ))
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("No address resolved for {}", host),
        )
    }))
}

/// 写入全部数据，并给每个 `write()` 调用加超时
///
/// 读方向一直有 [`connect_host`] 那样的超时约束，写方向过去却是裸 `write_all`：
/// 对端只连不读时，socket 发送缓冲填满后 `write` 会永久挂起，这条连接连同它的
/// 并发许可就一直被占着。写超时意味着**对端已经不可用**，调用方应当结束该连接，
/// 而不是重试。
///
/// 计时粒度是**单个 `write()` 调用**而不是整段数据：每次写出有进展就重新计时，
/// 因此大 body / 慢速客户端（每 30 秒内总能写出去一些字节）不会被误杀；
/// 只有"整整一个 `timeout` 内一个字节都写不出去"才判定失败，这与"对端不可用"
/// 的语义一致。
pub(crate) async fn write_all_with_timeout<W>(
    writer: &mut W,
    buf: &[u8],
    timeout: Duration,
    what: &str,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut rest = buf;
    while !rest.is_empty() {
        let n = match tokio::time::timeout(timeout, writer.write(rest)).await {
            Ok(res) => res?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("timeout writing {}", what),
                ))
            }
        };
        // `write` 返回 0 表示对端不可能再接受数据（如已关闭的写端），继续循环只会空转
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                format!("peer accepted zero bytes while writing {}", what),
            ));
        }
        rest = &rest[n..];
    }
    Ok(())
}

/// 判断 IO 错误是否为"对端正常/半正常关闭连接"类（不应记为 ERROR）
///
/// 这些错误在 TLS 隧道场景中极其常见，绝大多数并非代理本身的问题：
/// - `UnexpectedEof`：TLS 对端未发送 close_notify 就关闭连接（浏览器、curl 等常用做法）
/// - `ConnectionReset`：对端发送 TCP RST（移动网络切换、NAT 超时等）
/// - `ConnectionAborted`：本地或对端中止连接
/// - `BrokenPipe`：写入已关闭的管道（对端先关闭，己方仍在写）
pub(crate) fn is_benign_close_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
    )
}

/// Parse host:port, our own最小化实现。
///
/// 支持形式：
/// - `host`（无端口，默认 443）
/// - `host:port`
/// - `[ipv6]:port`（带方括号的 IPv6 字面量，符合 URL 规范）
///
/// 裸 IPv6（不含方括号，如 `::1`）因含多个冒号无法可靠拆分，会返回 Err 或误判；
/// 规范要求使用方括号形式。
pub(crate) fn parse_host_port(host_port: &str) -> Result<(&str, u16), String> {
    // 带方括号的 IPv6：先在末尾的 "]:" 处拆分，避免被内部冒号干扰
    if host_port.starts_with('[') {
        return parse_bracketed_ipv6(host_port);
    }

    match host_port.split_once(':') {
        Some((host, port_str)) => {
            let port = port_str.parse::<u16>().map_err(|e| e.to_string())?;
            Ok((host, port))
        }
        None => Ok((host_port, 443)), // 无端口，默认 HTTPS 端口
    }
}

/// 解析 `[ipv6]:port` 形式的带方括号 IPv6 地址
fn parse_bracketed_ipv6(host_port: &str) -> Result<(&str, u16), String> {
    // 定位 "]"
    let close = host_port
        .find(']')
        .ok_or_else(|| format!("unclosed '[' in host:port '{}'", host_port))?;
    let host = &host_port[..=close]; // 含方括号，如 "[::1]"

    let rest = &host_port[close + 1..];
    if rest.is_empty() {
        return Ok((host, 443)); // 无端口，默认 443
    }
    if !rest.starts_with(':') {
        return Err(format!(
            "expected ':port' after ']' in host:port '{}'",
            host_port
        ));
    }
    let port = rest[1..]
        .parse::<u16>()
        .map_err(|e| format!("invalid port in '{}': {}", host_port, e))?;
    Ok((host, port))
}

/// 去掉 IPv6 字面量的方括号：URL / `host:port` 里是 `[::1]`，socket/DNS/SNI 只接受 `::1`
///
/// 全项目唯一的方括号处理点：经典代理目标解析、CONNECT 隧道与 TLS SNI 都调用它，
/// 避免三处实现漂移（漏一处就表现为 IPv6 目标 502 或 SNI 非法）。
pub(crate) fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// 对端只连不读：每个 `write()` 的超时都必须触发，整体不能永久挂起
    #[tokio::test]
    async fn test_write_all_with_timeout_gives_up_when_peer_stops_reading() {
        let (mut writer, _peer) = tokio::io::duplex(8);
        let err = write_all_with_timeout(&mut writer, &[b'x'; 64], Duration::from_millis(50), "test")
            .await
            .expect_err("对端不读时写必须超时");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "写超时须映射为 TimedOut");
    }

    /// 慢但对端仍在消费：总耗时远超单个超时值，也不得判失败（超时按单次 `write()` 计）
    #[tokio::test]
    async fn test_write_all_with_timeout_allows_slow_but_progressing_peer() {
        let (mut writer, mut peer) = tokio::io::duplex(16);
        tokio::spawn(async move {
            let mut buf = [0u8; 4];
            while peer.read_exact(&mut buf).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        // 64 字节、每 20ms 才被消费 4 字节 → 总耗时约 300ms，远大于 50ms 的单次超时
        write_all_with_timeout(&mut writer, &[b'x'; 64], Duration::from_millis(50), "test")
            .await
            .expect("持续有进展的慢速对端不得被误杀");
    }

    #[test]
    fn test_is_benign_close_error_classifies_tls_close_notify_as_benign() {
        // rustls 对端未发送 close_notify 时返回的错误 → 应判定为良性
        let e = std::io::Error::new(std::io::ErrorKind::UnexpectedEof,
            "peer closed connection without sending TLS close_notify");
        assert!(is_benign_close_error(&e),
            "UnexpectedEof (TLS close_notify missing) must be benign");
    }

    #[test]
    fn test_is_benign_close_error_classifies_network_resets_as_benign() {
        // TCP RST / 连接中止 / 管道破裂 → 良性（网络中极常见）
        assert!(is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::ConnectionReset)));
        assert!(is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::ConnectionAborted)));
        assert!(is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::BrokenPipe)));
    }

    #[test]
    fn test_is_benign_close_error_rejects_real_errors() {
        // 真异常不应降级（保留 warn/error 日志通道）
        assert!(!is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)));
        assert!(!is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::AddrInUse)));
        assert!(!is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::TimedOut)));
        assert!(!is_benign_close_error(&std::io::Error::from(std::io::ErrorKind::InvalidData)));
    }

    // ─── parse_host_port 测试 ───

    #[test]
    fn test_parse_host_port_with_port() {
        let (host, port) = parse_host_port("example.com:8080").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_without_port_defaults_443() {
        let (host, port) = parse_host_port("example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443, "CONNECT 默认端口应为 443");
    }

    #[test]
    fn test_parse_host_port_ipv4() {
        let (host, port) = parse_host_port("1.2.3.4:9999").unwrap();
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 9999);
    }

    #[test]
    fn test_parse_host_port_bracketed_ipv6() {
        // 带方括号的 IPv6 字面量（URL 标准形式）
        let (host, port) = parse_host_port("[::1]:8443").unwrap();
        assert_eq!(host, "[::1]");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_parse_host_port_bare_ipv6() {
        // 无端口、无方括号的裸 IPv6 —— 会因含多个冒号被误判。
        // 这是已知限制（与旧实现一致）；文档标注用户应使用方括号形式。
        let (host, port) = parse_host_port("::1").unwrap_or(("fallback", 443));
        assert_eq!(host, "fallback");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_invalid_port_error() {
        assert!(parse_host_port("example.com:notaport").is_err(), "非数字端口应报错");
        assert!(parse_host_port("example.com:99999").is_err(), "端口超出 u16 范围应报错");
    }
}
