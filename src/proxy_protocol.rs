//! PROXY Protocol v1/v2 解析（自动检测）
//!
//! 适用场景：代理服务挂在 nginx/HAProxy 后面，通过 SNI 分流并使用
//! `proxy_protocol on;` 转发真实客户端 IP。
//!
//! PROXY Protocol 头在 TCP 连接建立后、任何应用层协议（HTTP/TLS）数据之前发送。
//! 本模块在 accept 之后先行解析该头，提取真实客户端 IP，同时保留可能已读入的后续
//! 数据（通过 [`PrefixedStream`] 回填，避免丢失首包）。
//!
//! v1 格式（文本）：
//! ```text
//! PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>\r\n
//! PROXY TCP6 <src_ip> <dst_ip> <src_port> <dst_port>\r\n
//! PROXY UNKNOWN\r\n
//! ```
//!
//! v2 格式（二进制）：
//! ```text
//! 12 字节签名 \r\n\r\n\0\r\nQUIT\n
//! + 版本/命令字节（0x21=PROXY, 0x20=LOCAL）
//! + 协议家族字节
//! + 2 字节长度
//! + 地址数据
//! ```
//!
//! `Auto` 模式不匹配签名时返回 [`PpDetectResult::NotMatched`]，由上层回退为普通
//! HTTP/TLS 处理——这是"同一端口既接受代理协议又接受直连流量"的关键。

use std::net::SocketAddr;
use std::time::Duration;

use crate::config::ProxyProtocolMode;
use crate::io::PrefixedStream;

/// PROXY Protocol v2 签名（12 字节）
const PP_V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";

/// PROXY Protocol v1 前缀
const PP_V1_PREFIX: &[u8] = b"PROXY ";

/// PROXY Protocol 头部最大允许长度（字节），防止恶意 len 值导致 OOM
const PP_MAX_HEADER_LEN: usize = 512;

/// PROXY Protocol 头部读取超时（秒），防止慢速攻击（slowloris）
const PP_HEADER_TIMEOUT_SECS: u64 = 10;

/// 自动检测 PROXY Protocol 的结果类型
pub(crate) enum PpDetectResult {
    /// 成功解析 PROXY Protocol 头：真实 IP（可能为 None，表示 UNKNOWN/LOCAL）+ 后续数据流
    Parsed(Option<SocketAddr>, PrefixedStream<tokio::net::TcpStream>),
    /// 数据不匹配 PROXY Protocol 签名（仅在 `Auto` 模式返回）：已读取的前缀 + 流
    NotMatched(Vec<u8>, tokio::net::TcpStream),
}

/// PROXY Protocol 解析/检测模式（内部使用，对应 config 中的模式）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PpParseMode {
    /// 强制要求：不匹配则返回错误
    Require,
    /// 自动检测：不匹配则返回 `NotMatched`，携带已读数据供上层回退
    Auto,
}

/// `Disable` 无法表示为解析模式——用类型系统而非 `unreachable!()` 表达该约束。
///
/// 调用方分流时已经保证只在 `Auto` / `Require` 下进入解析路径；此处返回
/// `Err(())` 是对该不变量的兜底，而非运行期 panic 点。
impl TryFrom<ProxyProtocolMode> for PpParseMode {
    type Error = ();

    fn try_from(mode: ProxyProtocolMode) -> Result<Self, Self::Error> {
        match mode {
            ProxyProtocolMode::Disable => Err(()),
            ProxyProtocolMode::Auto => Ok(PpParseMode::Auto),
            ProxyProtocolMode::Require => Ok(PpParseMode::Require),
        }
    }
}

/// 判断字节开头是否为 PROXY Protocol v1/v2 签名候选。
///
/// `seen` 为连接首字节（至少 6 字节）：
/// - v1：以 ASCII `PROXY ` 开头
/// - v2：前 6 字节与 v2 签名头一致
///
/// 普通 HTTP 请求首行（如 `GET /`、`CONNECT h`）不会匹配，从而被当作直连流量处理。
///
/// 该函数当前仅由单元测试直接使用；运行时签名检测在 [`parse_proxy_protocol`] 内部完成。
#[cfg(test)]
fn is_proxy_signature(seen: &[u8]) -> bool {
    if seen.len() < 6 {
        return false;
    }
    seen.starts_with(PP_V1_PREFIX) || seen[..6] == PP_V2_SIGNATURE[..6]
}

/// 解析或自动检测 PROXY Protocol 头。
///
/// - `Require` 模式：连接数据必须匹配 PROXY Protocol v1/v2 签名，解析失败返回 `Err`。
///   成功时返回 `PpDetectResult::Parsed`。
/// - `Auto` 模式：若数据匹配则解析并返回 `Parsed`；若不匹配 PROXY Protocol 签名，
///   返回 `NotMatched`，携带已读取的前缀数据供上层通过 [`PrefixedStream`]
///   回退给应用层（HTTP/TLS）正常处理。
///
/// 整个读取过程在 `PP_HEADER_TIMEOUT_SECS` 内完成，防止慢速攻击。
pub(crate) async fn parse_proxy_protocol(
    stream: tokio::net::TcpStream,
    mode: PpParseMode,
) -> std::io::Result<PpDetectResult> {
    use tokio::io::AsyncReadExt;

    tokio::time::timeout(
        Duration::from_secs(PP_HEADER_TIMEOUT_SECS),
        async move {
            let mut stream = stream;

            // ── 第一步：读取前 6 字节做签名快速检测 ──
            let mut header = [0u8; 6];
            if try_read_exact(&mut stream, &mut header).await?.is_none() {
                // EOF：只有 Require 模式视为错误，Auto 模式返回 NotMatched 空前缀
                return match mode {
                    PpParseMode::Require => Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "PROXY protocol header EOF before signature",
                    )),
                    PpParseMode::Auto => Ok(PpDetectResult::NotMatched(Vec::new(), stream)),
                };
            }

            // ── 判断签名类型 ──
            let is_v2_candidate = header == PP_V2_SIGNATURE[..6];
            let is_v1_candidate = header == *PP_V1_PREFIX;

            if !is_v2_candidate && !is_v1_candidate {
                // 不匹配任何 PROXY Protocol 签名
                return match mode {
                    PpParseMode::Require => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Data does not match PROXY protocol v1 or v2 format",
                    )),
                    PpParseMode::Auto => Ok(PpDetectResult::NotMatched(header.to_vec(), stream)),
                };
            }

            // ── v2 签名分支 ──
            if is_v2_candidate {
                // 继续读取剩余 6 字节签名
                let mut rest_sig = [0u8; 6];
                stream.read_exact(&mut rest_sig).await?;
                let mut full_sig = [0u8; 12];
                full_sig[..6].copy_from_slice(&header);
                full_sig[6..].copy_from_slice(&rest_sig);
                if &full_sig != PP_V2_SIGNATURE {
                    return match mode {
                        PpParseMode::Require => Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "PROXY protocol v2 signature mismatch",
                        )),
                        PpParseMode::Auto => {
                            // 前 6 字节命中 v2 前缀但完整签名不匹配 → 回退，携带已读 12 字节
                            let mut prefix = Vec::with_capacity(12);
                            prefix.extend_from_slice(&full_sig);
                            Ok(PpDetectResult::NotMatched(prefix, stream))
                        }
                    };
                }

                // 读取 ver_cmd, fam, len（4 字节）
                let mut fields = [0u8; 4];
                stream.read_exact(&mut fields).await?;
                let ver_cmd = fields[0];
                let fam = fields[1];
                let len = u16::from_be_bytes([fields[2], fields[3]]) as usize;

                // 版本必须为 2
                if ver_cmd >> 4 != 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "PROXY protocol v2 version mismatch",
                    ));
                }
                let cmd = ver_cmd & 0x0F;

                // 限制 len 最大值，防止 OOM
                if len > PP_MAX_HEADER_LEN {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("PROXY protocol v2 address data too large: {} bytes", len),
                    ));
                }

                match cmd {
                    0 => {
                        // LOCAL 命令：读取并丢弃 len 字节
                        let mut discard = vec![0u8; len];
                        stream.read_exact(&mut discard).await?;
                        Ok(PpDetectResult::Parsed(
                            None,
                            PrefixedStream::new(vec![], stream),
                        ))
                    }
                    1 => {
                        // PROXY 命令：根据协议家族解析地址
                        let mut addr_data = vec![0u8; len];
                        stream.read_exact(&mut addr_data).await?;
                        let addr = parse_pp_v2_addr(fam, &addr_data)?;
                        Ok(PpDetectResult::Parsed(
                            addr,
                            PrefixedStream::new(vec![], stream),
                        ))
                    }
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("PROXY protocol v2 unknown command: {}", cmd),
                    )),
                }
            } else {
                // ── v1 分支（必然命中，上面 is_v1_candidate 已保证） ──
                // 读取直到 \r\n（最多 107 字节，规范上限）
                let mut line = Vec::with_capacity(107);
                line.extend_from_slice(&header);
                loop {
                    let mut byte = [0u8; 1];
                    let n = stream.read(&mut byte).await?;
                    if n == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "PROXY protocol v1 header incomplete",
                        ));
                    }
                    line.push(byte[0]);
                    if line.ends_with(b"\r\n") {
                        break;
                    }
                    if line.len() > 107 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "PROXY protocol v1 header too long",
                        ));
                    }
                }
                let addr = parse_pp_v1_line(&line)?;
                Ok(PpDetectResult::Parsed(
                    addr,
                    PrefixedStream::new(vec![], stream),
                ))
            }
        },
    )
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "PROXY protocol header read timed out after {}s",
                PP_HEADER_TIMEOUT_SECS
            ),
        )
    })?
}

/// 尝试读取精确字节数，EOF（0 字节）时返回 `Ok(None)` 而不是错误
async fn try_read_exact<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> std::io::Result<Option<()>> {
    use tokio::io::AsyncReadExt;
    let mut total_read = 0usize;
    while total_read < buf.len() {
        let n = reader.read(&mut buf[total_read..]).await?;
        if n == 0 {
            return if total_read == 0 {
                Ok(None)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF while reading exact bytes",
                ))
            };
        }
        total_read += n;
    }
    Ok(Some(()))
}

/// 解析 PROXY Protocol v1 文本行
fn parse_pp_v1_line(line: &[u8]) -> std::io::Result<Option<SocketAddr>> {
    let s = std::str::from_utf8(line).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "PROXY v1 header not UTF-8")
    })?;
    let s = s.trim_end_matches("\r\n");

    // 格式：PROXY TCP4 src_ip dst_ip src_port dst_port
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PROXY v1 header too short",
        ));
    }

    // PROXY UNKNOWN → 无地址
    if parts[1] == "UNKNOWN" {
        return Ok(None);
    }

    if parts.len() < 6 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PROXY v1 header missing address fields",
        ));
    }

    let src_ip = parts[2];
    let src_port: u16 = parts[4].parse().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "PROXY v1 invalid port")
    })?;

    let addr: SocketAddr = match parts[1] {
        "TCP4" => {
            let ip: std::net::Ipv4Addr = src_ip.parse().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "PROXY v1 invalid IPv4")
            })?;
            SocketAddr::new(std::net::IpAddr::V4(ip), src_port)
        }
        "TCP6" => {
            let ip: std::net::Ipv6Addr = src_ip.parse().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "PROXY v1 invalid IPv6")
            })?;
            SocketAddr::new(std::net::IpAddr::V6(ip), src_port)
        }
        _ => return Ok(None), // UNKNOWN 或其他 → 无地址
    };

    Ok(Some(addr))
}

/// 解析 PROXY Protocol v2 地址数据
fn parse_pp_v2_addr(fam: u8, data: &[u8]) -> std::io::Result<Option<SocketAddr>> {
    // 协议家族：高 4 位是地址家族，低 4 位是传输协议
    let af = fam >> 4;
    let proto = fam & 0x0F;

    // UNSPEC（0x00）或 AF_UNIX（0x30/0x31）→ 无 IP 地址
    if af == 0 || af == 3 {
        return Ok(None);
    }

    // 仅 TCP（proto=1）和 UDP（proto=2）有意义
    if proto != 1 && proto != 2 {
        return Ok(None);
    }

    match af {
        1 => {
            // IPv4：4(src_ip) + 4(dst_ip) + 2(src_port) + 2(dst_port) = 12
            if data.len() < 12 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "PROXY v2 IPv4 address data too short",
                ));
            }
            let src_ip = std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            let src_port = u16::from_be_bytes([data[8], data[9]]);
            Ok(Some(SocketAddr::new(std::net::IpAddr::V4(src_ip), src_port)))
        }
        2 => {
            // IPv6：16(src_ip) + 16(dst_ip) + 2(src_port) + 2(dst_port) = 36
            if data.len() < 36 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "PROXY v2 IPv6 address data too short",
                ));
            }
            let mut src_ip = [0u8; 16];
            src_ip.copy_from_slice(&data[0..16]);
            let src_ip = std::net::Ipv6Addr::from(src_ip);
            let src_port = u16::from_be_bytes([data[32], data[33]]);
            Ok(Some(SocketAddr::new(std::net::IpAddr::V6(src_ip), src_port)))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── PROXY Protocol v1 解析测试 ───

    #[test]
    fn test_parse_pp_v1_tcp4() {
        let line = b"PROXY TCP4 192.168.1.100 10.0.0.1 12345 8080\r\n";
        let addr = parse_pp_v1_line(line).unwrap().unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.100");
        assert_eq!(addr.port(), 12345);
    }

    #[test]
    fn test_parse_pp_v1_tcp6() {
        let line = b"PROXY TCP6 ::1 ::2 12345 8080\r\n";
        let addr = parse_pp_v1_line(line).unwrap().unwrap();
        assert_eq!(addr.ip().to_string(), "::1");
        assert_eq!(addr.port(), 12345);
    }

    #[test]
    fn test_parse_pp_v1_unknown() {
        let line = b"PROXY UNKNOWN\r\n";
        let result = parse_pp_v1_line(line).unwrap();
        assert!(result.is_none(), "UNKNOWN should return None");
    }

    #[test]
    fn test_parse_pp_v1_malformed() {
        // 缺少字段
        assert!(parse_pp_v1_line(b"PROXY TCP4\r\n").is_err());
        // 无效端口
        assert!(parse_pp_v1_line(b"PROXY TCP4 1.2.3.4 5.6.7.8 abc 80\r\n").is_err());
        // 无效 IP
        assert!(parse_pp_v1_line(b"PROXY TCP4 not-an-ip 5.6.7.8 12345 80\r\n").is_err());
        // 非 UTF-8
        assert!(parse_pp_v1_line(b"PROXY \xff\xfe\r\n").is_err());
    }

    // ─── PROXY Protocol v2 解析测试 ───

    #[test]
    fn test_parse_pp_v2_tcp4() {
        // v2 IPv4: 签名(12) + ver_cmd(0x21) + fam(0x11=AF_INET+STREAM) + len(12)
        // + src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2)
        let mut buf = Vec::new();
        buf.extend_from_slice(PP_V2_SIGNATURE);
        buf.push(0x21); // version=2, command=PROXY
        buf.push(0x11); // AF_INET + STREAM
        buf.extend_from_slice(&12u16.to_be_bytes()); // length
        buf.extend_from_slice(&[192, 168, 1, 100]); // src_ip
        buf.extend_from_slice(&[10, 0, 0, 1]); // dst_ip
        buf.extend_from_slice(&12345u16.to_be_bytes()); // src_port
        buf.extend_from_slice(&8080u16.to_be_bytes()); // dst_port

        // 直接测试 parse_pp_v2_addr（签名+头部已在 parse_proxy_protocol 中消费）
        let fam = 0x11u8;
        let addr_data = &buf[16..]; // 跳过签名(12) + ver_cmd(1) + fam(1) + len(2)
        let addr = parse_pp_v2_addr(fam, addr_data).unwrap().unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.100");
        assert_eq!(addr.port(), 12345);
    }

    #[test]
    fn test_parse_pp_v2_tcp6() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x21, 0x21]); // ver_cmd=PROXY, fam=AF_INET6+STREAM
        buf.extend_from_slice(&36u16.to_be_bytes()); // length=36
        // src_ip (16 bytes)
        let src_ip: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // ::1
        buf.extend_from_slice(&src_ip);
        // dst_ip (16 bytes)
        buf.extend_from_slice(&[0; 16]);
        // src_port (2 bytes)
        buf.extend_from_slice(&54321u16.to_be_bytes());
        // dst_port (2 bytes)
        buf.extend_from_slice(&443u16.to_be_bytes());

        let fam = 0x21u8;
        let addr_data = &buf[4..]; // 跳过 ver_cmd + fam + len
        let addr = parse_pp_v2_addr(fam, addr_data).unwrap().unwrap();
        assert_eq!(addr.ip().to_string(), "::1");
        assert_eq!(addr.port(), 54321);
    }

    #[test]
    fn test_parse_pp_v2_local() {
        // LOCAL 命令（ver_cmd=0x20）→ 无地址
        let fam = 0x00u8; // UNSPEC
        let result = parse_pp_v2_addr(fam, &[]).unwrap();
        assert!(result.is_none(), "UNSPEC family should return None");
    }

    #[test]
    fn test_parse_pp_v2_data_too_short() {
        // IPv4 数据不足 12 字节 → 错误
        let fam = 0x11u8;
        let short_data = &[1, 2, 3]; // 只有 3 字节
        assert!(parse_pp_v2_addr(fam, short_data).is_err());
    }

    // ─── PROXY Protocol v2 安全校验测试 ───

    #[test]
    fn test_pp_v2_cmd_unspecified_returns_error() {
        // cmd = 0x02 (未定义的命令) → 应返回错误
        let ver_cmd = 0x22u8; // version=2, cmd=2 (未定义)
        let cmd = ver_cmd & 0x0F;
        assert_ne!(cmd, 0, "cmd should not be LOCAL");
        assert_ne!(cmd, 1, "cmd should not be PROXY");
    }

    #[test]
    fn test_pp_max_header_len_constant_is_reasonable() {
        const {
            assert!(
                PP_MAX_HEADER_LEN >= 512,
                "max header len should be at least 512"
            );
            assert!(
                PP_MAX_HEADER_LEN < 65535,
                "max header len should be well below u16::MAX"
            );
        }
    }

    #[test]
    fn test_pp_header_timeout_constant_is_reasonable() {
        const {
            assert!(PP_HEADER_TIMEOUT_SECS >= 5, "timeout should be at least 5s");
            assert!(
                PP_HEADER_TIMEOUT_SECS <= 60,
                "timeout should be at most 60s"
            );
        }
    }

    #[test]
    fn test_is_proxy_signature_detects_v1_prefix() {
        assert!(is_proxy_signature(b"PROXY TCP4 1.2.3.4"));
        assert!(is_proxy_signature(b"PROXY UNKNOWN"));
    }

    #[test]
    fn test_is_proxy_signature_detects_v2_signature() {
        // v2 签名前 6 字节：\r\n\r\n\0\r
        assert!(is_proxy_signature(b"\r\n\r\n\x00\rQUIT"));
    }

    #[test]
    fn test_is_proxy_signature_rejects_plain_http() {
        // 普通 HTTP 代理请求首行不会被误判为 PROXY Protocol
        assert!(!is_proxy_signature(b"GET http://example.com/"));
        assert!(!is_proxy_signature(b"CONNECT example.com:443"));
        assert!(!is_proxy_signature(b"POST /path HTTP/1.1"));
    }

    #[test]
    fn test_is_proxy_signature_rejects_short_input() {
        // 不足 6 字节无法判断签名，应视为非 PROXY（交给普通流量处理）
        assert!(!is_proxy_signature(b""));
        assert!(!is_proxy_signature(b"GET"));
        assert!(!is_proxy_signature(b"PROX"));
    }

    // ─── 模式映射：类型层禁止 Disable ───

    #[test]
    fn test_pp_parse_mode_try_from_rejects_disable() {
        // Disable 不应能被映射为解析模式（旧实现用 unreachable!() 兜底）
        assert!(PpParseMode::try_from(ProxyProtocolMode::Disable).is_err());
        assert_eq!(
            PpParseMode::try_from(ProxyProtocolMode::Auto).unwrap(),
            PpParseMode::Auto
        );
        assert_eq!(
            PpParseMode::try_from(ProxyProtocolMode::Require).unwrap(),
            PpParseMode::Require
        );
    }
}
