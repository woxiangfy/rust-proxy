//! HTTP 请求体分帧与流式转发
//!
//! 唯一职责：在不缓冲整个 body 的前提下，把客户端请求体按 RFC 7230 分帧边界
//! 原样转发到上游（含 chunked 终止块识别、已缓冲前缀回灌、超时约束）。
//!
//! 经典代理与路径前缀直连都经 `crate::protocol::relay::forward_request_body` 调用本模块
//! （两条链路只在日志标签上不同），因此不依赖任何上层模块（仅依赖
//! [`crate::support::buffer_pool`] 与 [`crate::support::net`] 的写超时原语），是纯叶模块。

use crate::support::buffer_pool::{BufferPool, BUFFER_SIZE};
use crate::support::net::write_all_with_timeout;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

/// 请求体转发失败发生在哪一侧
///
/// 调用方据此决定能否向客户端回写错误响应：写上游失败说明目标不可用，
/// 可以回 502；读客户端失败说明客户端已经不可用，回写没有接收方。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyFailureSide {
    /// 读客户端失败（超时 / 连接错误）
    Client,
    /// 写上游失败（超时 / 连接错误）
    Upstream,
}

/// 带方向的请求体转发错误
#[derive(Debug)]
pub(super) struct BodyForwardError {
    pub(super) side: BodyFailureSide,
    pub(super) error: std::io::Error,
}

impl BodyForwardError {
    fn client(error: std::io::Error) -> Self {
        Self {
            side: BodyFailureSide::Client,
            error,
        }
    }

    fn upstream(error: std::io::Error) -> Self {
        Self {
            side: BodyFailureSide::Upstream,
            error,
        }
    }
}

/// RFC 7230 chunked 请求体分帧状态机
///
/// 仅用于识别 body 结束位置（最终块 `0\r\n` 及随后的空行），所有字节原样转发。
struct ChunkedBodyReader {
    state: ChunkState,
    /// chunk-size 行 / trailer 行缓冲
    line: Vec<u8>,
    /// 当前 chunk 剩余数据字节
    chunk_remaining: u64,
    /// chunk 数据后已消费的 CRLF 字节数（0..=2）
    crlf_seen: u8,
    /// 正常结束（读到终止块与空行）
    done: bool,
    /// 畸形分帧：既不是正常结束，也不应继续转发
    malformed: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum ChunkState {
    /// 读取 chunk-size 行（可能跨多个输入片段）
    SizeLine,
    /// 转发 chunk 数据
    Data,
    /// 等待 chunk 数据后的 \r\n
    DataCrlf,
    /// 读取 trailer（遇空行结束）
    Trailers,
}

impl ChunkedBodyReader {
    fn new() -> Self {
        Self {
            state: ChunkState::SizeLine,
            line: Vec::with_capacity(16),
            chunk_remaining: 0,
            crlf_seen: 0,
            done: false,
            malformed: false,
        }
    }

    #[inline]
    fn done(&self) -> bool {
        self.done
    }

    /// 分帧已损坏：调用方必须报错，不能当作 body 正常结束
    #[inline]
    fn malformed(&self) -> bool {
        self.malformed
    }

    /// 消费一个输入字节，推进分帧状态
    fn push_byte(&mut self, b: u8) {
        if self.done || self.malformed {
            return;
        }
        match self.state {
            ChunkState::SizeLine => {
                if self.line.len() >= 64 {
                    self.malformed = true; // 防御：chunk-size/trailer 行异常长
                    return;
                }
                self.line.push(b);
                if self.line.ends_with(b"\r\n") {
                    match parse_chunk_size(&self.line) {
                        Some(0) => {
                            self.line.clear();
                            self.state = ChunkState::Trailers;
                        }
                        Some(n) => {
                            self.line.clear();
                            self.chunk_remaining = n;
                            self.state = ChunkState::Data;
                        }
                        None => self.malformed = true, // 畸形行：停止转发并报错
                    }
                }
            }
            ChunkState::Data => {
                if self.chunk_remaining > 0 {
                    self.chunk_remaining -= 1;
                    if self.chunk_remaining == 0 {
                        self.crlf_seen = 0;
                        self.state = ChunkState::DataCrlf;
                    }
                }
            }
            ChunkState::DataCrlf => {
                if self.crlf_seen == 0 && b == b'\r' {
                    self.crlf_seen = 1;
                } else if self.crlf_seen == 1 && b == b'\n' {
                    self.crlf_seen = 2;
                    self.state = ChunkState::SizeLine;
                } else {
                    self.malformed = true; // 畸形 CRLF：停止转发并报错
                }
            }
            ChunkState::Trailers => {
                if self.line.len() >= 64 {
                    self.malformed = true;
                    return;
                }
                self.line.push(b);
                if self.line.ends_with(b"\r\n") {
                    if self.line == b"\r\n" {
                        self.done = true; // 空行：body 结束
                    } else {
                        self.line.clear(); // trailer 行，继续
                    }
                }
            }
        }
    }
}

/// 解析 chunk-size 行（可能带 extension：`1a;ext=val`），返回十六进制大小
fn parse_chunk_size(line: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(line).ok()?;
    let s = s.strip_suffix("\r\n").unwrap_or(s);
    let hex = s.split(';').next()?.trim();
    u64::from_str_radix(hex, 16).ok()
}

/// 畸形 chunked 分帧：客户端输入错误，不属于上游故障
fn malformed_chunked_error() -> BodyForwardError {
    BodyForwardError::client(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "malformed chunked request body",
    ))
}

/// 流式转发 chunked 编码的请求体。
///
/// `prefix` 是调用方已从 socket 读入的 body 前缀（可能是完整 body，也可能只是开头）。
/// **这些字节必须由本函数的分帧状态机消费后再转发**：若调用方先原样写出、再从这里读
/// socket，则终止块落在前缀里时状态机永远等不到结束，连接会一直挂到超时。
///
/// 分帧状态机逐字节解析并原样转发，直到遇到终止块 `0\r\n` 及随后的空行（trailer 结束）。
/// 输出按 BUFFER_SIZE 批量 flush，避免逐字节写。
///
/// 畸形分帧（非十六进制 size 行、chunk 数据后不是 CRLF、行缓冲超限）一律返回
/// [`BodyForwardError`]（客户端侧），不再像旧实现那样把它当作 body 正常结束。
pub(super) async fn forward_chunked_body<S, T>(
    client: &mut S,
    target: &mut T,
    prefix: &[u8],
    timeout: Duration,
    buffer_pool: &BufferPool,
) -> Result<(), BodyForwardError>
where
    S: AsyncRead + Unpin,
    T: AsyncWrite + Unpin,
{
    let mut reader = ChunkedBodyReader::new();
    let mut buf = buffer_pool.get();
    let buf_slice = buf.as_mut_slice();
    let mut out: Vec<u8> = Vec::with_capacity(BUFFER_SIZE);

    // 先处理已缓冲前缀：原样转发，同时驱动状态机
    if !prefix.is_empty() {
        for &b in prefix {
            reader.push_byte(b);
            out.push(b);
            if reader.malformed() {
                // 分帧已损坏：丢弃未写出的字节并报错，调用方不得继续读响应
                return Err(malformed_chunked_error());
            }
            if reader.done() {
                // 整个 body 都在前缀里结束：立即收尾，不再等 socket
                write_all_with_timeout(target, &out, timeout, "chunked request body")
                    .await
                    .map_err(BodyForwardError::upstream)?;
                return Ok(());
            }
        }
        write_all_with_timeout(target, &out, timeout, "chunked request body")
            .await
            .map_err(BodyForwardError::upstream)?;
        out.clear();
    }

    loop {
        let n = match tokio::time::timeout(timeout, client.read(buf_slice)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(BodyForwardError::client(e)),
            Err(_) => {
                return Err(BodyForwardError::client(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timeout reading chunked body",
                )))
            }
        };
        if n == 0 {
            // 客户端在完整分帧前关闭：按已收到内容结束（目标端会因 body 不完整而报错）
            return Ok(());
        }

        for &b in &buf_slice[..n] {
            reader.push_byte(b);
            out.push(b);
            if reader.malformed() {
                return Err(malformed_chunked_error());
            }
            if out.len() >= BUFFER_SIZE {
                write_all_with_timeout(target, &out, timeout, "chunked request body")
                    .await
                    .map_err(BodyForwardError::upstream)?;
                out.clear();
            }
            if reader.done() {
                if !out.is_empty() {
                    write_all_with_timeout(target, &out, timeout, "chunked request body")
                        .await
                        .map_err(BodyForwardError::upstream)?;
                }
                return Ok(());
            }
        }
    }
}

/// 按 `Content-Length` 转发请求体：先发已缓冲字节，再流式读转剩余部分。
///
/// 返回已向上游写出的字节数。`Ok(n)` 且 `n < content_length` 表示客户端在 body 发完前
/// 就关闭了连接——此时上游已收到部分 body，怎么处理由调用方决定（经典代理选择继续
/// 读响应，与 [`forward_chunked_body`] 把提前关闭当正常结束的语义保持一致）。
///
/// 已缓冲字节按 `content_length` 截断：超出的部分属于管道化的下一个请求，
/// 一起发出去会污染本次请求体。
pub(super) async fn forward_content_length_body<S, T>(
    client: &mut S,
    target: &mut T,
    buffered: &[u8],
    content_length: u64,
    timeout: Duration,
    buffer_pool: &BufferPool,
) -> Result<u64, BodyForwardError>
where
    S: AsyncRead + Unpin,
    T: AsyncWrite + Unpin,
{
    let buffered = if buffered.len() as u64 > content_length {
        &buffered[..content_length as usize]
    } else {
        buffered
    };

    if !buffered.is_empty() {
        write_all_with_timeout(target, buffered, timeout, "request body (content-length)")
            .await
            .map_err(BodyForwardError::upstream)?;
    }
    let mut sent = buffered.len() as u64;
    if sent >= content_length {
        return Ok(sent);
    }

    let mut tmp = buffer_pool.get();
    let tmp_slice = tmp.as_mut_slice();
    while sent < content_length {
        let want = std::cmp::min((content_length - sent) as usize, tmp_slice.len());
        let n = match tokio::time::timeout(timeout, client.read(&mut tmp_slice[..want])).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(BodyForwardError::client(e)),
            Err(_) => {
                return Err(BodyForwardError::client(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timeout reading request body",
                )))
            }
        };
        if n == 0 {
            // 客户端提前关闭：body 不完整，交由调用方决定后续动作
            break;
        }
        write_all_with_timeout(target, &tmp_slice[..n], timeout, "request body (content-length)")
            .await
            .map_err(BodyForwardError::upstream)?;
        sent += n as u64;
    }

    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// 用给定数据驱动 `ChunkedBodyReader`，返回其是否在正确位置判定结束。
    fn drive_chunked(data: &[u8]) -> bool {
        let mut r = ChunkedBodyReader::new();
        for &b in data {
            r.push_byte(b);
            if r.done() {
                return true;
            }
        }
        r.done()
    }

    #[test]
    fn test_chunked_termination_single_chunk() {
        // "4\r\ndata\r\n0\r\n\r\n" —— 单 chunk + 终止块 + 空行
        let data = b"4\r\ndata\r\n0\r\n\r\n";
        assert!(drive_chunked(data), "chunked body 应正确处理单块并结束");
    }

    #[test]
    fn test_chunked_termination_multiple_chunks() {
        let data = b"3\r\nfoo\r\n4\r\nbar!\r\n0\r\n\r\n";
        assert!(drive_chunked(data));
    }

    #[test]
    fn test_chunked_large_in_single_pass() {
        // 单个大数据块（跨内部 crlf 边界仍应识别）
        let data = b"a\r\n0123456789\r\n0\r\n\r\n";
        assert!(drive_chunked(data));
    }

    #[test]
    fn test_chunked_with_trailer() {
        // 终止块后带 trailer 行再以空行结束
        let data = b"1\r\na\r\n0\r\nX-Custom: val\r\n\r\n";
        assert!(drive_chunked(data), "应支持 trailer 字段后收尾");
    }

    #[test]
    fn test_chunked_incomplete_not_done() {
        // body 未完整发送：既不算结束，也不是畸形（上游/客户端都可能只是还没发完）
        let data = b"4\r\ndata\r\n0\r\n";
        let mut r = ChunkedBodyReader::new();
        for &b in data {
            r.push_byte(b);
        }
        assert!(!r.done(), "缺少最终空行时不应视为结束");
        assert!(!r.malformed(), "输入不完整不等于畸形");
    }

    #[test]
    fn test_chunked_malformed_data_crlf_stops_forwarding() {
        // 风险：chunk 数据后不是 CRLF 时必须立即停止并报错，不能继续"重新同步"。
        // 否则畸形分帧会被当成合法 body 转发，代理与上游对边界的理解随之分叉。
        let data = b"1\r\naX\r\n0\r\n\r\n";
        let mut r = ChunkedBodyReader::new();
        for (i, &b) in data.iter().enumerate() {
            r.push_byte(b);
            if r.malformed() {
                assert_eq!(i, 4, "数据后不是 CRLF 时应在该字节（索引 4）立即报错");
                assert!(!r.done(), "畸形分帧不得被标记为正常结束");
                return;
            }
        }
        panic!("畸形分帧必须触发 malformed，而不是读到终止块");
    }

    #[test]
    fn test_chunked_size_line_is_bounded() {
        // 风险：超长 chunk-size 行使行缓冲无限增长（内存放大）。
        // 状态机必须在 64 字节处停止，且不把后续字节当作合法分帧。
        let data = vec![b'a'; 80];
        let mut r = ChunkedBodyReader::new();
        let mut consumed = 0;
        for &b in &data {
            r.push_byte(b);
            consumed += 1;
            if r.malformed() {
                break;
            }
        }
        assert!(r.malformed(), "超长 size 行必须报错");
        assert!(!r.done(), "超长 size 行不得被标记为正常结束");
        assert_eq!(consumed, 65, "行缓冲上限 64 字节，加上触发判断的一字节");
    }

    #[test]
    fn test_chunked_size_with_extension_parsed() {
        let line: &[u8] = b"1a;ext=value\r\n";
        assert_eq!(parse_chunk_size(line), Some(0x1a));
    }

    #[test]
    fn test_chunked_invalid_size_line_stops() {
        // 畸形 chunk-size（非十六进制）→ 状态机必须标记畸形，而不是正常结束
        let data = b"zz\r\ndata\r\n";
        let mut r = ChunkedBodyReader::new();
        for &b in data {
            r.push_byte(b);
            if r.malformed() {
                assert!(!r.done());
                return;
            }
        }
        panic!("畸形 chunk-size 必须触发 malformed");
    }

    #[test]
    fn test_parse_chunk_size_basic() {
        assert_eq!(parse_chunk_size(b"1a\r\n"), Some(26));
        assert_eq!(parse_chunk_size(b"0\r\n"), Some(0));
        assert_eq!(parse_chunk_size(b"A\r\n"), Some(10)); // 大小写不敏感
        assert_eq!(parse_chunk_size(b"garbage\r\n"), None);
        assert_eq!(parse_chunk_size(b""), None);
    }

    // ─── chunked body 转发（含已缓冲前缀）───

    /// 完整 body 已落在缓冲区里时，必须立即收尾而不能继续读 socket（否则挂到超时）。
    #[tokio::test]
    async fn test_forward_chunked_body_completes_entirely_from_prefix() {
        let (_client_w, mut client_r) = tokio::io::duplex(64);
        let (mut up_w, mut up_r) = tokio::io::duplex(4096);
        let pool = BufferPool::new();

        // 客户端 socket 已无数据（duplex 写端被丢弃 → read 返回 0），只有前缀里有完整 body
        drop(_client_w);
        let prefix = b"5\r\nhello\r\n0\r\n\r\n";
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            forward_chunked_body(&mut client_r, &mut up_w, prefix, Duration::from_secs(2), &pool),
        )
        .await
        .expect("不应等待 socket，前缀里已有完整 body");
        assert!(res.is_ok());
        drop(up_w);

        let mut got = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut up_r, &mut got).await.unwrap();
        assert_eq!(got, prefix.to_vec());
    }

    /// 前缀只是 body 的一部分：剩余部分仍从 socket 读取并接续转发。
    #[tokio::test]
    async fn test_forward_chunked_body_continues_from_socket_after_prefix() {
        let (mut client_w, mut client_r) = tokio::io::duplex(64);
        let (mut up_w, mut up_r) = tokio::io::duplex(4096);
        let pool = BufferPool::new();

        let prefix = b"5\r\nhel".to_vec();
        let rest = b"lo\r\n0\r\n\r\n".to_vec();
        let rest_clone = rest.clone();
        tokio::spawn(async move {
            client_w.write_all(&rest_clone).await.unwrap();
            drop(client_w);
        });

        let res = tokio::time::timeout(
            Duration::from_secs(2),
            forward_chunked_body(&mut client_r, &mut up_w, &prefix, Duration::from_secs(2), &pool),
        )
        .await
        .expect("应在读到终止块后立即返回");
        assert!(res.is_ok());
        drop(up_w);

        let mut got = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut up_r, &mut got).await.unwrap();
        let mut want = prefix.clone();
        want.extend_from_slice(&rest);
        assert_eq!(got, want);
    }

    /// 畸形 chunked（数据后不是 CRLF）必须报错，不得当作正常结束
    ///
    /// 旧实现把畸形分帧与「读到终止块」都记成 `done`，`forward_chunked_body` 返回
    /// `Ok(())`，调用方会继续去读响应——而请求体实际上已经被截断。
    #[tokio::test]
    async fn test_forward_chunked_body_reports_malformed_data_crlf() {
        let (mut client, mut client_peer) = tokio::io::duplex(64);
        let mut upstream: Vec<u8> = Vec::new();
        let pool = BufferPool::new();

        // chunk 数据后是 "X" 而不是 CRLF：分帧已损坏
        client_peer.write_all(b"1\r\naX\r\n0\r\n\r\n").await.unwrap();
        drop(client_peer);

        let res = forward_chunked_body(
            &mut client,
            &mut upstream,
            &[],
            Duration::from_millis(200),
            &pool,
        )
        .await;

        assert!(
            res.is_err(),
            "畸形 chunked 必须报错，而不是返回 Ok 让调用方继续读响应"
        );
    }

    /// 已缓冲前缀里的畸形 chunk-size 行同样必须报错
    #[tokio::test]
    async fn test_forward_chunked_body_reports_malformed_size_line() {
        let (_client_peer, mut client) = tokio::io::duplex(64);
        let mut upstream: Vec<u8> = Vec::new();
        let pool = BufferPool::new();

        let res = forward_chunked_body(
            &mut client,
            &mut upstream,
            b"zz\r\ndata\r\n",
            Duration::from_millis(200),
            &pool,
        )
        .await;

        assert!(
            res.is_err(),
            "非十六进制 chunk-size 必须报错，而不是返回 Ok"
        );
    }

    // ─── Content-Length 精确转发 ───
    #[tokio::test]
    async fn test_forward_cl_truncates_buffered_to_content_length() {
        // 已缓冲字节超出 CL 的部分属于管道化的下一个请求，不能一起发出去
        let (mut client, _peer) = tokio::io::duplex(64);
        let mut upstream: Vec<u8> = Vec::new();
        let pool = BufferPool::new();
        let sent = forward_content_length_body(
            &mut client,
            &mut upstream,
            b"abcdefgh",
            4,
            Duration::from_millis(500),
            &pool,
        )
        .await
        .expect("write must succeed");
        assert_eq!(sent, 4);
        assert_eq!(upstream, b"abcd");
    }

    #[tokio::test]
    async fn test_forward_cl_reads_remaining_stream_and_reports_short_body() {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut peer) = tokio::io::duplex(64);
        let mut upstream: Vec<u8> = Vec::new();
        let pool = BufferPool::new();

        // 客户端只发 2 字节就关闭：应返回已发送字节数而不是挂到超时
        peer.write_all(b"cd").await.unwrap();
        drop(peer);

        let sent = forward_content_length_body(
            &mut client,
            &mut upstream,
            b"ab",
            6,
            Duration::from_millis(500),
            &pool,
        )
        .await
        .expect("short body is not an io error, caller decides");
        assert_eq!(sent, 4, "已缓冲 2 字节 + 流式 2 字节");
        assert_eq!(upstream, b"abcd");
    }
}
