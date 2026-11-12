//! 请求头读取：把客户端连接上的字节累积到出现 `\r\n\r\n` 为止
//!
//! 本模块只做传输层解析，不判断代理语义、不做认证、不建上游连接。输出两种结果：
//! - 字节存储方式（常见情况零拷贝复用池化缓冲区）
//! - 完整性状态（`Complete` / `Incomplete` / `Overflow`），调用方据此决定丢弃或回 431

use crate::protocol::http_util::{find_header_end, MAX_HEAD_BYTES};
use crate::support::buffer_pool::{BufferPool, PooledBuffer, BUFFER_SIZE};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

/// 请求头读取结果的存储方式
///
/// 常见情况（请求头在第一次读取内完成）复用池化缓冲区，实现零拷贝；
/// 大请求头则需要扩展堆缓冲。
pub(super) enum RequestStorage {
    /// 单次读取即包含完整请求头：直接持有池化缓冲区（零拷贝）
    Pooled(PooledBuffer, usize),
    /// 需要多次读取的大请求：持有堆缓冲
    Heap(Vec<u8>),
}

impl RequestStorage {
    /// 获取已读数据的字节切片
    #[inline]
    pub(super) fn as_slice(&self) -> &[u8] {
        match self {
            RequestStorage::Pooled(b, n) => &b.as_slice()[..*n],
            RequestStorage::Heap(v) => v,
        }
    }
}

/// 请求头的读取结果状态
///
/// "读到数据"不等于"读到了完整的头"。截断的头既不能当完整头解析，更不能转发：
/// 转发给上游时会补上结束空行，上游把它当作合法请求处理，而代理与客户端对
/// "这条请求到底发了什么"理解不同（历史实现在超限时就是这样把截断头送出去的）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HeadStatus {
    /// 已找到 `\r\n\r\n`，可以安全解析与转发
    Complete,
    /// 客户端在头结束前关闭连接（EOF）：内容不完整，只能丢弃
    Incomplete,
    /// 达到 [`MAX_HEAD_BYTES`] 仍无结束符：畸形或恶意，回 431
    Overflow,
}

/// 读取请求头，直到出现 `\r\n\r\n`（或达到 `MAX_HEAD_BYTES` 上限 / 客户端 EOF）。
///
/// 整个读取过程受一次 `timeout` 约束，防止慢速攻击（slowloris）逐次续期。
/// 常见情况（一次读取即含完整头）复用池化缓冲区，零拷贝。
pub(super) async fn read_request_head<S>(
    client: &mut S,
    buffer_pool: &BufferPool,
    timeout: Duration,
) -> std::io::Result<(RequestStorage, HeadStatus)>
where
    S: AsyncRead + Unpin,
{
    tokio::time::timeout(timeout, read_request_head_inner(client, buffer_pool))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out reading request head",
            )
        })?
}

async fn read_request_head_inner<S>(
    client: &mut S,
    buffer_pool: &BufferPool,
) -> std::io::Result<(RequestStorage, HeadStatus)>
where
    S: AsyncRead + Unpin,
{
    // 第一段读入池化缓冲区（常见路径：零拷贝）
    let mut buf = buffer_pool.get();
    let n = client.read(buf.as_mut_slice()).await?;
    if n == 0 {
        // 连接建立后一个字节都没发就关闭：按不完整处理（调用方会直接丢弃）
        return Ok((RequestStorage::Pooled(buf, 0), HeadStatus::Incomplete));
    }
    if find_header_end(&buf.as_slice()[..n]).is_some() {
        return Ok((RequestStorage::Pooled(buf, n), HeadStatus::Complete));
    }

    // 慢路径：多次读取累积到堆缓冲。
    // 注意：短读（n < BUFFER_SIZE）不代表客户端已发完，TCP 可能分片，
    // 因此必须继续读取直到出现头结束符、超限或 EOF。
    let mut data = Vec::with_capacity(2 * BUFFER_SIZE);
    data.extend_from_slice(&buf.as_slice()[..n]);
    loop {
        let m = client.read(buf.as_mut_slice()).await?;
        if m == 0 {
            // EOF：已读内容里仍没有结束符 → 头是截断的，不能当完整头转发
            return Ok((RequestStorage::Heap(data), HeadStatus::Incomplete));
        }
        data.extend_from_slice(&buf.as_slice()[..m]);
        if find_header_end(&data).is_some() {
            break;
        }
        if data.len() >= MAX_HEAD_BYTES {
            // 读够了上限仍未见到头结束符：标记超限，不再继续读（防慢速续期）
            return Ok((RequestStorage::Heap(data), HeadStatus::Overflow));
        }
    }
    Ok((RequestStorage::Heap(data), HeadStatus::Complete))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    // ─── 慢速头（slowloris）──────────────────────────────

    /// 慢速滴水客户端：每 `interval` 才吐 1 字节。
    ///
    /// 关键在于**每次读取都真的等待**：如果实现把 deadline 重置到每次 `read` 上，
    /// 这个读取器就能一直续期、永远读不完；只有「整段读取共享一个 deadline」才会超时。
    struct DripReader {
        data: Vec<u8>,
        pos: usize,
        interval: Duration,
        delay: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl DripReader {
        fn new(data: Vec<u8>, interval: Duration) -> Self {
            Self {
                data,
                pos: 0,
                interval,
                delay: None,
            }
        }
    }

    impl AsyncRead for DripReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let me = self.get_mut();
            if me.pos >= me.data.len() {
                return Poll::Ready(Ok(())); // EOF
            }
            let interval = me.interval;
            let delay = me
                .delay
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(interval)));
            if delay.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            me.delay = None;
            buf.put_slice(&me.data[me.pos..me.pos + 1]);
            me.pos += 1;
            Poll::Ready(Ok(()))
        }
    }

    /// 慢速滴水必须在**整体** deadline 处放弃，而不是被逐次读取续期。
    ///
    /// 用 `start_paused` 的虚拟时钟：每秒 1 字节、200 字节的头，若逐次续期要 200 秒；
    /// 虚拟时间下断言的是「恰好 5 秒放弃」，既不真实等待也不受机器快慢影响。
    #[tokio::test(start_paused = true)]
    async fn test_read_request_head_times_out_on_slow_drip() {
        let pool = BufferPool::new();
        let head = format!(
            "GET http://a.com/ HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
            "a".repeat(200)
        );
        let total = head.len();
        let mut reader = DripReader::new(head.into_bytes(), Duration::from_secs(1));

        let start = tokio::time::Instant::now();
        let err = match read_request_head(&mut reader, &pool, Duration::from_secs(5)).await {
            Ok(_) => panic!("慢速滴水必须超时，不能一直等到读完 {total} 字节"),
            Err(e) => e,
        };

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(
            start.elapsed(),
            Duration::from_secs(5),
            "整体 deadline 必须生效，不能被逐次读取续期"
        );
        assert!(
            reader.pos < total,
            "超时时请求头只应收到 {} / {} 字节",
            reader.pos,
            total
        );
    }

    /// 对照组：同样逐字节到达，但在 deadline 内读完必须成功。
    ///
    /// 没有这条，上一条用例可能只是因为「分片就读不出来」而通过。
    #[tokio::test(start_paused = true)]
    async fn test_read_request_head_accepts_slow_but_within_deadline() {
        let pool = BufferPool::new();
        let head = format!(
            "GET http://a.com/ HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
            "a".repeat(200)
        );
        let mut reader = DripReader::new(head.as_bytes().to_vec(), Duration::from_millis(1));

        let (storage, status) = read_request_head(&mut reader, &pool, Duration::from_secs(5))
            .await
            .expect("deadline 内读完应成功");

        assert_eq!(status, HeadStatus::Complete);
        assert_eq!(storage.as_slice(), head.as_bytes());
    }

    #[tokio::test]
    async fn test_read_request_head_flags_overflow_only_when_incomplete() {
        let pool = BufferPool::new();

        // 完整头（含结束符）：不标记超限
        let mut complete = &b"GET http://a.com/ HTTP/1.1\r\nHost: a.com\r\n\r\n"[..];
        let (storage, status) = read_request_head(&mut complete, &pool, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(status, HeadStatus::Complete, "完整头不得判为超限");
        assert!(storage.as_slice().ends_with(b"\r\n\r\n"));

        // 顶满上限仍无结束符：必须标记超限——否则调用方会把截断的头当成完整头转发
        let mut big = Vec::new();
        big.extend_from_slice(b"GET http://a.com/ HTTP/1.1\r\nX-Pad: ");
        big.resize(MAX_HEAD_BYTES, b'a');
        let mut incomplete = &big[..];
        let (_, status) = read_request_head(&mut incomplete, &pool, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(
            status,
            HeadStatus::Overflow,
            "读满 {MAX_HEAD_BYTES} 字节仍无结束符必须标记超限"
        );
    }

    /// 客户端在头结束前关闭：状态必须是 `Incomplete`，调用方据此丢弃。
    ///
    /// 这条与超限用例区分开：截断的原因不同（EOF vs 长度上限），处理方式也不同
    /// （静默丢弃 vs 回 431），但共同点是**都不能当完整头解析或转发**。
    #[tokio::test]
    async fn test_read_request_head_marks_eof_truncated_head_incomplete() {
        let pool = BufferPool::new();
        let mut partial = &b"GET http://a.com/ HTTP/1.1\r\nHost: a.com"[..];
        let (storage, status) = read_request_head(&mut partial, &pool, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(status, HeadStatus::Incomplete);
        assert_eq!(
            storage.as_slice(),
            b"GET http://a.com/ HTTP/1.1\r\nHost: a.com",
            "已读字节仍需保留，供调用方记录日志"
        );
    }
}
