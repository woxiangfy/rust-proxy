//! 通用流适配器（前缀缓冲流等）

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 包装一个流，读取时优先返回预先读取的前缀字节，前缀耗尽后透传内部流。
///
/// 用于两类场景：
/// - PROXY Protocol：解析头后保留已读入的前缀数据，供 HTTP/TLS 应用层继续消费
/// - CONNECT 隧道：客户端把隧道数据（如 TLS ClientHello）与 CONNECT 请求一并发送时，
///   避免已读入缓冲的字节被丢弃
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// 创建前缀缓冲流。`prefix` 为空时等价于直接使用 `inner`。
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }

    /// 取出内部流（丢弃未消费的前缀）
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// 是否仍存在未消费的前缀字节
    #[inline]
    pub fn has_pending_prefix(&self) -> bool {
        self.prefix_pos < self.prefix.len()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 先消费前缀中剩余的数据
        if this.prefix_pos < this.prefix.len() {
            let remaining = &this.prefix[this.prefix_pos..];
            let n = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.prefix_pos += n;
            return Poll::Ready(Ok(()));
        }

        // 前缀耗尽后透传内部流
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn test_prefixed_stream_reads_prefix_before_inner() {
        let (mut writer, reader) = duplex(1024);
        let mut stream = PrefixedStream::new(b"hello".to_vec(), reader);
        writer.write_all(b"world").await.unwrap();
        drop(writer);

        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "helloworld");
    }

    #[tokio::test]
    async fn test_prefixed_stream_empty_prefix_passthrough() {
        let (mut writer, reader) = duplex(1024);
        let mut stream = PrefixedStream::new(Vec::new(), reader);
        writer.write_all(b"data").await.unwrap();
        drop(writer);

        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "data");
    }

    #[tokio::test]
    async fn test_prefixed_stream_write_and_shutdown_passthrough() {
        let (writer, mut reader) = duplex(1024);
        let mut stream = PrefixedStream::new(b"x".to_vec(), writer);
        stream.write_all(b"ab").await.unwrap();
        stream.flush().await.unwrap();
        drop(stream);

        let mut out = String::new();
        reader.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "ab");
    }
}
