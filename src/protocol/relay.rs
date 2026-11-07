//! 响应回传：把上游读到的字节原样写给客户端
//!
//! 经典代理与路径前缀直连共用同一段「读上游 → 写客户端」循环（自适应缓冲、
//! 单次读单次写、不解析响应语义），差异只在**如何解释结束原因**：
//! 经典代理把所有结束都视为正常收尾，路径前缀直连需要把读错误/超时上抛给调用方。
//! 因此本模块只返回中性的 [`CopyOutcome`]，由各调用点自行映射回原有契约与日志。

use crate::support::buffer_pool::AdaptiveBuffer;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 响应拷贝循环的结束原因（中性描述，不含任何日志或返回类型决策）
#[derive(Debug)]
pub(crate) enum CopyOutcome {
    /// 上游正常关闭（读到 EOF）
    Eof,
    /// 读上游出错；原始错误保留给调用方判断是否等价于正常关闭
    ReadError(std::io::Error),
    /// 读上游超时
    TimedOut,
    /// 写客户端失败：客户端已断开
    ClientClosed,
}

/// 流式转发响应体：一次读上游、一次写客户端，直到上游 EOF 或任一端断开。
///
/// 拷贝缓冲自适应（8KB 起步，长传输 / 大 body 翻倍到 256KB），中间不做额外分配。
/// 返回值附带循环结束时的缓冲大小（字节），供调用方沿用原有日志格式。
pub(crate) async fn copy_upstream_to_client<S, T>(
    client: &mut S,
    upstream: &mut T,
    timeout: Duration,
) -> (CopyOutcome, usize)
where
    S: AsyncWrite + Unpin,
    T: AsyncRead + Unpin,
{
    let mut copy = AdaptiveBuffer::new();
    loop {
        copy.prepare();
        match tokio::time::timeout(timeout, upstream.read(copy.as_mut_slice())).await {
            Ok(Ok(0)) => return (CopyOutcome::Eof, copy.current_size()),
            Ok(Ok(n)) => {
                copy.note_copied(n);
                if client
                    .write_all(&copy.as_mut_slice()[..n])
                    .await
                    .is_err()
                {
                    return (CopyOutcome::ClientClosed, copy.current_size());
                }
            }
            Ok(Err(e)) => return (CopyOutcome::ReadError(e), copy.current_size()),
            Err(_) => return (CopyOutcome::TimedOut, copy.current_size()),
        }
    }
}
