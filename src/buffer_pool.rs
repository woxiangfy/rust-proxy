//! 缓冲区池模块，提供零拷贝和缓冲区复用功能
//!
//! 池容量支持动态扩缩：
//! - 初始上限 4 个，当池空且未达硬上限时自动翻倍扩容（最多 64 个）
//! - 连续归还 20 次未触发扩容时，自动减半缩容（最少 4 个），丢弃多余缓冲区

use std::sync::{Arc, Mutex};

/// 代理操作使用的缓冲区大小
pub const BUFFER_SIZE: usize = 8192;

// ── 动态扩缩容常量 ──

/// 最小池容量
const MIN_POOL_SIZE: usize = 4;
/// 初始池容量上限
const INITIAL_MAX_POOL_SIZE: usize = 4;
/// 硬上限（池容量不会超过此值）
const HARD_MAX_POOL_SIZE: usize = 64;
/// 缩容阈值：连续归还次数超过此值且未扩容时触发缩容
const SHRINK_THRESHOLD: usize = 20;

// ── 池内部状态 ──

/// 缓冲区池的内部共享状态
struct PoolState {
    buffers: Vec<Vec<u8>>,
    max_size: usize,
    /// 当前借出中的缓冲区数量
    outstanding: usize,
    /// 自上次扩容以来连续归还的次数，用于判断是否需要缩容
    idle_drops: usize,
}

/// 线程安全的缓冲区池，适用于高并发场景
///
/// 内部使用 `std::sync::Mutex` 而非 `tokio::sync::Mutex`，
/// 因为临界区极短（仅 Vec 的 push/pop 操作），不会阻塞 Tokio 运行时。
#[derive(Clone)]
pub struct BufferPool {
    state: Arc<Mutex<PoolState>>,
}

impl BufferPool {
    /// 使用默认设置创建新的缓冲区池
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(PoolState {
                buffers: Vec::with_capacity(INITIAL_MAX_POOL_SIZE),
                max_size: INITIAL_MAX_POOL_SIZE,
                outstanding: 0,
                idle_drops: 0,
            })),
        }
    }

    /// 从池中获取一个缓冲区
    ///
    /// 优先从池中复用已有缓冲区；若池为空则分配新的。
    /// 当池为空且当前容量未达硬上限时，自动扩容（容量翻倍）。
    pub fn get(&self) -> PooledBuffer {
        let mut state = self.state.lock().unwrap();

        if let Some(buf) = state.buffers.pop() {
            state.outstanding += 1;
            state.idle_drops = 0; // 活跃使用中，重置缩容计数器
            PooledBuffer {
                data: buf,
                state: Arc::clone(&self.state),
            }
        } else {
            // 池空 → 若借出数已达当前容量上限，翻倍扩容
            if state.outstanding >= state.max_size && state.max_size < HARD_MAX_POOL_SIZE {
                state.max_size = (state.max_size * 2).min(HARD_MAX_POOL_SIZE);
                state.idle_drops = 0; // 重置缩容计数器
            }
            state.outstanding += 1;
            // 释放锁后再分配内存，避免在锁内执行 8KB 零初始化
            drop(state);
            PooledBuffer {
                data: vec![0u8; BUFFER_SIZE],
                state: Arc::clone(&self.state),
            }
        }
    }

    /// 返回当前池中的缓冲区数量（仅用于测试和监控）
    #[cfg(test)]
    fn len(&self) -> usize {
        self.state.lock().unwrap().buffers.len()
    }

    /// 返回当前池容量上限（仅用于测试和监控）
    #[cfg(test)]
    fn max_size(&self) -> usize {
        self.state.lock().unwrap().max_size
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

/// 从缓冲区池借出的缓冲区
///
/// 当 `PooledBuffer` 被释放时，缓冲区会自动归还到池中供后续复用。
pub struct PooledBuffer {
    data: Vec<u8>,
    state: Arc<Mutex<PoolState>>,
}

impl PooledBuffer {
    /// 获取缓冲区数据的可变切片引用
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// 获取缓冲区数据的不可变切片引用
    #[inline]
    #[allow(dead_code)]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // 同步归还缓冲区，避免生成 Tokio 任务的开销
        let buf = std::mem::take(&mut self.data);

        if let Ok(mut state) = self.state.lock() {
            state.outstanding = state.outstanding.saturating_sub(1);
            state.idle_drops += 1;

            if state.buffers.len() < state.max_size {
                state.buffers.push(buf);
            }

            // 缩容判断：连续归还次数超阈值且容量未到最小值
            if state.idle_drops > SHRINK_THRESHOLD && state.max_size > MIN_POOL_SIZE {
                state.max_size /= 2;
                state.idle_drops = 0;
                // 丢弃超出新容量的缓冲区
                let new_max = state.max_size;
                state.buffers.truncate(new_max);
            }
        }
        // 如果获取锁失败（理论上不会发生），缓冲区直接释放
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_reuse() {
        let pool = BufferPool::new();

        let buf = pool.get();
        let ptr = buf.as_slice().as_ptr();
        drop(buf);

        // 再次获取，验证是否复用了之前的缓冲区
        let buf2 = pool.get();
        assert_eq!(buf2.as_slice().as_ptr(), ptr);
    }

    #[test]
    fn test_dynamic_growth() {
        let pool = BufferPool::new();
        assert_eq!(pool.max_size(), INITIAL_MAX_POOL_SIZE);

        // 获取 INITIAL_MAX_POOL_SIZE + 1 个缓冲区，触发扩容
        let bufs: Vec<PooledBuffer> = (0..INITIAL_MAX_POOL_SIZE + 1).map(|_| pool.get()).collect();

        // 扩容后容量应翻倍
        assert_eq!(pool.max_size(), INITIAL_MAX_POOL_SIZE * 2);
        assert_eq!(pool.len(), 0); // 池中还剩 0 个（因为全被借出后又扩容了一次）

        drop(bufs);
    }

    #[test]
    fn test_dynamic_shrink() {
        let pool = BufferPool::new();

        // 先触发扩容到 8
        let bufs: Vec<PooledBuffer> = (0..INITIAL_MAX_POOL_SIZE + 1).map(|_| pool.get()).collect();
        assert_eq!(pool.max_size(), INITIAL_MAX_POOL_SIZE * 2);
        drop(bufs);

        // 活跃使用中不应缩容：每次从池中取出会重置 idle_drops
        for _ in 0..SHRINK_THRESHOLD + 2 {
            let buf = pool.get();
            drop(buf);
        }
        assert_eq!(
            pool.max_size(),
            INITIAL_MAX_POOL_SIZE * 2,
            "活跃使用的池不应缩容"
        );

        // 借出大量缓冲区后一次性归还，累积 idle_drops 触发缩容
        let held: Vec<_> = (0..SHRINK_THRESHOLD + 1).map(|_| pool.get()).collect();
        let expanded_max = pool.max_size();
        drop(held);
        assert!(
            pool.max_size() < expanded_max,
            "长期闲置的池应触发缩容，当前 max_size={}",
            pool.max_size()
        );
    }

    #[test]
    fn test_hard_max_limit() {
        let pool = BufferPool::new();

        // 持续触发扩容，直到硬上限
        let mut all_bufs = Vec::new();
        let mut prev_max = pool.max_size();
        while prev_max < HARD_MAX_POOL_SIZE {
            // 借出超过当前容量的缓冲区以触发扩容
            for _ in 0..prev_max + 1 {
                all_bufs.push(pool.get());
            }
            let new_max = pool.max_size();
            assert!(new_max > prev_max || new_max == HARD_MAX_POOL_SIZE);
            prev_max = new_max;
        }
        assert_eq!(pool.max_size(), HARD_MAX_POOL_SIZE);

        drop(all_bufs);
    }
}