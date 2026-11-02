//! 缓冲区池模块，提供零拷贝和缓冲区复用功能
//!
//! 池容量支持动态扩缩：
//! - 初始上限 4 个，当池空且未达硬上限时自动翻倍扩容（最多 64 个）
//! - 连续归还 20 次未触发扩容时，自动减半缩容（最少 4 个），丢弃多余缓冲区

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 池化缓冲区大小（请求头读取、短请求转发等短生命周期场景）
///
/// 大文件转发的 body 拷贝不再用固定大小，而是走 [`AdaptiveBuffer`]：
/// 初始 8KB，持续传输后自动翻倍到 256KB，兼顾「小请求省内存」与「大文件少系统调用」。
pub const BUFFER_SIZE: usize = 8192;

// ── 自适应拷贝缓冲区参数 ──

/// 初始大小：8KB（小响应/小请求几乎不占额外内存）
pub const ADAPTIVE_INITIAL: usize = 8 * 1024;
/// 上限：再大收益趋于平坦，而每连接常驻内存 ×2（8KB→256KB 共 5 次翻倍）
pub const ADAPTIVE_MAX: usize = 256 * 1024;
/// 持续传输超过该时长后翻倍（慢速链路 / 长时间下载的主要触发条件）
pub const ADAPTIVE_GROW_INTERVAL: Duration = Duration::from_secs(5);
/// 或已拷贝超过该字节数后翻倍：纯时间触发对「几秒就下完」的快连接不生效，
/// 补一条按量的触发条件，让 1Gbps+ 内网/loopback 的大文件也能快速用上大缓冲。
pub const ADAPTIVE_GROW_AFTER_BYTES: u64 = 32 * 1024 * 1024;

/// 自适应拷贝缓冲区
///
/// 生命周期跟着一次 body 转发走：开始 8KB，满足触发条件（持续 5s 或累计拷贝 32MB）
/// 就翻倍，直到 256KB 上限；每次翻倍之间互不叠加，避免瞬间冲顶。
///
/// 为什么按「时间 + 字节」双条件：小文件下载（<8KB 级）直接用 8KB 结束，零额外内存；
/// 大文件下载才会逐步放大，最终把每 MB 的 read/write 系统调用从 256 次降到 4 次。
#[derive(Debug)]
pub struct AdaptiveBuffer {
    buf: Vec<u8>,
    started: Instant,
    /// 下一次允许按时间翻倍的时刻（相对 `started`）
    next_grow_at: Duration,
    /// 下一次允许按字节翻倍的门槛
    next_grow_bytes: u64,
    /// 自上次翻倍以来累计拷贝的字节数
    copied: u64,
    interval: Duration,
    grow_after_bytes: u64,
    max: usize,
}

impl AdaptiveBuffer {
    pub fn new() -> Self {
        Self::with_limits(
            ADAPTIVE_INITIAL,
            ADAPTIVE_GROW_INTERVAL,
            ADAPTIVE_GROW_AFTER_BYTES,
            ADAPTIVE_MAX,
        )
    }

    fn with_limits(initial: usize, interval: Duration, grow_after_bytes: u64, max: usize) -> Self {
        let initial = initial.clamp(1, max.max(1));
        Self {
            buf: vec![0u8; initial],
            started: Instant::now(),
            next_grow_at: interval,
            next_grow_bytes: grow_after_bytes,
            copied: 0,
            interval,
            grow_after_bytes,
            max,
        }
    }

    /// 每次 read 前调用：到点则翻倍（写入 0 填充的新长度）
    #[inline]
    pub fn prepare(&mut self) {
        if self.buf.len() >= self.max {
            return;
        }
        let due = self.started.elapsed() >= self.next_grow_at
            || (self.grow_after_bytes > 0 && self.copied >= self.next_grow_bytes);
        if !due {
            return;
        }
        let new_len = (self.buf.len().saturating_mul(2)).min(self.max);
        self.buf.resize(new_len, 0);
        self.copied = 0;
        self.next_grow_at = self.started.elapsed() + self.interval;
        self.next_grow_bytes = self.grow_after_bytes;
        log::debug!("Adaptive copy buffer grew to {} KB", new_len / 1024);
    }

    /// 记录本次实际拷贝的字节数（用于按量触发翻倍）
    #[inline]
    pub fn note_copied(&mut self, n: usize) {
        self.copied = self.copied.saturating_add(n as u64);
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    #[inline]
    pub fn current_size(&self) -> usize {
        self.buf.len()
    }
}

impl Default for AdaptiveBuffer {
    fn default() -> Self {
        Self::new()
    }
}

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
        // 锁 poison 容错：临界区极短且不跨 await，panic 后状态自洽，继续使用
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

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
        self.state.lock().unwrap_or_else(|e| e.into_inner()).buffers.len()
    }

    /// 返回当前池容量上限（仅用于测试和监控）
    #[cfg(test)]
    fn max_size(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).max_size
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

        // 锁 poison 容错：即使锁已损坏也归还缓冲区，避免内存泄漏
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── 自适应拷贝缓冲区 ───

    #[test]
    fn test_adaptive_starts_at_initial_size() {
        let buf = AdaptiveBuffer::new();
        assert_eq!(buf.current_size(), ADAPTIVE_INITIAL);
        assert_eq!(ADAPTIVE_INITIAL, 8 * 1024);
    }

    #[test]
    fn test_adaptive_small_transfer_does_not_grow() {
        let mut buf = AdaptiveBuffer::new();
        // 小响应：拷贝 8KB，未达按量阈值（32MB），时间也没到 5s
        buf.note_copied(8 * 1024);
        buf.prepare();
        assert_eq!(buf.current_size(), ADAPTIVE_INITIAL, "小传输不应扩容");
    }

    #[test]
    fn test_adaptive_grows_by_bytes() {
        let mut buf = AdaptiveBuffer::with_limits(8192, Duration::from_secs(3600), 1000, 1 << 20);
        assert_eq!(buf.current_size(), 8192);
        buf.note_copied(1000);
        buf.prepare();
        assert_eq!(buf.current_size(), 16384, "累计达阈值应翻倍");
        // 翻倍后计数清零，需再累计一个阈值才继续翻倍
        buf.note_copied(500);
        buf.prepare();
        assert_eq!(buf.current_size(), 16384, "未达新阈值不应翻倍");
        buf.note_copied(500);
        buf.prepare();
        assert_eq!(buf.current_size(), 32768);
    }

    #[test]
    fn test_adaptive_grows_by_time_and_caps() {
        // interval=0：每次 prepare 都到点，验证翻倍序列与上限
        let mut buf = AdaptiveBuffer::with_limits(8192, Duration::ZERO, 0, 256 * 1024);
        let mut sizes = Vec::new();
        for _ in 0..8 {
            buf.prepare();
            sizes.push(buf.current_size());
        }
        assert_eq!(
            sizes,
            vec![16384, 32768, 65536, 131072, 262144, 262144, 262144, 262144],
            "应逐次翻倍并在 256KB 封顶"
        );
    }

    #[test]
    fn test_adaptive_default_cap_is_256k() {
        let mut buf = AdaptiveBuffer::with_limits(ADAPTIVE_INITIAL, Duration::ZERO, 0, ADAPTIVE_MAX);
        for _ in 0..10 {
            buf.prepare();
        }
        assert_eq!(buf.current_size(), 256 * 1024);
        // 8KB → 256KB 共 5 次翻倍，每 MB 的系统调用从 256 次降到 8 次
        assert_eq!(ADAPTIVE_MAX / ADAPTIVE_INITIAL, 32);
    }

    #[test]
    fn test_adaptive_buffer_zero_filled_and_writable() {
        let mut buf = AdaptiveBuffer::new();
        buf.prepare();
        let s = buf.as_mut_slice();
        assert!(s.iter().all(|&b| b == 0), "扩容后新增区域必须是 0");
        s[0] = 1;
        s[s.len() - 1] = 2;
    }

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

    #[test]
    fn test_pool_survives_poisoned_lock() {
        let pool = BufferPool::new();

        // 故意污染池的内部锁：持锁期间 panic
        let _ = std::panic::catch_unwind(|| {
            let _guard = pool.state.lock().unwrap();
            panic!("intentional panic to poison the pool lock");
        });

        // 锁被污染后 get/drop/len/max_size 均应正常工作
        let buf = pool.get();
        assert_eq!(buf.as_slice().len(), BUFFER_SIZE);
        drop(buf);
        assert_eq!(pool.len(), 1);
        assert!(pool.max_size() >= MIN_POOL_SIZE);
    }
}