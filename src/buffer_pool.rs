//! Buffer pool module for zero-copy and buffer reuse

use std::sync::Arc;
use tokio::sync::Mutex;

/// Buffer size for proxy operations
pub const BUFFER_SIZE: usize = 8192;

/// A thread-safe buffer pool for high-concurrency scenarios
#[derive(Clone)]
pub struct BufferPool {
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl BufferPool {
    /// Create a new buffer pool with default settings
    pub fn new() -> Self {
        Self {
            pool: Arc::new(Mutex::new(Vec::with_capacity(64))),
        }
    }

    /// Get a buffer from the pool
    pub async fn get(&self) -> PooledBuffer {
        let mut pool = self.pool.lock().await;
        
        if let Some(buf) = pool.pop() {
            PooledBuffer {
                data: buf,
                pool: Arc::clone(&self.pool),
            }
        } else {
            // Create new buffer if pool is empty
            PooledBuffer {
                data: vec![0u8; BUFFER_SIZE],
                pool: Arc::clone(&self.pool),
            }
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

/// A buffer borrowed from the pool
pub struct PooledBuffer {
    data: Vec<u8>,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl PooledBuffer {
    /// Get a mutable slice to the buffer data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        let pool = Arc::clone(&self.pool);
        let buf = std::mem::take(&mut self.data);
        
        // Spawn a task to return the buffer asynchronously
        tokio::spawn(async move {
            let mut pool = pool.lock().await;
            if pool.len() < 128 { // Max pool size
                let mut buf = buf;
                buf.resize(BUFFER_SIZE, 0);
                pool.push(buf);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_buffer_pool() {
        let pool = BufferPool::new();
        
        // Get a buffer from the pool
        let mut buf = pool.get().await;
        
        // Write data to buffer
        let slice = buf.as_mut_slice();
        slice[0..4].copy_from_slice(b"test");
        
        // Return buffer to pool when dropped
        drop(buf);
        
        // Get another buffer
        let _buf2 = pool.get().await;
    }
}
