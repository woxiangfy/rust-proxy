//! DNS caching module with async resolution support

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info};

use trust_dns_resolver::{config::*, AsyncResolver, TokioAsyncResolver};

/// DNS缓存条目
struct DnsCacheEntry {
    ip: IpAddr,
    timestamp: Instant,
}

/// DNS缓存管理器
#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<RwLock<HashMap<String, DnsCacheEntry>>>,
    ttl: Duration,
    resolver: Arc<TokioAsyncResolver>,
}

impl DnsCache {
    /// 创建新的DNS缓存实例
    /// ttl_minutes: 缓存过期时间（分钟）
    pub async fn new(ttl_minutes: u64) -> Self {
        let resolver = AsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        info!("DNS cache initialized with {} minutes TTL", ttl_minutes);

        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_minutes * 60),
            resolver: Arc::new(resolver),
        }
    }

    /// 获取或解析DNS记录
    pub async fn get_or_resolve(&self, host: &str) -> anyhow::Result<IpAddr> {
        // 先检查缓存
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(host) {
                if Instant::now() - entry.timestamp < self.ttl {
                    debug!("DNS cache hit for {}", host);
                    return Ok(entry.ip);
                } else {
                    debug!("DNS cache expired for {}", host);
                }
            }
        }

        // 缓存未命中或已过期，执行DNS解析
        let ip = self.resolve(host).await?;

        // 更新缓存
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                host.to_string(),
                DnsCacheEntry {
                    ip,
                    timestamp: Instant::now(),
                },
            );
            debug!("DNS cache updated for {} -> {}", host, ip);
        }

        Ok(ip)
    }

    /// 执行异步DNS解析
    async fn resolve(&self, host: &str) -> anyhow::Result<IpAddr> {
        debug!("Performing DNS resolution for {}", host);
        
        let response = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(|e| anyhow::anyhow!("DNS resolution failed for {}: {}", host, e))?;

        response
            .iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No IP address found for {}", host))
    }

    /// 获取缓存大小
    #[allow(dead_code)]
    pub async fn cache_size(&self) -> usize {
        self.cache.read().await.len()
    }

    /// 手动清除缓存
    #[allow(dead_code)]
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("DNS cache cleared");
    }

    /// 清理过期缓存
    #[allow(dead_code)]
    pub async fn cleanup_expired(&self) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();
        let old_size = cache.len();
        
        cache.retain(|_, entry| now - entry.timestamp < self.ttl);
        
        let removed = old_size - cache.len();
        if removed > 0 {
            debug!("Cleaned up {} expired DNS cache entries", removed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_cache() {
        let cache = DnsCache::new(5).await;
        
        // 第一次查询（缓存未命中）
        let ip1 = cache.get_or_resolve("localhost").await.unwrap();
        assert_eq!(ip1, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        
        // 第二次查询（缓存命中）
        let ip2 = cache.get_or_resolve("localhost").await.unwrap();
        assert_eq!(ip1, ip2);
        
        assert_eq!(cache.cache_size().await, 1);
    }

    #[tokio::test]
    async fn test_cache_cleanup() {
        let cache = DnsCache::new(0).await; // 0分钟TTL（立即过期）
        
        // 添加缓存条目
        cache.get_or_resolve("localhost").await.unwrap();
        assert_eq!(cache.cache_size().await, 1);
        
        // 清理过期缓存
        cache.cleanup_expired().await;
        assert_eq!(cache.cache_size().await, 0);
    }
}
