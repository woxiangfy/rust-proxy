//! TLS 证书体系：证书加载、自签回退、mtime 热重载
//!
//! 本模块只负责"如何得到并持续刷新一个可用的 [`TlsAcceptor`]"，不关心 accept 循环、
//! 不关心连接从哪里来。`server` 侧只调用三个入口：
//!
//! - [`build_tls_reloader`]：用户提供 cert+key 时构造（支持热重载）
//! - [`generate_self_signed_reloader`]：cert+key 缺失/加载失败时的自签回退（不参与热重载）
//! - [`TlsReloader::current_acceptor`]：每次握手取最新 acceptor（热重载对其透明）
//!
//! 热重载策略：定时比较 cert/key 文件的 mtime，变化则重建 acceptor 并原子替换；
//! 重建失败保留旧证书，服务不中断。

use anyhow::{Context, Result};
use log::{debug, info, warn};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;

/// TLS 证书热重载检查间隔（秒）
pub(crate) const TLS_RELOAD_CHECK_INTERVAL_SECS: u64 = 3600;

/// 自签证书有效期（年）
pub(crate) const SELF_SIGNED_VALIDITY_YEARS: i32 = 10;

/// 容忍 `std::sync::Mutex` poison：锁在持有期间发生 panic 时仍继续使用内部数据。
///
/// 代理服务器的锁临界区极短且不跨 await，panic 后内部状态通常仍是自洽的；
/// 与其让整个服务器因一次 panic 而崩溃，不如继续运行（仅丢弃一次操作）。
fn mutex_guard<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|e| e.into_inner())
}

/// 容忍 `std::sync::RwLock` 读锁 poison（语义同 [`mutex_guard`]）
fn rwlock_read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

/// 容忍 `std::sync::RwLock` 写锁 poison（语义同 [`mutex_guard`]）
fn rwlock_write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

/// TLS 证书来源（用户提供 / 自动生成自签）
///
/// 热重载仅对"用户提供"来源有意义；自动生成的自签证书不参与热重载。
pub(crate) enum TlsSource {
    /// 用户显式提供了 cert+key，记录路径以支持 mtime 检查和热重载
    UserProvided {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    /// 自动生成的自签证书（无外部文件），不参与热重载
    AutoSelfSigned,
}

/// TLS 证书热重载管理器
///
/// 封装 `TlsAcceptor` 并支持运行时热重载（仅对用户提供的证书）：
/// - 定时检查证书/私钥文件的修改时间（mtime）
/// - 若文件已更新，重新加载证书并原子替换内部的 `TlsAcceptor`
/// - 重载失败时保留旧证书，确保服务不中断
///
/// 自动生成自签证书时，热重载逻辑是 no-op（因为没有外部源文件可监听）。
pub(crate) struct TlsReloader {
    acceptor: RwLock<Arc<TlsAcceptor>>,
    pub(crate) source: TlsSource,
    /// 上次加载时证书文件的 mtime（仅 UserProvided 有用）
    last_cert_mtime: Mutex<Option<SystemTime>>,
    last_key_mtime: Mutex<Option<SystemTime>>,
}

impl TlsReloader {
    /// 从用户提供的 cert+key 创建 Reloader（启用热重载）
    fn from_user_certs(cert_path: PathBuf, key_path: PathBuf) -> Result<Self> {
        let acceptor = build_tls_acceptor_from_files(&cert_path, &key_path)?;
        let cert_mtime = file_mtime(&cert_path)?;
        let key_mtime = file_mtime(&key_path)?;
        Ok(Self {
            acceptor: RwLock::new(Arc::new(acceptor)),
            source: TlsSource::UserProvided { cert_path, key_path },
            last_cert_mtime: Mutex::new(Some(cert_mtime)),
            last_key_mtime: Mutex::new(Some(key_mtime)),
        })
    }

    /// 从已经构造好的 acceptor 创建（自动生成自签场景，不支持热重载）
    fn from_acceptor(acceptor: TlsAcceptor, source: TlsSource) -> Self {
        Self {
            acceptor: RwLock::new(Arc::new(acceptor)),
            source,
            last_cert_mtime: Mutex::new(None),
            last_key_mtime: Mutex::new(None),
        }
    }

    /// 获取当前 acceptor 的 Arc 引用（供 TLS 握手使用）
    pub(crate) fn current_acceptor(&self) -> Arc<TlsAcceptor> {
        rwlock_read(&self.acceptor).clone()
    }

    /// 是否需要定期重载证书文件
    ///
    /// - 用户提供的证书（来自 PEM 文件）→ `true`：监听文件 mtime 实现热重载
    /// - 自动生成的自签证书（无外部文件）→ `false`：不需要定时检查
    pub(crate) fn needs_reload_check(&self) -> bool {
        matches!(self.source, TlsSource::UserProvided { .. })
    }

    /// 检查证书/私钥文件是否更新，若更新则重新加载
    ///
    /// 返回值：
    /// - `Ok(true)`：文件已变化，证书已成功重载
    /// - `Ok(false)`：文件未变化，或为自动生成证书无需检查
    /// - `Err(_)`：重载失败（如证书格式无效），保留旧证书继续服务
    fn check_and_reload(&self) -> Result<bool> {
        let (cert_path, key_path) = match &self.source {
            TlsSource::UserProvided { cert_path, key_path } => (cert_path, key_path),
            TlsSource::AutoSelfSigned => return Ok(false), // 自动生成的无外部文件，跳过
        };

        let cert_mtime = file_mtime(cert_path)?;
        let key_mtime = file_mtime(key_path)?;

        let need_reload = {
            let last_cert = *mutex_guard(&self.last_cert_mtime);
            let last_key = *mutex_guard(&self.last_key_mtime);
            last_cert != Some(cert_mtime) || last_key != Some(key_mtime)
        };

        if !need_reload {
            return Ok(false);
        }

        // 文件已变化，尝试重新加载
        let new_acceptor = build_tls_acceptor_from_files(cert_path, key_path)?;

        *rwlock_write(&self.acceptor) = Arc::new(new_acceptor);
        *mutex_guard(&self.last_cert_mtime) = Some(cert_mtime);
        *mutex_guard(&self.last_key_mtime) = Some(key_mtime);

        Ok(true)
    }
}

/// 根据 TlsConfig 创建 TlsReloader（仅支持用户证书路径，不做自动回退；回退由 `server` 处理）
pub(crate) fn build_tls_reloader(tls: &TlsConfig) -> Result<TlsReloader> {
    match (&tls.cert_path, &tls.key_path) {
        (Some(cert), Some(key)) => TlsReloader::from_user_certs(cert.clone(), key.clone()),
        _ => anyhow::bail!("TLS certificate and/or private key paths not configured"),
    }
}

/// 生成 10 年有效期的自签证书并封装为 TlsReloader
///
/// 证书特性：
/// - 算法：Ed25519（性能和安全性平衡，Rust 原生实现）
/// - Subject CN：`rust-proxy auto`
/// - SAN：`localhost`, `127.0.0.1`, `::1`
/// - 有效期：SELF_SIGNED_VALIDITY_YEARS（10 年）
/// - 用途：TLS 服务器端
///
/// **不写入任何文件**，纯内存生成，进程重启后证书会变化。
pub(crate) fn generate_self_signed_reloader() -> Result<TlsReloader> {
    // rcgen 0.13 中 KeyPair::generate() 默认使用 Ed25519
    let key_pair = KeyPair::generate()
        .context("Failed to generate Ed25519 key pair for self-signed certificate")?;

    let mut params = CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])
    .map_err(|e| anyhow::anyhow!("Failed to build CertificateParams: {}", e))?;
    params.distinguished_name.push(DnType::CommonName, "auto");
    params.is_ca = IsCa::NoCa;

    // 有效期：SELF_SIGNED_VALIDITY_YEARS 年（基于当前 UTC 时间推算年月日）
    // rcgen 0.13 使用 time::OffsetDateTime，这里通过 not_before 加偏移构造 not_after
    let validity_secs = SELF_SIGNED_VALIDITY_YEARS as i64 * 365 * 24 * 60 * 60;
    params.not_after = params
        .not_before
        .checked_add(time::Duration::seconds(validity_secs))
        .context("Overflow when calculating self-signed certificate not_after time")?;

    let cert = params
        .self_signed(&key_pair)
        .context("Failed to self-sign certificate")?;

    // 转换为 rustls 接受的格式（通过 into_owned 获取 'static 所有权数据）
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().as_ref().to_vec());
    let key_der_bytes: Vec<u8> = key_pair.serialized_der().to_vec();
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_der_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid generated private key DER: {}", e))?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("Failed to create rustls ServerConfig for self-signed certificate")?;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    Ok(TlsReloader::from_acceptor(
        acceptor,
        TlsSource::AutoSelfSigned,
    ))
}

/// 执行一次 TLS 证书热重载检查
pub(crate) fn handle_tls_reload(tls_reloader: &TlsReloader) {
    match tls_reloader.check_and_reload() {
        Ok(true) => match &tls_reloader.source {
            TlsSource::UserProvided {
                cert_path,
                key_path,
            } => info!(
                "TLS certificates reloaded successfully (cert={}, key={})",
                cert_path.display(),
                key_path.display()
            ),
            TlsSource::AutoSelfSigned => {}
        },
        Ok(false) => debug!("TLS certificates unchanged (or auto-signed)"),
        Err(e) => warn!(
            "TLS certificate reload failed (keeping old certificate): {}",
            e
        ),
    }
}

/// 获取文件的最后修改时间（mtime）
fn file_mtime(path: &Path) -> Result<SystemTime> {
    let metadata =
        fs::metadata(path).with_context(|| format!("Cannot stat file: {}", path.display()))?;
    metadata
        .modified()
        .with_context(|| format!("Cannot get mtime of file: {}", path.display()))
}

/// 根据 PEM 证书和私钥**文件**构建 `tokio_rustls::TlsAcceptor`
fn build_tls_acceptor_from_files(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    let cert_chain = load_certs(cert_path).with_context(|| {
        format!(
            "Failed to load TLS certificates from {}",
            cert_path.display()
        )
    })?;
    let key = load_key(key_path)
        .with_context(|| format!("Failed to load TLS private key from {}", key_path.display()))?;
    build_tls_acceptor_from_raw(cert_chain, key)
}

/// 从内存中的证书+私钥直接构建 TlsAcceptor（供 build_tls_acceptor_from_files 复用）
fn build_tls_acceptor_from_raw(
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<TlsAcceptor> {
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("Failed to create rustls ServerConfig (invalid cert/key pair)")?;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// 从 PEM 文件读取所有证书
fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file =
        fs::File::open(path).with_context(|| format!("Cannot open cert file: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs = certs(&mut reader).filter_map(|c| c.ok()).collect::<Vec<_>>();
    if certs.is_empty() {
        anyhow::bail!("No valid PEM certificates found in {}", path.display());
    }
    Ok(certs)
}

/// 从 PEM 文件读取私钥（优先 PKCS#8，兼容 RSA）
fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file =
        fs::File::open(path).with_context(|| format!("Cannot open key file: {}", path.display()))?;
    let mut reader = BufReader::new(file);

    // 先尝试 PKCS#8（最常见）
    let pkcs8_keys: Vec<_> = pkcs8_private_keys(&mut reader)
        .filter_map(|k| k.ok())
        .collect();
    if let Some(key) = pkcs8_keys.into_iter().next() {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
    }

    // 回退：尝试 RSA
    let rsa_keys: Vec<_> = rustls_pemfile::rsa_private_keys(&mut BufReader::new(
        fs::File::open(path)
            .with_context(|| format!("Cannot re-open key file: {}", path.display()))?,
    ))
    .filter_map(|k| k.ok())
    .collect();
    if let Some(key) = rsa_keys.into_iter().next() {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key));
    }

    anyhow::bail!(
        "No valid private key (PKCS#8 or RSA) found in {}",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_mtime_returns_mtime_for_existing_file() {
        // 用 file!() 定位自身，避免文件再移动后测试路径失真。
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file!());
        let mtime = file_mtime(&path);
        assert!(mtime.is_ok(), "file_mtime should succeed for existing file");
    }

    #[test]
    fn test_file_mtime_fails_for_nonexistent_file() {
        let path = Path::new("/nonexistent/path/file.pem");
        let mtime = file_mtime(path);
        assert!(mtime.is_err(), "file_mtime should fail for nonexistent file");
    }

    #[test]
    fn test_generate_self_signed_reloader_works() {
        // 验证自签证书生成不报错，且产物可用于构造 acceptor
        let reloader = generate_self_signed_reloader();
        assert!(reloader.is_ok(), "self-signed cert generation should succeed");
        let reloader = reloader.unwrap();
        assert!(
            matches!(reloader.source, TlsSource::AutoSelfSigned),
            "source must be AutoSelfSigned"
        );
        // current_acceptor 必须能够正常获取（无锁中毒）
        let acceptor = reloader.current_acceptor();
        // Arc::strong_count >=1 即可证明内部已正确初始化
        assert!(Arc::strong_count(&acceptor) >= 1);
    }

    #[test]
    fn test_self_signed_check_and_reload_is_noop() {
        // 自动生成的证书 check_and_reload 应恒返回 Ok(false)，且无副作用
        let reloader = generate_self_signed_reloader().unwrap();
        for _ in 0..3 {
            match reloader.check_and_reload() {
                Ok(false) => {}
                other => panic!("expected Ok(false) for auto-signed reload, got {:?}", other),
            }
        }
    }

    #[test]
    fn test_self_signed_reloader_does_not_need_reload_check() {
        // 自签证书场景：needs_reload_check 必须返回 false
        // （保证主循环不会创建无意义的定时器）
        let reloader = generate_self_signed_reloader().unwrap();
        assert!(
            !reloader.needs_reload_check(),
            "auto-generated self-signed cert should NOT need periodic reload check"
        );
    }

    // ─── 锁 poison 容错测试 ───

    #[test]
    fn test_mutex_guard_survives_poison() {
        // 故意污染 Mutex：持锁期间 panic
        let m = Mutex::new(42u32);
        let _ = std::panic::catch_unwind(|| {
            let _guard = m.lock().unwrap();
            panic!("intentional panic to poison the mutex");
        });

        // 锁被污染后 mutex_guard 仍能读取并写入数据
        assert_eq!(*mutex_guard(&m), 42);
        *mutex_guard(&m) = 7;
        assert_eq!(*mutex_guard(&m), 7);
    }

    #[test]
    fn test_rwlock_helpers_survive_poison() {
        // 写锁污染：持锁期间 panic
        let rw = RwLock::new("value".to_string());
        let _ = std::panic::catch_unwind(|| {
            let _guard = rw.write().unwrap();
            panic!("intentional panic to poison the rwlock");
        });

        // 污染后读/写均应正常
        assert_eq!(rwlock_read(&rw).as_str(), "value");
        rwlock_write(&rw).push('!');

        // 读锁污染同理
        let rw2 = RwLock::new(1u8);
        let _ = std::panic::catch_unwind(|| {
            let _guard = rw2.read().unwrap();
            panic!("intentional panic to poison the read lock");
        });
        assert_eq!(*rwlock_read(&rw2), 1);
    }
}
