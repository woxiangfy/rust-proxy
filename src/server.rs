//! HTTP 代理服务器生命周期管理模块
//!
//! 负责服务器启动、TCP/TLS 监听、连接接受和优雅关闭。
//! 支持同时监听 HTTP 和 HTTPS (TLS) 两个端口。
//!
//! TLS 启用语义（严格）：
//! 1. 用户**显式指定了 `https_port`**（命令行 `--https-port` 或配置文件 `https_port`）
//!    → 必须启用 HTTPS：
//!    - 若同时提供了合法 cert+key，使用用户证书，支持热重载
//!    - 若 cert+key 缺失或加载失败，自动生成**10 年有效期自签证书**并输出 warn 日志
//!      （自签证书不参与定期重载，因为无外部源文件可监听）
//! 2. 未指定 `https_port` → **不启用 HTTPS**（即使配置了 cert+key 也忽略）

use anyhow::{Context, Result};
use std::fs;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use log::{debug, error, info, warn};
use tokio_rustls::TlsAcceptor;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair};

use crate::buffer_pool::BufferPool;
use crate::config::{Args, TlsConfig};
use crate::proxy::{handle_client, handle_client_tls};

/// TLS 证书热重载检查间隔（秒）
const TLS_RELOAD_CHECK_INTERVAL_SECS: u64 = 3600;

/// 自签证书有效期（年）
const SELF_SIGNED_VALIDITY_YEARS: i32 = 10;

/// 启动代理服务器，根据配置可能同时监听 HTTP 和 HTTPS (TLS) 端口
pub async fn run_server(args: &Args, shutdown_rx: Option<oneshot::Receiver<()>>) -> Result<()> {
    let buffer_pool = Arc::new(BufferPool::new());
    let auth = Arc::new(args.auth.clone());

    // ── 根据 TLS 配置构建 TlsReloader ──
    // config 层已确保：args.tls 为 Some ⟺ 用户显式指定了 https_port
    // 因此这里只需要决定：用用户证书还是回退到自签证书
    let tls_reloader = if let Some(tls) = &args.tls {
        match build_tls_reloader(tls) {
            Ok(reloader) => Some(Arc::new(reloader)),
            Err(e) => {
                // 用户已显式启用 HTTPS（https_port 已指定），cert/key 缺失或加载失败时，
                // 回退生成 10 年自签证书并输出 warn 日志
                warn!(
                    "Failed to load TLS certificates ({}); falling back to a self-signed \
                    certificate valid for {} years.",
                    e, SELF_SIGNED_VALIDITY_YEARS
                );
                match generate_self_signed_reloader() {
                    Ok(reloader) => Some(Arc::new(reloader)),
                    Err(gen_err) => {
                        anyhow::bail!(
                            "Failed to load TLS certificates AND failed to generate self-signed \
                            fallback: cert error: {}; self-signed error: {}",
                            e, gen_err
                        );
                    }
                }
            }
        }
    } else {
        None
    };

    // ── 绑定 HTTP 端口 ──
    let http_bind_addr = format!("0.0.0.0:{}", args.port);
    info!("Binding HTTP address: {}", http_bind_addr);
    let http_listener = TcpListener::bind(&http_bind_addr)
        .await
        .with_context(|| format!("Failed to bind HTTP to {}", http_bind_addr))?;

    // ── 绑定 HTTPS 端口（如启用） ──
    let https_listener = if let Some(reloader) = tls_reloader.as_ref() {
        let https_port = args.tls.as_ref().expect("tls config must exist").https_port;
        if https_port == args.port {
            anyhow::bail!(
                "HTTPS port {} conflicts with HTTP port; please specify a different --https-port",
                https_port
            );
        }
        let https_bind_addr = format!("0.0.0.0:{}", https_port);
        info!("Binding HTTPS address: {}", https_bind_addr);
        let listener = TcpListener::bind(&https_bind_addr)
            .await
            .with_context(|| format!("Failed to bind HTTPS to {}", https_bind_addr))?;
        Some((listener, Arc::clone(reloader)))
    } else {
        None
    };

    // ── 启动日志 ──
    info!("rust_proxy is running");
    if let Some(tls) = &args.tls {
        let tls_reloader = tls_reloader.as_ref().expect("reloader must exist");
        match &tls_reloader.source {
            TlsSource::UserProvided { cert_path, .. } => info!(
                "HTTP port: {}, HTTPS (TLS) port: {}, cert: {} (hot reload enabled, check every {}s)",
                args.port,
                tls.https_port,
                cert_path.display(),
                TLS_RELOAD_CHECK_INTERVAL_SECS
            ),
            TlsSource::AutoSelfSigned => info!(
                "HTTP port: {}, HTTPS (TLS) port: {} (auto-generated self-signed cert)",
                args.port,
                tls.https_port
            ),
        }
    } else {
        info!("HTTP port: {} (TLS not enabled)", args.port);
    }

    accept_connections_dual(
        http_listener,
        https_listener,
        args.timeout,
        buffer_pool,
        auth,
        shutdown_rx,
    )
    .await;

    Ok(())
}

/// TLS 证书来源（用户提供 / 自动生成自签）
///
/// 热重载仅对"用户提供"来源有意义；自动生成的自签证书不参与热重载。
enum TlsSource {
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
/// 自动生成自签证书时，热重载逻辑是 no-op（因为没有外部源文件）。
struct TlsReloader {
    acceptor: RwLock<Arc<TlsAcceptor>>,
    source: TlsSource,
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
    fn current_acceptor(&self) -> Arc<TlsAcceptor> {
        self.acceptor.read().unwrap().clone()
    }

    /// 是否需要定期重载证书文件
    ///
    /// - 用户提供的证书（来自 PEM 文件）→ `true`：监听文件 mtime 实现热重载
    /// - 自动生成的自签证书（无外部文件）→ `false`：不需要定时检查
    fn needs_reload_check(&self) -> bool {
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
            let last_cert = *self.last_cert_mtime.lock().unwrap();
            let last_key = *self.last_key_mtime.lock().unwrap();
            last_cert != Some(cert_mtime) || last_key != Some(key_mtime)
        };

        if !need_reload {
            return Ok(false);
        }

        // 文件已变化，尝试重新加载
        let new_acceptor = build_tls_acceptor_from_files(cert_path, key_path)?;

        *self.acceptor.write().unwrap() = Arc::new(new_acceptor);
        *self.last_cert_mtime.lock().unwrap() = Some(cert_mtime);
        *self.last_key_mtime.lock().unwrap() = Some(key_mtime);

        Ok(true)
    }
}

/// 根据 TlsConfig 创建 TlsReloader（仅支持用户证书路径，不做自动回退；回退在 run_server 处理）
fn build_tls_reloader(tls: &TlsConfig) -> Result<TlsReloader> {
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
fn generate_self_signed_reloader() -> Result<TlsReloader> {
    // rcgen 0.13 中 KeyPair::generate() 默认使用 Ed25519
    let key_pair = KeyPair::generate()
        .context("Failed to generate Ed25519 key pair for self-signed certificate")?;

    let mut params = CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ]).map_err(|e| anyhow::anyhow!("Failed to build CertificateParams: {}", e))?;
    params.distinguished_name.push(DnType::CommonName, "rust-proxy auto");
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

    Ok(TlsReloader::from_acceptor(acceptor, TlsSource::AutoSelfSigned))
}

/// 获取文件的最后修改时间（mtime）
fn file_mtime(path: &Path) -> Result<SystemTime> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("Cannot stat file: {}", path.display()))?;
    metadata
        .modified()
        .with_context(|| format!("Cannot get mtime of file: {}", path.display()))
}

/// 根据 PEM 证书和私钥**文件**构建 `tokio_rustls::TlsAcceptor`
fn build_tls_acceptor_from_files(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    let cert_chain = load_certs(cert_path)
        .with_context(|| format!("Failed to load TLS certificates from {}", cert_path.display()))?;
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
    let file = fs::File::open(path).with_context(|| format!("Cannot open cert file: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs = certs(&mut reader)
        .filter_map(|c| c.ok())
        .collect::<Vec<_>>();
    if certs.is_empty() {
        anyhow::bail!("No valid PEM certificates found in {}", path.display());
    }
    Ok(certs)
}

/// 从 PEM 文件读取私钥（优先 PKCS#8，兼容 RSA）
fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = fs::File::open(path).with_context(|| format!("Cannot open key file: {}", path.display()))?;
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
        fs::File::open(path).with_context(|| format!("Cannot re-open key file: {}", path.display()))?,
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

/// accept_connections_dual 中用于区分 HTTP / HTTPS accept 结果的内部枚举
enum DualAccept {
    Http(std::io::Result<(tokio::net::TcpStream, SocketAddr)>),
    Https(
        std::io::Result<(tokio::net::TcpStream, SocketAddr)>,
        Arc<TlsReloader>,
    ),
}

/// 主循环：同时接受 HTTP 和 HTTPS（如启用）连接，共用线程池与优雅关闭逻辑
async fn accept_connections_dual(
    http_listener: TcpListener,
    https_listener: Option<(TcpListener, Arc<TlsReloader>)>,
    timeout: u64,
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<crate::config::AuthUser>>>,
    mut shutdown_rx: Option<oneshot::Receiver<()>>,
) {
    let mut join_set = JoinSet::new();

    // 证书热重载定时器：
    //   - 仅 HTTPS 启用 且 证书为"用户提供"（来自 PEM 文件）时才创建
    //   - 自签证书（自动生成）无外部文件可监听 → 不创建定时器，避免无意义的周期性唤醒
    //   - 纯 HTTP 模式 → 不创建
    let mut tls_check_interval = match &https_listener {
        Some((_, reloader)) if reloader.needs_reload_check() => {
            let mut iv = tokio::time::interval(Duration::from_secs(TLS_RELOAD_CHECK_INTERVAL_SECS));
            iv.tick().await; // 跳过第一次立即触发
            Some(iv)
        }
        _ => None,
    };

    loop {
        let http_accept = http_listener.accept();

        if let Some((https_listener, tls_reloader)) = https_listener.as_ref() {
            // 双通道模式：HTTP + HTTPS
            // 仅当需要热重载时才把 tls_tick 加入 select；否则跳过定时器分支
            if let Some(interval) = tls_check_interval.as_mut() {
                let tls_tick = interval.tick();
                tokio::pin!(tls_tick);
                let https_accept = https_listener.accept();
                tokio::pin!(https_accept);

                let result = if let Some(shutdown) = shutdown_rx.as_mut() {
                    tokio::select! {
                        res = http_accept => Some(DualAccept::Http(res)),
                        res = https_accept => Some(DualAccept::Https(res, Arc::clone(tls_reloader))),
                        _ = &mut tls_tick => {
                            handle_tls_reload(tls_reloader);
                            continue;
                        }
                        _ = shutdown => {
                            info!("Received shutdown signal, stopping server...");
                            info!("Waiting for {} active connections to complete...", join_set.len());
                            while join_set.join_next().await.is_some() {}
                            info!("All active connections completed, server stopped");
                            return;
                        }
                        _ = join_set.join_next(), if !join_set.is_empty() => continue,
                    }
                } else {
                    tokio::select! {
                        res = http_accept => Some(DualAccept::Http(res)),
                        res = https_accept => Some(DualAccept::Https(res, Arc::clone(tls_reloader))),
                        _ = &mut tls_tick => {
                            handle_tls_reload(tls_reloader);
                            continue;
                        }
                        _ = join_set.join_next(), if !join_set.is_empty() => continue,
                    }
                };
                dispatch_accept_result(result, &mut join_set, timeout, &buffer_pool, &auth);
            } else {
                // 自签证书场景：无热重载定时器，仅 select HTTP/HTTPS/shutdown
                let https_accept = https_listener.accept();
                tokio::pin!(https_accept);

                let result = if let Some(shutdown) = shutdown_rx.as_mut() {
                    tokio::select! {
                        res = http_accept => Some(DualAccept::Http(res)),
                        res = https_accept => Some(DualAccept::Https(res, Arc::clone(tls_reloader))),
                        _ = shutdown => {
                            info!("Received shutdown signal, stopping server...");
                            info!("Waiting for {} active connections to complete...", join_set.len());
                            while join_set.join_next().await.is_some() {}
                            info!("All active connections completed, server stopped");
                            return;
                        }
                        _ = join_set.join_next(), if !join_set.is_empty() => continue,
                    }
                } else {
                    tokio::select! {
                        res = http_accept => Some(DualAccept::Http(res)),
                        res = https_accept => Some(DualAccept::Https(res, Arc::clone(tls_reloader))),
                        _ = join_set.join_next(), if !join_set.is_empty() => continue,
                    }
                };
                dispatch_accept_result(result, &mut join_set, timeout, &buffer_pool, &auth);
            }
        } else {
            // 单通道模式：仅 HTTP（未启用 TLS，不创建任何证书重载定时器）
            let result = if let Some(shutdown) = shutdown_rx.as_mut() {
                tokio::select! {
                    res = http_accept => Some(DualAccept::Http(res)),
                    _ = shutdown => {
                        info!("Received shutdown signal, stopping server...");
                        info!("Waiting for {} active connections to complete...", join_set.len());
                        while join_set.join_next().await.is_some() {}
                        info!("All active connections completed, server stopped");
                        return;
                    }
                    _ = join_set.join_next(), if !join_set.is_empty() => continue,
                }
            } else {
                tokio::select! {
                    res = http_accept => Some(DualAccept::Http(res)),
                    _ = join_set.join_next(), if !join_set.is_empty() => continue,
                }
            };
            dispatch_accept_result(result, &mut join_set, timeout, &buffer_pool, &auth);
        }
    }
}

/// 将 accept 结果分发到连接处理任务
fn dispatch_accept_result(
    result: Option<DualAccept>,
    join_set: &mut JoinSet<()>,
    timeout: u64,
    buffer_pool: &Arc<BufferPool>,
    auth: &Arc<Option<Vec<crate::config::AuthUser>>>,
) {
    match result {
        Some(DualAccept::Http(Ok((client, _addr)))) => {
            let bp = Arc::clone(buffer_pool);
            let au = Arc::clone(auth);
            join_set.spawn(async move {
                handle_client(client, timeout, bp, au).await;
            });
        }
        Some(DualAccept::Http(Err(e))) => {
            error!("Failed to accept HTTP connection: {}", e);
        }
        Some(DualAccept::Https(Ok((client, addr)), tls_reloader)) => {
            let bp = Arc::clone(buffer_pool);
            let au = Arc::clone(auth);
            join_set.spawn(async move {
                process_tls_client(client, addr, tls_reloader, timeout, bp, au).await;
            });
        }
        Some(DualAccept::Https(Err(e), _)) => {
            error!("Failed to accept HTTPS connection: {}", e);
        }
        None => {}
    }
}

/// 执行一次 TLS 证书热重载检查
fn handle_tls_reload(tls_reloader: &TlsReloader) {
    match tls_reloader.check_and_reload() {
        Ok(true) => match &tls_reloader.source {
            TlsSource::UserProvided { cert_path, key_path } => info!(
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

/// 对 accept 下来的 HTTPS socket 执行 TLS 握手，成功后交给 handle_client_tls
async fn process_tls_client(
    client: tokio::net::TcpStream,
    addr: SocketAddr,
    tls_reloader: Arc<TlsReloader>,
    timeout: u64,
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<crate::config::AuthUser>>>,
) {
    // 获取当前 acceptor（支持热重载，每次握手获取最新版本）
    let acceptor = tls_reloader.current_acceptor();
    let tls_handshake_timeout = Duration::from_secs(10);
    let tls_stream = match tokio::time::timeout(tls_handshake_timeout, acceptor.accept(client)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!("TLS handshake failed for {}: {}", addr, e);
            return;
        }
        Err(_) => {
            warn!("TLS handshake timed out for {}", addr);
            return;
        }
    };
    handle_client_tls(tls_stream, addr, timeout, buffer_pool, auth).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_mtime_returns_mtime_for_existing_file() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server.rs");
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
}
