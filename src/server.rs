//! HTTP 代理服务器生命周期管理模块
//!
//! 负责服务器启动、TCP/TLS 监听、连接接受和优雅关闭。
//! 支持同时监听 HTTP 和 HTTPS (TLS) 两个端口。

use anyhow::{Context, Result};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use log::{error, info, warn};
use tokio_rustls::TlsAcceptor;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};

use crate::buffer_pool::BufferPool;
use crate::config::{Args, TlsConfig};
use crate::proxy::{handle_client, handle_client_tls};

/// 启动代理服务器，根据配置可能同时监听 HTTP 和 HTTPS (TLS) 端口
///
/// `shutdown_rx` 用于接收外部关闭信号，实现优雅关闭。传入 `None` 则服务器无限运行。
pub async fn run_server(args: &Args, shutdown_rx: Option<oneshot::Receiver<()>>) -> Result<()> {
    // 初始化缓冲区池，用于零拷贝数据传输
    let buffer_pool = Arc::new(BufferPool::new());
    // 认证用户列表包装为 Arc，零开销地分发给每个连接任务
    let auth = Arc::new(args.auth.clone());

    // 构建 TLS acceptor（如启用）
    let tls_acceptor = if let Some(tls) = &args.tls {
        let acceptor = build_tls_acceptor(tls).with_context(|| {
            format!(
                "Failed to build TLS acceptor (cert={}, key={})",
                tls.cert_path.display(),
                tls.key_path.display()
            )
        })?;
        Some(Arc::new(acceptor))
    } else {
        None
    };

    // 监听 HTTP
    let http_bind_addr = format!("0.0.0.0:{}", args.port);
    info!("Binding HTTP address: {}", http_bind_addr);
    let http_listener = TcpListener::bind(&http_bind_addr)
        .await
        .with_context(|| format!("Failed to bind HTTP to {}", http_bind_addr))?;

    // 如配置 TLS，则额外监听 HTTPS 端口
    let https_listener = if let (Some(acceptor), Some(tls)) = (tls_acceptor.as_ref(), &args.tls) {
        // 端口冲突检测：避免 HTTP 与 HTTPS 端口相同导致语义混乱
        if tls.https_port == args.port {
            anyhow::bail!(
                "HTTPS port {} conflicts with HTTP port; please specify a different --https-port",
                tls.https_port
            );
        }
        let https_bind_addr = format!("0.0.0.0:{}", tls.https_port);
        info!("Binding HTTPS address: {}", https_bind_addr);
        let listener = TcpListener::bind(&https_bind_addr)
            .await
            .with_context(|| format!("Failed to bind HTTPS to {}", https_bind_addr))?;
        Some((listener, Arc::clone(acceptor)))
    } else {
        None
    };

    info!("rust_proxy is running");
    if let Some(tls) = &args.tls {
        info!(
            "HTTP port: {}, HTTPS (TLS) port: {}, cert: {}",
            args.port,
            tls.https_port,
            tls.cert_path.display()
        );
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

/// 根据 TLS 配置构建 `tokio_rustls::TlsAcceptor`
///
/// 从 PEM 文件加载证书链和私钥，配置 rustls ServerConfig。
fn build_tls_acceptor(tls: &TlsConfig) -> Result<TlsAcceptor> {
    let cert_chain = load_certs(&tls.cert_path)
        .with_context(|| format!("Failed to load TLS certificates from {}", tls.cert_path.display()))?;
    let key = load_key(&tls.key_path)
        .with_context(|| format!("Failed to load TLS private key from {}", tls.key_path.display()))?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("Failed to create rustls ServerConfig (invalid cert/key pair)")?;

    // 开启 OCSP stapling 和协议级优化：优先 HTTP/2 兼容的 ALPN（我们走 HTTP/1.1 代理协议即可）
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// 从 PEM 文件读取所有证书（返回 Vec<Certificate>）
fn load_certs(path: &PathBuf) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("Cannot open cert file: {}", path.display()))?;
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
fn load_key(path: &PathBuf) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("Cannot open key file: {}", path.display()))?;
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
        File::open(path).with_context(|| format!("Cannot re-open key file: {}", path.display()))?,
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
        Arc<TlsAcceptor>,
    ),
}

/// 主循环：同时接受 HTTP 和 HTTPS（如启用）连接，共用线程池与优雅关闭逻辑
///
/// `https_listener` 为 `None` 时退化为纯 HTTP 监听，行为与旧版本一致。
async fn accept_connections_dual(
    http_listener: TcpListener,
    https_listener: Option<(TcpListener, Arc<TlsAcceptor>)>,
    timeout: u64,
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<crate::config::AuthUser>>>,
    mut shutdown_rx: Option<oneshot::Receiver<()>>,
) {
    let mut join_set = JoinSet::new();

    loop {
        let http_accept = http_listener.accept();

        let result = if let Some((https_listener, tls_acceptor)) = https_listener.as_ref() {
            // 双通道模式：HTTP + HTTPS
            let https_accept = https_listener.accept();
            tokio::pin!(https_accept);

            if let Some(shutdown) = shutdown_rx.as_mut() {
                tokio::select! {
                    res = http_accept => Some(DualAccept::Http(res)),
                    res = https_accept => Some(DualAccept::Https(res, Arc::clone(tls_acceptor))),
                    _ = shutdown => {
                        info!("Received shutdown signal, stopping server...");
                        info!("Waiting for {} active connections to complete...", join_set.len());
                        while join_set.join_next().await.is_some() {}
                        info!("All active connections completed, server stopped");
                        return;
                    }
                    _ = join_set.join_next(), if !join_set.is_empty() => None,
                }
            } else {
                tokio::select! {
                    res = http_accept => Some(DualAccept::Http(res)),
                    res = https_accept => Some(DualAccept::Https(res, Arc::clone(tls_acceptor))),
                    _ = join_set.join_next(), if !join_set.is_empty() => None,
                }
            }
        } else {
            // 单通道模式：仅 HTTP
            if let Some(shutdown) = shutdown_rx.as_mut() {
                tokio::select! {
                    res = http_accept => Some(DualAccept::Http(res)),
                    _ = shutdown => {
                        info!("Received shutdown signal, stopping server...");
                        info!("Waiting for {} active connections to complete...", join_set.len());
                        while join_set.join_next().await.is_some() {}
                        info!("All active connections completed, server stopped");
                        return;
                    }
                    _ = join_set.join_next(), if !join_set.is_empty() => None,
                }
            } else {
                tokio::select! {
                    res = http_accept => Some(DualAccept::Http(res)),
                    _ = join_set.join_next(), if !join_set.is_empty() => None,
                }
            }
        };

        match result {
            Some(DualAccept::Http(Ok((client, _addr)))) => {
                let bp = Arc::clone(&buffer_pool);
                let au = Arc::clone(&auth);
                join_set.spawn(async move {
                    // handle_client 内部自行获取 peer_addr，此处不需要 addr
                    handle_client(client, timeout, bp, au).await;
                });
            }
            Some(DualAccept::Http(Err(e))) => {
                error!("Failed to accept HTTP connection: {}", e);
            }
            Some(DualAccept::Https(Ok((client, addr)), tls_acceptor)) => {
                let bp = Arc::clone(&buffer_pool);
                let au = Arc::clone(&auth);
                join_set.spawn(async move {
                    process_tls_client(client, addr, tls_acceptor, timeout, bp, au).await;
                });
            }
            Some(DualAccept::Https(Err(e), _)) => {
                error!("Failed to accept HTTPS connection: {}", e);
            }
            None => {}
        }
    }
}

/// 对 accept 下来的 HTTPS socket 执行 TLS 握手，成功后交给 handle_client_tls
async fn process_tls_client(
    client: tokio::net::TcpStream,
    addr: SocketAddr,
    tls_acceptor: Arc<TlsAcceptor>,
    timeout: u64,
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<crate::config::AuthUser>>>,
) {
    // TLS 握手独立超时，避免恶意慢握手拖垮代理
    let tls_handshake_timeout = Duration::from_secs(10);
    let tls_stream = match tokio::time::timeout(tls_handshake_timeout, tls_acceptor.accept(client)).await {
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
