//! HTTP 代理服务器生命周期管理模块
//!
//! 负责服务器启动、TCP/TLS 监听、连接接受和优雅关闭。
//! 支持同时监听 HTTP 和 HTTPS (TLS) 两个端口。
//!
//! 本模块只保留"accept → 分派 → 处理"这条主干，两个子系统已拆为独立模块：
//! - 证书体系与热重载：[`crate::tls`]
//! - PROXY Protocol 解析：[`crate::proxy_protocol`]
//!
//! TLS 启用语义（严格）：
//! 1. 用户**显式指定了 `https_port`**（命令行 `--https-port` 或配置文件 `https_port`）
//!    → 必须启用 HTTPS：
//!    - 若同时提供了合法 cert+key，使用用户证书，支持热重载
//!    - 若 cert+key 缺失或加载失败，自动生成**10 年有效期自签证书**并输出 warn 日志
//!      （自签证书不参与定期重载，因为无外部源文件可监听）
//! 2. 未指定 `https_port` → **不启用 HTTPS**（即使配置了 cert+key 也忽略）

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Semaphore};
use tokio::task::JoinSet;

use crate::buffer_pool::BufferPool;
use crate::config::{Args, AuthUser, ProxyProtocolMode};
use crate::io::PrefixedStream;
use crate::path_proxy::PathProxyConfig;
use crate::proxy::{handle_client, handle_client_with_addr};
use crate::proxy_protocol::{parse_proxy_protocol, PpDetectResult, PpParseMode};
use crate::tls::{
    build_tls_reloader, generate_self_signed_reloader, handle_tls_reload, TlsReloader, TlsSource,
    SELF_SIGNED_VALIDITY_YEARS, TLS_RELOAD_CHECK_INTERVAL_SECS,
};

/// 最大并发连接数（HTTP + HTTPS 合计）
///
/// 超出上限后新连接直接关闭（不排队），防止恶意批量连接打满文件句柄与内存。
const MAX_CONCURRENT_CONNECTIONS: usize = 4096;

/// 启动代理服务器，根据配置可能同时监听 HTTP 和 HTTPS (TLS) 端口
pub async fn run_server(args: &Args, shutdown_rx: Option<oneshot::Receiver<()>>) -> Result<()> {
    let buffer_pool = Arc::new(BufferPool::new());
    let auth = Arc::new(args.auth.clone());

    // ── 路径前缀直连模式（可选）──
    // 前缀合法性在此校验（配置层无法记录日志）；非法前缀直接启动失败，避免静默降级。
    let path_proxy = match &args.path_proxy_prefix {
        Some(prefix) => {
            let cfg = PathProxyConfig::new(
                prefix,
                args.path_proxy_insecure_tls,
                args.path_proxy_rewrite_location,
            )?;
            info!(
                "Path-prefix direct proxy enabled: /{}/http://host/path and /{}/https://host/path \
                 (insecure_tls={}, rewrite_location={})",
                cfg.prefix(),
                cfg.prefix(),
                cfg.insecure_tls,
                cfg.rewrite_location
            );
            if args.auth.is_none() {
                warn!(
                    "Path-prefix direct proxy is open to anyone reaching this port \
                     (no [[auth]] configured); consider [[auth]] to avoid being used as an open relay"
                );
            }
            Some(cfg)
        }
        None => None,
    };
    let path_proxy = Arc::new(path_proxy);

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

    // ── 校验：HTTP 与 HTTPS 至少启用其一 ──
    if args.port.is_none() && tls_reloader.is_none() {
        anyhow::bail!(
            "Neither HTTP nor HTTPS proxy is enabled. Specify --port and/or --https-port."
        );
    }

    // ── 端口冲突检测（仅在两者都启用时检查） ──
    if let (Some(http_port), Some(tls)) = (args.port, args.tls.as_ref()) {
        if http_port == tls.https_port {
            anyhow::bail!(
                "HTTP port {} conflicts with HTTPS port {}; please specify different ports",
                http_port,
                tls.https_port
            );
        }
    }

    // ── 绑定 HTTP 端口（如启用） ──
    let http_listener = if let Some(port) = args.port {
        let http_bind_addr = format!("0.0.0.0:{}", port);
        info!("Binding HTTP address: {}", http_bind_addr);
        Some(
            TcpListener::bind(&http_bind_addr)
                .await
                .with_context(|| format!("Failed to bind HTTP to {}", http_bind_addr))?,
        )
    } else {
        info!("HTTP proxy disabled (only --https-port was specified)");
        None
    };

    // ── 绑定 HTTPS 端口（如启用） ──
    let https_listener = if let Some(reloader) = tls_reloader.as_ref() {
        let https_port = args.tls.as_ref().expect("tls config must exist").https_port;
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
    match (args.port, &args.tls) {
        (Some(http_port), Some(tls)) => {
            let tls_reloader = tls_reloader.as_ref().expect("reloader must exist");
            match &tls_reloader.source {
                TlsSource::UserProvided { cert_path, .. } => info!(
                    "HTTP port: {}, HTTPS (TLS) port: {}, cert: {} (hot reload enabled, check every {}s)",
                    http_port,
                    tls.https_port,
                    cert_path.display(),
                    TLS_RELOAD_CHECK_INTERVAL_SECS
                ),
                TlsSource::AutoSelfSigned => info!(
                    "HTTP port: {}, HTTPS (TLS) port: {} (auto-generated self-signed cert, \
                    {} years validity). NOT recommended for production use!",
                    http_port,
                    tls.https_port,
                    SELF_SIGNED_VALIDITY_YEARS
                ),
            }
        }
        (Some(http_port), None) => info!("HTTP port: {} (TLS not enabled)", http_port),
        (None, Some(tls)) => {
            let tls_reloader = tls_reloader.as_ref().expect("reloader must exist");
            match &tls_reloader.source {
                TlsSource::UserProvided { cert_path, .. } => info!(
                    "HTTP disabled, HTTPS (TLS) port: {}, cert: {} (hot reload enabled, check every {}s)",
                    tls.https_port,
                    cert_path.display(),
                    TLS_RELOAD_CHECK_INTERVAL_SECS
                ),
                TlsSource::AutoSelfSigned => info!(
                    "HTTP disabled, HTTPS (TLS) port: {} (auto-generated self-signed cert, \
                    {} years validity). NOT recommended for production use!",
                    tls.https_port,
                    SELF_SIGNED_VALIDITY_YEARS
                ),
            }
        }
        (None, None) => unreachable!("validated above: at least one listener is enabled"),
    }

    // 分别展示 HTTP/HTTPS 两个端口实际使用的 PROXY Protocol 模式
    let show_mode = |m: ProxyProtocolMode| {
        if m == ProxyProtocolMode::Disable {
            "disable".to_string()
        } else {
            format!("{} (v1/v2 auto-detect)", m)
        }
    };
    info!(
        "PROXY Protocol: http={} https={}",
        show_mode(args.http_proxy_protocol),
        show_mode(args.https_proxy_protocol),
    );
    if !args.proxy_protocol_trusted_ips.is_empty() {
        info!(
            "PROXY Protocol trusted IPs: {:?}",
            args.proxy_protocol_trusted_ips
        );
    } else {
        info!("PROXY Protocol: no trusted IP whitelist (accepting from all sources)");
    }

    accept_connections_dual(
        http_listener,
        https_listener,
        args.timeout,
        buffer_pool,
        auth,
        path_proxy,
        args.http_proxy_protocol,
        args.https_proxy_protocol,
        Arc::new(args.proxy_protocol_trusted_ips.clone()),
        shutdown_rx,
    )
    .await;

    Ok(())
}

/// accept_connections_dual 中用于区分 HTTP / HTTPS accept 结果的内部枚举
enum DualAccept {
    Http(std::io::Result<(tokio::net::TcpStream, SocketAddr)>),
    Https(
        std::io::Result<(tokio::net::TcpStream, SocketAddr)>,
        Arc<TlsReloader>,
    ),
}

/// 主循环：根据启用的 listener（HTTP/HTTPS）接受连接，共用线程池与优雅关闭逻辑
///
/// 支持三种模式：
///   - 仅 HTTP（`http_listener=Some, https_listener=None`）
///   - 仅 HTTPS（`http_listener=None, https_listener=Some`）
///   - HTTP + HTTPS 双通道（两者都 `Some`）
#[allow(clippy::too_many_arguments)]
async fn accept_connections_dual(
    http_listener: Option<TcpListener>,
    https_listener: Option<(TcpListener, Arc<TlsReloader>)>,
    timeout: u64,
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<AuthUser>>>,
    path_proxy: Arc<Option<PathProxyConfig>>,
    http_proxy_protocol: ProxyProtocolMode,
    https_proxy_protocol: ProxyProtocolMode,
    proxy_protocol_trusted_ips: Arc<Vec<std::net::IpAddr>>,
    mut shutdown_rx: Option<oneshot::Receiver<()>>,
) {
    let mut join_set = JoinSet::new();
    // 并发连接信号量：超出上限的连接直接拒绝（关闭），防止 DoS
    let conn_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    if http_listener.is_none() && https_listener.is_none() {
        error!("No listeners enabled, server cannot accept connections");
        return;
    }

    // 提前克隆 HTTPS reloader 引用，供热重载 tick 触发时使用
    let https_reloader: Option<Arc<TlsReloader>> =
        https_listener.as_ref().map(|(_, r)| Arc::clone(r));

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
        // 每轮循环根据启用的 listener 构造 accept future；
        // 未启用的 listener 用 pending() 占位，select 不会选中它的分支。
        // 注意：先计算启用标志（避免后续对 tls_check_interval 的多重借用冲突）
        let http_enabled = http_listener.is_some();
        let https_enabled = https_listener.is_some();
        let tick_enabled = tls_check_interval.is_some();

        let http_accept = async {
            match &http_listener {
                Some(l) => l.accept().await,
                None => std::future::pending::<std::io::Result<(tokio::net::TcpStream, SocketAddr)>>().await,
            }
        };
        let https_accept = async {
            match &https_listener {
                Some((l, _)) => l.accept().await,
                None => std::future::pending::<std::io::Result<(tokio::net::TcpStream, SocketAddr)>>().await,
            }
        };
        let tls_tick = async {
            match &mut tls_check_interval {
                Some(iv) => iv.tick().await,
                None => std::future::pending::<tokio::time::Instant>().await,
            }
        };
        tokio::pin!(http_accept, https_accept, tls_tick);

        // HTTP/HTTPS 启用情况决定 select 分支是否参与（用条件守卫）

        let result: Option<DualAccept> = if let Some(shutdown) = shutdown_rx.as_mut() {
            tokio::select! {
                res = &mut http_accept, if http_enabled => Some(DualAccept::Http(res)),
                res = &mut https_accept, if https_enabled => {
                    let (_, reloader) = https_listener.as_ref().expect("https_accept fired means https_listener exists");
                    Some(DualAccept::Https(res, Arc::clone(reloader)))
                }
                _ = &mut tls_tick, if tick_enabled => {
                    handle_tls_reload(https_reloader.as_ref().expect("tick fired means reloader exists"));
                    None
                }
                _ = shutdown => {
                    drain_joinset(&mut join_set).await;
                    return;
                }
                _ = join_set.join_next(), if !join_set.is_empty() => None,
            }
        } else {
            tokio::select! {
                res = &mut http_accept, if http_enabled => Some(DualAccept::Http(res)),
                res = &mut https_accept, if https_enabled => {
                    let (_, reloader) = https_listener.as_ref().expect("https_accept fired means https_listener exists");
                    Some(DualAccept::Https(res, Arc::clone(reloader)))
                }
                _ = &mut tls_tick, if tick_enabled => {
                    handle_tls_reload(https_reloader.as_ref().expect("tick fired means reloader exists"));
                    None
                }
                _ = join_set.join_next(), if !join_set.is_empty() => None,
            }
        };

        if let Some(da) = result {
            dispatch_accept_result(
                Some(da),
                &mut join_set,
                timeout,
                &buffer_pool,
                &auth,
                &path_proxy,
                http_proxy_protocol,
                https_proxy_protocol,
                &proxy_protocol_trusted_ips,
                &conn_semaphore,
            );
        }
        // result == None：定时器触发或 task 完成，直接进入下一轮循环
    }
}

/// 等待所有活跃连接完成（用于优雅关闭）
async fn drain_joinset(join_set: &mut JoinSet<()>) {
    info!("Received shutdown signal, stopping server...");
    info!("Waiting for {} active connections to complete...", join_set.len());
    while join_set.join_next().await.is_some() {}
    info!("All active connections completed, server stopped");
}

/// 尝试获取一个并发连接许可。
///
/// 超出 [`MAX_CONCURRENT_CONNECTIONS`] 上限时返回 `None` 并关闭该连接（不排队），
/// 防止恶意批量连接耗尽资源。返回的许可由处理任务持有，任务结束时自动归还。
fn try_acquire_conn_permit(
    semaphore: &Arc<Semaphore>,
    addr: &SocketAddr,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    match semaphore.clone().try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            warn!(
                "Connection limit reached ({}), rejecting connection from {}",
                MAX_CONCURRENT_CONNECTIONS, addr
            );
            None
        }
    }
}

/// 将 accept 结果分发到连接处理任务
#[allow(clippy::too_many_arguments)]
fn dispatch_accept_result(
    result: Option<DualAccept>,
    join_set: &mut JoinSet<()>,
    timeout: u64,
    buffer_pool: &Arc<BufferPool>,
    auth: &Arc<Option<Vec<AuthUser>>>,
    path_proxy: &Arc<Option<PathProxyConfig>>,
    http_proxy_protocol: ProxyProtocolMode,
    https_proxy_protocol: ProxyProtocolMode,
    proxy_protocol_trusted_ips: &Arc<Vec<std::net::IpAddr>>,
    conn_semaphore: &Arc<Semaphore>,
) {
    match result {
        Some(DualAccept::Http(Ok((client, addr)))) => {
            // 超出并发上限：关闭连接并跳过
            let Some(permit) = try_acquire_conn_permit(conn_semaphore, &addr) else {
                return;
            };
            let bp = Arc::clone(buffer_pool);
            let au = Arc::clone(auth);
            let pp = Arc::clone(path_proxy);
            let t1 = Arc::clone(proxy_protocol_trusted_ips);
            let pp_mode = http_proxy_protocol;
            join_set.spawn(async move {
                // 许可在任务整个生命周期内持有，结束后自动归还信号量
                let _permit = permit;
                match pp_mode {
                    ProxyProtocolMode::Disable => {
                        handle_client(client, timeout, bp, au, pp).await;
                    }
                    ProxyProtocolMode::Auto | ProxyProtocolMode::Require => {
                        process_http_client_pp(client, addr, timeout, bp, au, pp, t1, pp_mode).await;
                    }
                }
            });
        }
        Some(DualAccept::Http(Err(e))) => {
            error!("Failed to accept HTTP connection: {}", e);
        }
        Some(DualAccept::Https(Ok((client, addr)), tls_reloader)) => {
            // 超出并发上限：关闭连接并跳过
            let Some(permit) = try_acquire_conn_permit(conn_semaphore, &addr) else {
                return;
            };
            let bp = Arc::clone(buffer_pool);
            let au = Arc::clone(auth);
            let pp = Arc::clone(path_proxy);
            let t2 = Arc::clone(proxy_protocol_trusted_ips);
            let pp_mode = https_proxy_protocol;
            join_set.spawn(async move {
                // 许可在任务整个生命周期内持有，结束后自动归还信号量
                let _permit = permit;
                match pp_mode {
                    ProxyProtocolMode::Disable => {
                        process_tls_client(client, addr, tls_reloader, timeout, bp, au, pp).await;
                    }
                    ProxyProtocolMode::Auto | ProxyProtocolMode::Require => {
                        process_tls_client_pp(
                            client,
                            addr,
                            tls_reloader,
                            timeout,
                            bp,
                            au,
                            pp,
                            t2,
                            pp_mode,
                        )
                        .await;
                    }
                }
            });
        }
        Some(DualAccept::Https(Err(e), _)) => {
            error!("Failed to accept HTTPS connection: {}", e);
        }
        None => {}
    }
}

/// PROXY Protocol 启用时的 HTTP 连接处理：
/// 先检查 peer IP 是否在可信列表中，再按模式解析/自动检测 PROXY Protocol 头
#[allow(clippy::too_many_arguments)]
async fn process_http_client_pp(
    client: tokio::net::TcpStream,
    fallback_addr: SocketAddr,
    timeout: u64,
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<AuthUser>>>,
    path_proxy: Arc<Option<PathProxyConfig>>,
    trusted_ips: Arc<Vec<std::net::IpAddr>>,
    pp_mode: ProxyProtocolMode,
) {
    // IP 白名单检查：若配置了可信列表且源 IP 不在列表中，跳过 PROXY Protocol 解析
    if !trusted_ips.is_empty() && !trusted_ips.contains(&fallback_addr.ip()) {
        debug!(
            "PROXY Protocol: skipping for untrusted source IP {} (trusted: {:?})",
            fallback_addr.ip(),
            trusted_ips
        );
        handle_client(client, timeout, buffer_pool, auth, path_proxy).await;
        return;
    }

    // Disable 在类型层无法表示为解析模式；若真被传入（分派逻辑被改坏），
    // 保守回退为"当作直连 HTTP 处理"而不是 panic。
    let Ok(internal_mode) = PpParseMode::try_from(pp_mode) else {
        warn!(
            "PROXY Protocol: unexpected mode {} for HTTP listener, treating as plain HTTP",
            pp_mode
        );
        handle_client(client, timeout, buffer_pool, auth, path_proxy).await;
        return;
    };

    let (real_addr, stream) = match parse_proxy_protocol(client, internal_mode).await {
        Ok(PpDetectResult::Parsed(real_opt, stream)) => {
            let real_addr = real_opt.unwrap_or(fallback_addr);
            debug!(
                "PROXY Protocol({}): {} -> real client {}",
                pp_mode, fallback_addr, real_addr
            );
            (real_addr, stream)
        }
        Ok(PpDetectResult::NotMatched(prefix, tcp)) => {
            // Auto 模式：不匹配 → 回退，携带 prefix 供 HTTP 请求头解析使用。
            // handle_client 的 read_request_head 会多次读取直到找到头结束符，
            // 因此前缀字节不会丢失。
            debug!(
                "PROXY Protocol(Auto): no signature detected from {}, fallback to plain HTTP",
                fallback_addr
            );
            (fallback_addr, PrefixedStream::new(prefix, tcp))
        }
        Err(e) => {
            if matches!(pp_mode, ProxyProtocolMode::Require) {
                warn!(
                    "PROXY Protocol(Require) parse failed from {}: {}",
                    fallback_addr, e
                );
            } else {
                debug!(
                    "PROXY Protocol(Auto) parse failed from {}: {} (signature matched but malformed, dropping)",
                    fallback_addr, e
                );
            }
            return;
        }
    };

    handle_client_with_addr(stream, real_addr, timeout, buffer_pool, auth, path_proxy).await;
}

/// PROXY Protocol 启用时的 HTTPS 连接处理：
/// 先检查 peer IP 是否在可信列表中，再按模式解析/自动检测 PROXY Protocol 头
#[allow(clippy::too_many_arguments)]
async fn process_tls_client_pp(
    client: tokio::net::TcpStream,
    fallback_addr: SocketAddr,
    tls_reloader: Arc<TlsReloader>,
    timeout: u64,
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<AuthUser>>>,
    path_proxy: Arc<Option<PathProxyConfig>>,
    trusted_ips: Arc<Vec<std::net::IpAddr>>,
    pp_mode: ProxyProtocolMode,
) {
    // IP 白名单检查：若配置了可信列表且源 IP 不在列表中，跳过 PROXY Protocol 解析
    if !trusted_ips.is_empty() && !trusted_ips.contains(&fallback_addr.ip()) {
        debug!(
            "PROXY Protocol: skipping for untrusted source IP {} (trusted: {:?})",
            fallback_addr.ip(),
            trusted_ips
        );
        process_tls_client(
            client,
            fallback_addr,
            tls_reloader,
            timeout,
            buffer_pool,
            auth,
            path_proxy,
        )
        .await;
        return;
    }

    // 同 process_http_client_pp：Disable 不应到此，保守回退为"不做 PROXY 解析直接握手"
    let Ok(internal_mode) = PpParseMode::try_from(pp_mode) else {
        warn!(
            "PROXY Protocol: unexpected mode {} for HTTPS listener, treating as plain TLS",
            pp_mode
        );
        process_tls_client(
            client,
            fallback_addr,
            tls_reloader,
            timeout,
            buffer_pool,
            auth,
            path_proxy,
        )
        .await;
        return;
    };

    let (real_addr, stream) = match parse_proxy_protocol(client, internal_mode).await {
        Ok(PpDetectResult::Parsed(real_opt, stream)) => {
            let real_addr = real_opt.unwrap_or(fallback_addr);
            debug!(
                "PROXY Protocol({}): {} -> real client {}",
                pp_mode, fallback_addr, real_addr
            );
            (real_addr, stream)
        }
        Ok(PpDetectResult::NotMatched(prefix, tcp)) => {
            // Auto 模式：不匹配 → 回退，携带 prefix 供 TLS ClientHello 使用
            debug!(
                "PROXY Protocol(Auto): no signature detected from {}, fallback to plain TLS",
                fallback_addr
            );
            (fallback_addr, PrefixedStream::new(prefix, tcp))
        }
        Err(e) => {
            if matches!(pp_mode, ProxyProtocolMode::Require) {
                warn!(
                    "PROXY Protocol(Require) parse failed from {}: {}",
                    fallback_addr, e
                );
            } else {
                debug!(
                    "PROXY Protocol(Auto) parse failed from {}: {} (signature matched but malformed, dropping)",
                    fallback_addr, e
                );
            }
            return;
        }
    };

    // TLS 握手（与 process_tls_client 逻辑一致，但流类型为 PrefixedStream<TcpStream>）
    let acceptor = tls_reloader.current_acceptor();
    let tls_handshake_timeout = Duration::from_secs(10);
    let tls_stream = match tokio::time::timeout(tls_handshake_timeout, acceptor.accept(stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!("TLS handshake failed for {}: {}", real_addr, e);
            return;
        }
        Err(_) => {
            warn!("TLS handshake timed out for {}", real_addr);
            return;
        }
    };
    handle_client_with_addr(tls_stream, real_addr, timeout, buffer_pool, auth, path_proxy).await;
}

/// 对 accept 下来的 HTTPS socket 执行 TLS 握手，成功后交给 handle_client_with_addr
async fn process_tls_client(
    client: tokio::net::TcpStream,
    addr: SocketAddr,
    tls_reloader: Arc<TlsReloader>,
    timeout: u64,
    buffer_pool: Arc<BufferPool>,
    auth: Arc<Option<Vec<AuthUser>>>,
    path_proxy: Arc<Option<PathProxyConfig>>,
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
    handle_client_with_addr(tls_stream, addr, timeout, buffer_pool, auth, path_proxy).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conn_permit_exhaustion_rejects_connections() {
        let sem = Arc::new(Semaphore::new(2));
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // 前 2 个连接可获取许可
        let p1 = try_acquire_conn_permit(&sem, &addr).expect("first permit");
        let p2 = try_acquire_conn_permit(&sem, &addr).expect("second permit");

        // 第 3 个连接被拒绝（信号量耗尽）
        assert!(
            try_acquire_conn_permit(&sem, &addr).is_none(),
            "third connection must be rejected when the semaphore is exhausted"
        );

        // 释放一个许可后新连接可重新进入
        drop(p1);
        let p3 = try_acquire_conn_permit(&sem, &addr).expect("permit after release");
        drop(p2);
        drop(p3);
    }
}
