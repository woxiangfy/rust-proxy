//! Unix 服务：systemd / 平台原生 manager 安装与 `--run-as-service` 分派
//!
//! Linux 用 systemd 专用 manager：`<dyn ServiceManager>::native()` 在容器、非 systemd
//! 发行版里会退化成 sysv 或直接探测失败，显式指定可以把"装到哪"变成确定行为。
//! 其余 Unix（macOS / BSD）仍走平台原生探测。
//!
//! `run_as_service` 由外部服务管理器拉起，没有终端也没有信号处理器，
//! 因此不注册关停信号：SIGTERM 默认动作即可让进程退出。

use anyhow::{Context, Result};
use log::{error, info};
use service_manager::{ServiceInstallCtx, ServiceManager};

use crate::config::Args;
use crate::logging;
use crate::server;

use super::parse_service_args;

/// 安装服务（平台 manager 的选择见模块注释）
pub(super) fn install(ctx: ServiceInstallCtx) -> Result<()> {
    #[cfg(target_os = "linux")]
    let manager: Box<dyn ServiceManager> =
        Box::new(service_manager::SystemdServiceManager::system());

    #[cfg(not(target_os = "linux"))]
    let manager: Box<dyn ServiceManager> =
        <dyn ServiceManager>::native().context("Failed to detect service management platform")?;

    manager.install(ctx).context("Failed to install service")?;
    Ok(())
}

/// 服务进程入口（`--run-as-service` 分支）
pub fn run_as_service() -> Result<()> {
    let start_args = parse_service_args();
    let args = Args::from_run_args(&start_args);

    // 服务模式下没有终端，日志必须落文件；未配置时放在可执行文件旁边
    let effective_log_file = if args.log_file.is_some() {
        args.log_file.clone()
    } else {
        std::env::current_exe().ok().map(|mut path| {
            path.set_file_name("proxy.log");
            path
        })
    };

    logging::setup_logging(&effective_log_file, &args.log_level)
        .context("Failed to setup logging")?;

    match (args.port, args.tls.as_ref().map(|t| t.https_port)) {
        (Some(http_port), Some(https_port)) => info!(
            "Rust Proxy Service starting... HTTP port: {}, HTTPS port: {}",
            http_port, https_port
        ),
        (Some(http_port), None) => info!("Rust Proxy Service starting... HTTP port: {}", http_port),
        (None, Some(https_port)) => info!(
            "Rust Proxy Service starting... HTTPS port: {} (HTTP disabled)",
            https_port
        ),
        (None, None) => info!("Rust Proxy Service starting... (no listener enabled)"),
    }

    let runtime = if args.multi_thread {
        tokio::runtime::Runtime::new().context("Failed to create multi-thread Tokio runtime")?
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create single-thread Tokio runtime")?
    };

    if let Err(e) = runtime.block_on(server::run_server(&args, None)) {
        error!("Server error: {}", e);
        return Err(e);
    }

    Ok(())
}
