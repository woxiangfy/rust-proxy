//! Windows 服务：SCM 安装与 `--run-as-service` 分派
//!
//! `windows_service` crate 的 API 是"注册控制处理器 + 阻塞在 dispatcher"的模型，
//! 与 Unix 的"启动后等信号"完全不同，因此单独成文件；本模块只在 `cfg(windows)`
//! 下参与编译。
//!
//! 服务生命周期：`StartPending` → `Running` → `StopPending` → `Stopped`。
//! 收到 `Stop` / `Shutdown` 控制信号时通过 oneshot 通知 [`server::run_server`]
//! 进入优雅关停，随后才把状态置为 `Stopped`，避免 SCM 认为服务"卡死"。

use anyhow::{Context, Result};
use log::{error, info};
use service_manager::{ServiceInstallCtx, ServiceManager};
use std::ffi::OsString;
use std::sync::Mutex;
use tokio::sync::oneshot;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use crate::config::Args;
use crate::logging;
use crate::server;

use super::{parse_service_args, DEFAULT_SERVICE_DESCRIPTION};

/// SCM 里的服务名与 `ServiceLabel` 必须一致，否则 install 之后 status / stop 找不到
const SERVICE_NAME: &str = super::SERVICE_LABEL;

/// 关停信号发送端：控制处理器运行在 SCM 的线程上，只能通过静态变量把信号交给主线程
static SHUTDOWN_TX: Mutex<Option<oneshot::Sender<()>>> = Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

/// 安装服务，并补一条 `sc description`
///
/// `service-manager` 的 `ServiceInstallCtx` 未暴露描述字段，而 SCM 原生支持，
/// 因此装完之后再补一条 `sc` 命令。失败只告警不中断：描述属于展示信息，
/// 服务本身已经装好，不该因为这一步失败而报错。
pub(super) fn install(ctx: ServiceInstallCtx) -> Result<()> {
    let manager =
        <dyn ServiceManager>::native().context("Failed to detect service management platform")?;

    manager.install(ctx).context("Failed to install service")?;
    set_service_description(DEFAULT_SERVICE_DESCRIPTION);
    Ok(())
}

fn set_service_description(description: &str) {
    match std::process::Command::new("sc")
        .args(["description", SERVICE_NAME, description])
        .output()
    {
        Ok(o) if o.status.success() => {}
        Ok(o) => println!(
            "Warning: Failed to set service description: {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => println!("Warning: Failed to run sc: {}", e),
    }
}

/// 把当前进程交给 SCM 的 dispatcher（`--run-as-service` 分支的入口）
pub fn run_as_service() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("Failed to start service dispatcher")?;
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!("Service error: {}", e);
    }
}

fn run_service() -> Result<()> {
    let start_args = parse_service_args()?;
    let args = Args::from_run_args(&start_args)?;

    // 服务模式下没有终端，日志必须落文件；未配置时放在可执行文件旁边
    let log_file = args.log_file.clone().unwrap_or_else(|| {
        let mut path = std::env::current_exe().unwrap();
        path.set_file_name("proxy.log");
        path
    });

    logging::setup_logging(&Some(log_file.clone()), &args.log_level)
        .context("Failed to setup logging")?;

    info!("Rust Proxy Service starting...");

    let status_handle = service_control_handler::register(SERVICE_NAME, handle_control)
        .context("Failed to register service control handler")?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::from_secs(2),
        process_id: None,
    })?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    // 锁 poison 容错：服务生命周期的锁，panic 后继续使用内部状态
    let mut guard = SHUTDOWN_TX.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(shutdown_tx);
    drop(guard);

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    let runtime = if args.multi_thread {
        tokio::runtime::Runtime::new().context("Failed to create multi-thread Tokio runtime")?
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create single-thread Tokio runtime")?
    };
    runtime.block_on(async {
        if let Err(e) = server::run_server(&args, Some(shutdown_rx)).await {
            error!("Server error: {}", e);
        }
    });

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::from_secs(2),
        process_id: None,
    })?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    info!("Rust Proxy Service stopped");
    Ok(())
}

fn handle_control(control: ServiceControl) -> ServiceControlHandlerResult {
    match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            info!(
                "Received {} control signal",
                if control == ServiceControl::Stop {
                    "stop"
                } else {
                    "shutdown"
                }
            );
            if let Ok(mut tx) = SHUTDOWN_TX.lock() {
                if let Some(sender) = tx.take() {
                    let _ = sender.send(());
                }
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}
