use anyhow::{Context, Result};
use service_manager::{
    RestartPolicy, ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};
use std::ffi::OsString;

use crate::config::Args;

const SERVICE_LABEL: &str = "rust-proxy";

pub fn install_service(args: &Args) -> Result<()> {
    let exe_path = std::env::current_exe()
        .context("Failed to get current executable path")?;
    
    let label: ServiceLabel = SERVICE_LABEL.parse().unwrap();
    
    let mut command_args = vec![OsString::from("--run-as-service")];
    
    if let Some(log_file) = &args.log_file {
        command_args.push(OsString::from("--log-file"));
        command_args.push(OsString::from(log_file.display().to_string()));
    }
    if args.port != Args::DEFAULT_PORT {
        command_args.push(OsString::from("--port"));
        command_args.push(OsString::from(args.port.to_string()));
    }
    if args.timeout != Args::DEFAULT_TIMEOUT {
        command_args.push(OsString::from("--timeout"));
        command_args.push(OsString::from(args.timeout.to_string()));
    }
    if args.log_level != Args::DEFAULT_LOG_LEVEL {
        command_args.push(OsString::from("--log-level"));
        command_args.push(OsString::from(args.log_level.to_string()));
    }

    let manager = <dyn ServiceManager>::native()
        .context("Failed to detect service management platform")?;

    manager.install(ServiceInstallCtx {
        label: label.clone(),
        program: exe_path,
        args: command_args,
        contents: None,
        username: None,
        autostart: true,
        environment: None,
        restart_policy: RestartPolicy::default(),
        working_directory: None,
    })
    .context("Failed to install service")?;

    println!("Service installed successfully: {}", label);
    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    let label: ServiceLabel = SERVICE_LABEL.parse().unwrap();

    let manager = <dyn ServiceManager>::native()
        .context("Failed to detect service management platform")?;

    let _ = manager.stop(ServiceStopCtx {
        label: label.clone(),
    });
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    manager.uninstall(ServiceUninstallCtx {
        label: label.clone(),
    })
    .context("Failed to uninstall service")?;

    println!("Service uninstalled successfully");
    Ok(())
}

pub fn start_service() -> Result<()> {
    let label: ServiceLabel = SERVICE_LABEL.parse().unwrap();

    let manager = <dyn ServiceManager>::native()
        .context("Failed to detect service management platform")?;

    manager.start(ServiceStartCtx {
        label: label.clone(),
    })
    .context("Failed to start service")?;

    println!("Service started successfully");
    Ok(())
}

pub fn stop_service() -> Result<()> {
    let label: ServiceLabel = SERVICE_LABEL.parse().unwrap();

    let manager = <dyn ServiceManager>::native()
        .context("Failed to detect service management platform")?;

    manager.stop(ServiceStopCtx {
        label: label.clone(),
    })
    .context("Failed to stop service")?;

    println!("Service stopped successfully");
    Ok(())
}

pub fn restart_service() -> Result<()> {
    stop_service()?;
    std::thread::sleep(std::time::Duration::from_secs(2));
    start_service()?;
    println!("Service restarted successfully");
    Ok(())
}

#[cfg(windows)]
mod windows_service {
    use anyhow::{Context, Result};
    use tokio::runtime::Runtime;
    use tokio::sync::oneshot;
    use tracing::{error, info};
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };
    use std::ffi::OsString;
    use std::sync::Mutex;

    use crate::config::Args;
    use crate::logging;
    use crate::server;

    const SERVICE_NAME: &str = "rust-proxy";

    static SHUTDOWN_TX: Mutex<Option<oneshot::Sender<()>>> = Mutex::new(None);

    define_windows_service!(ffi_service_main, service_main);

    pub fn run_as_service(args: &Args) -> Result<()> {
        ARGS.with(|cell| {
            *cell.borrow_mut() = Some(args.clone());
        });
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .context("Failed to start service dispatcher")?;
        Ok(())
    }

    thread_local! {
        static ARGS: std::cell::RefCell<Option<Args>> = std::cell::RefCell::new(None);
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(e) = run_service() {
            error!("Service error: {}", e);
        }
    }

    fn run_service() -> Result<()> {
        let args = ARGS.with(|cell| cell.borrow().clone().unwrap_or_else(|| {
            Args::from_start_args(&crate::config::StartArgs {
                config: None,
                port: None,
                log_file: None,
                timeout: None,
                log_level: None,
            })
        }));

        let log_file = args.log_file.clone().unwrap_or_else(|| {
            let mut path = std::env::current_exe().unwrap();
            path.set_file_name("proxy.log");
            path
        });

        let _guard = logging::setup_logging(&Some(log_file), &args.log_level)
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
        *SHUTDOWN_TX.lock().unwrap() = Some(shutdown_tx);

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })?;

        let runtime = Runtime::new().context("Failed to create Tokio runtime")?;
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
                info!("Received {} control signal", 
                    if control == ServiceControl::Stop { "stop" } else { "shutdown" });
                if let Ok(mut tx) = SHUTDOWN_TX.lock() {
                    if let Some(sender) = tx.take() {
                        let _ = sender.send(());
                    }
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => {
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    }
}

#[cfg(windows)]
pub use windows_service::run_as_service;

#[cfg(not(windows))]
pub fn run_as_service(_args: &Args) -> Result<()> {
    Err(anyhow::anyhow!("Service mode is only supported on Windows"))
}