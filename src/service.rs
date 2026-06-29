use anyhow::{Context, Result};
use service_manager::{
    RestartPolicy, ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx,
    ServiceStatus, ServiceStatusCtx, ServiceStopCtx, ServiceUninstallCtx,
};
use std::ffi::OsString;

use crate::config::ServerRunArgs;

const SERVICE_LABEL: &str = "rust-proxy";
const DEFAULT_SERVICE_DESCRIPTION: &str = "Rust HTTP Proxy Server";

pub fn install_service(run_args: &ServerRunArgs) -> Result<()> {
    let exe_path = std::env::current_exe()
        .context("Failed to get current executable path")?;
    
    let exe_dir = exe_path.parent()
        .context("Failed to get executable directory")?
        .to_path_buf();
    
    let label: ServiceLabel = SERVICE_LABEL.parse().unwrap();
    
    let mut command_args = vec![OsString::from("--run-as-service")];
    
    if let Some(mut config) = run_args.config.clone() {
        if config.is_relative() {
            config = std::env::current_dir()
                .context("Failed to get current directory")?
                .join(config);
        }
        config = config.canonicalize()
            .context("Failed to canonicalize config path")?;
        command_args.push(OsString::from("--config"));
        command_args.push(OsString::from(config.display().to_string()));
    }
    
    if let Some(port) = run_args.port {
        command_args.push(OsString::from("--port"));
        command_args.push(OsString::from(port.to_string()));
    }
    
    if let Some(log_file) = &run_args.log_file {
        let log_file = if log_file.is_absolute() {
            log_file.clone()
        } else {
            std::env::current_dir()
                .context("Failed to get current directory")?
                .join(log_file)
        };
        command_args.push(OsString::from("--log-file"));
        command_args.push(OsString::from(log_file.display().to_string()));
    }
    
    if let Some(timeout) = run_args.timeout {
        command_args.push(OsString::from("--timeout"));
        command_args.push(OsString::from(timeout.to_string()));
    }
    
    if let Some(log_level) = run_args.log_level {
        command_args.push(OsString::from("--log-level"));
        command_args.push(OsString::from(log_level.to_string()));
    }

    let description = DEFAULT_SERVICE_DESCRIPTION.to_string();

    #[cfg(target_os = "linux")]
    {
        use service_manager::SystemdServiceManager;
        
        let mut manager = SystemdServiceManager::system();
        // manager.config.unit.description = Some(description.clone());
        
        manager.install(ServiceInstallCtx {
            label: label.clone(),
            program: exe_path,
            args: command_args,
            contents: None,
            username: None,
            autostart: true,
            environment: None,
            restart_policy: RestartPolicy::default(),
            working_directory: Some(exe_dir),
        })
        .context("Failed to install service")?;
    }
    
    #[cfg(windows)]
    {
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
            working_directory: Some(exe_dir),
        })
        .context("Failed to install service")?;

        let output = std::process::Command::new("sc")
            .args(["description", SERVICE_LABEL, &description])
            .output()
            .context("Failed to set service description")?;
        
        if !output.status.success() {
            println!("Warning: Failed to set service description: {}", String::from_utf8_lossy(&output.stderr));
        }
    }
    
    #[cfg(not(any(target_os = "linux", windows)))]
    {
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
            working_directory: Some(exe_dir),
        })
        .context("Failed to install service")?;
    }

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

pub fn status_service() -> Result<()> {
    let label: ServiceLabel = SERVICE_LABEL.parse().unwrap();

    let manager = <dyn ServiceManager>::native()
        .context("Failed to detect service management platform")?;

    let status = manager.status(ServiceStatusCtx {
        label: label.clone(),
    })
    .context("Failed to get service status")?;

    match status {
        ServiceStatus::Running => {
            println!("Service is running");
        }
        ServiceStatus::Stopped(reason) => {
            if let Some(r) = reason {
                println!("Service is stopped: {}", r);
            } else {
                println!("Service is stopped");
            }
        }
        ServiceStatus::NotInstalled => {
            println!("Service is not installed");
        }
    }

    Ok(())
}

#[cfg(windows)]
mod windows_service {
    use anyhow::{Context, Result};
    use tokio::sync::oneshot;
    use log::{error, info};
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
        let start_args = crate::parse_service_args();
        let args = Args::from_run_args(&start_args);

        let log_file = args.log_file.clone().unwrap_or_else(|| {
            let mut path = std::env::current_exe().unwrap();
            path.set_file_name("proxy.log");
            path
        });

        logging::setup_logging(&Some(log_file.clone()), &args.log_level)
            .context("Failed to setup logging")?;

        // let working_dir = std::env::current_dir().ok();
        info!(
            "Rust Proxy Service starting... port={}",
            args.port
        );

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
pub fn run_as_service() -> Result<()> {
    use crate::config::Args;
    use crate::logging;
    use crate::server;
    use tokio::runtime::Runtime;
    use log::{error, info};

    let start_args = crate::parse_service_args();
    let args = Args::from_run_args(&start_args);

    let effective_log_file = if args.log_file.is_some() {
        args.log_file.clone()
    } else {
        std::env::current_exe()
            .ok()
            .map(|mut path| {
                path.set_file_name("proxy.log");
                path
            })
    };

    logging::setup_logging(&effective_log_file, &args.log_level)
        .context("Failed to setup logging")?;

    info!("Rust Proxy Service starting... port={}", args.port);

    let runtime = if args.multi_thread {
        Runtime::new().context("Failed to create multi-thread Tokio runtime")?
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create single-thread Tokio runtime")?
    };
    if let Err(e) = runtime.block_on(server::run_server(&args, None)) {
        error!("Server error: {}", e);
        return Err(e.into());
    }

    Ok(())
}