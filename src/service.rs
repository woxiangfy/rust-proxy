use anyhow::{Context, Result};
use clap::Parser;
use service_manager::{
    RestartPolicy, ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStatus,
    ServiceStatusCtx, ServiceStopCtx, ServiceUninstallCtx,
};
use std::ffi::OsString;

use crate::config::{RunAsServiceArgs, ServerRunArgs};

const SERVICE_LABEL: &str = "rust-proxy";
/// 服务描述（仅 Windows 使用：`sc description` 需要，Linux 的 systemd unit 描述另配）
#[cfg(windows)]
const DEFAULT_SERVICE_DESCRIPTION: &str = "Rust HTTP Proxy Server";

/// 解析服务模式下的运行参数
///
/// 系统服务启动时（Windows SCM / systemd），命令行由 [`install_service`] 生成，
/// 形如 `rust-proxy --run-as-service --port 8080 --log-level info`。这条路径不经过
/// 顶层 `Cli`（`--run-as-service` 不是子命令），因此用 [`RunAsServiceArgs`]
/// （`--run-as-service` + `#[command(flatten)] ServerRunArgs`）复用同一套 `#[arg]` 定义。
///
/// 相比此前手写的逐参数 `match`，新增一个 flag 时只需改 `ServerRunArgs` 一处，
/// 不会再出现"CLI 支持、服务模式静默丢配置"的漏项。
///
/// 解析失败（例如人工追加了未知参数）时告警并回退默认值：服务模式下没有终端可交互，
/// 直接退出会让系统服务反复重启，回退到"仅用配置文件"更可控。
fn parse_service_args() -> ServerRunArgs {
    match RunAsServiceArgs::try_parse_from(std::env::args_os()) {
        Ok(parsed) => parsed.run_args,
        Err(e) => {
            log::warn!(
                "Failed to parse service-mode arguments ({}); falling back to defaults",
                e
            );
            ServerRunArgs::default()
        }
    }
}

/// 通过 `sc description` 补充服务描述
///
/// `service-manager` 的 `ServiceInstallCtx` 未暴露描述字段，而 Windows SCM 原生支持，
/// 因此装完之后再补一条 `sc` 命令。失败只告警不中断：描述属于展示信息，
/// 服务本身已经装好了，不该因为这一步失败而报错。
#[cfg(windows)]
fn set_service_description(description: &str) {
    match std::process::Command::new("sc")
        .args(["description", SERVICE_LABEL, description])
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

pub fn install_service(run_args: &ServerRunArgs) -> Result<()> {
    let exe_path = std::env::current_exe().context("Failed to get current executable path")?;

    let exe_dir = exe_path
        .parent()
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
        config = config
            .canonicalize()
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

    // HTTPS/TLS 配置参数
    if let Some(https_port) = run_args.https_port {
        command_args.push(OsString::from("--https-port"));
        command_args.push(OsString::from(https_port.to_string()));
    }
    if let Some(tls_cert) = &run_args.tls_cert {
        let tls_cert = if tls_cert.is_absolute() {
            tls_cert.clone()
        } else {
            std::env::current_dir()
                .context("Failed to get current directory")?
                .join(tls_cert)
        };
        command_args.push(OsString::from("--tls-cert"));
        command_args.push(OsString::from(tls_cert.display().to_string()));
    }
    if let Some(tls_key) = &run_args.tls_key {
        let tls_key = if tls_key.is_absolute() {
            tls_key.clone()
        } else {
            std::env::current_dir()
                .context("Failed to get current directory")?
                .join(tls_key)
        };
        command_args.push(OsString::from("--tls-key"));
        command_args.push(OsString::from(tls_key.display().to_string()));
    }

    if let Some(pp_mode) = run_args.proxy_protocol_mode {
        command_args.push(OsString::from("--proxy-protocol-mode"));
        command_args.push(OsString::from(pp_mode.to_string()));
    } else if run_args.proxy_protocol {
        command_args.push(OsString::from("--proxy-protocol"));
    }

    if !run_args.proxy_protocol_trusted_ips.is_empty() {
        let ips_str = run_args
            .proxy_protocol_trusted_ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",");
        command_args.push(OsString::from("--proxy-protocol-trusted-ips"));
        command_args.push(OsString::from(ips_str));
    }

    // 路径前缀直连模式
    if let Some(prefix) = &run_args.path_proxy_prefix {
        command_args.push(OsString::from("--path-proxy-prefix"));
        command_args.push(OsString::from(prefix));
    }
    if run_args.path_proxy_insecure {
        command_args.push(OsString::from("--path-proxy-insecure"));
    }

    // 三个平台的差异只在"用哪个 manager"和"装完是否补描述"：
    //   Linux  → systemd 专用 manager
    //   Windows → 平台原生 manager + sc description 补中文描述（service-manager 不支持）
    //   其他   → 平台原生 manager
    // 因此安装参数只构造一次，避免三份字面量各自漂移。
    let install_ctx = ServiceInstallCtx {
        label: label.clone(),
        program: exe_path,
        args: command_args,
        contents: None,
        username: None,
        autostart: true,
        environment: None,
        restart_policy: RestartPolicy::default(),
        working_directory: Some(exe_dir),
    };

    #[cfg(target_os = "linux")]
    {
        use service_manager::SystemdServiceManager;

        let mut manager = SystemdServiceManager::system();
        // manager.config.unit.description = Some(DEFAULT_SERVICE_DESCRIPTION.to_string());

        manager
            .install(install_ctx)
            .context("Failed to install service")?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let manager = <dyn ServiceManager>::native()
            .context("Failed to detect service management platform")?;

        manager
            .install(install_ctx)
            .context("Failed to install service")?;

        #[cfg(windows)]
        set_service_description(DEFAULT_SERVICE_DESCRIPTION);
    }

    println!("Service installed successfully: {}", label);
    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    let label: ServiceLabel = SERVICE_LABEL.parse().unwrap();

    let manager =
        <dyn ServiceManager>::native().context("Failed to detect service management platform")?;

    let _ = manager.stop(ServiceStopCtx {
        label: label.clone(),
    });
    std::thread::sleep(std::time::Duration::from_secs(2));

    manager
        .uninstall(ServiceUninstallCtx {
            label: label.clone(),
        })
        .context("Failed to uninstall service")?;

    println!("Service uninstalled successfully");
    Ok(())
}

pub fn start_service() -> Result<()> {
    let label: ServiceLabel = SERVICE_LABEL.parse().unwrap();

    let manager =
        <dyn ServiceManager>::native().context("Failed to detect service management platform")?;

    manager
        .start(ServiceStartCtx {
            label: label.clone(),
        })
        .context("Failed to start service")?;

    println!("Service started successfully");
    Ok(())
}

pub fn stop_service() -> Result<()> {
    let label: ServiceLabel = SERVICE_LABEL.parse().unwrap();

    let manager =
        <dyn ServiceManager>::native().context("Failed to detect service management platform")?;

    manager
        .stop(ServiceStopCtx {
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

    let manager =
        <dyn ServiceManager>::native().context("Failed to detect service management platform")?;

    let status = manager
        .status(ServiceStatusCtx {
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
    use log::{error, info};
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

    /// 复用外层 `service` 模块的解析函数（嵌套模块需要 `super::` 前缀）
    use super::parse_service_args;

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
        let start_args = parse_service_args();
        let args = Args::from_run_args(&start_args);

        let log_file = args.log_file.clone().unwrap_or_else(|| {
            let mut path = std::env::current_exe().unwrap();
            path.set_file_name("proxy.log");
            path
        });

        logging::setup_logging(&Some(log_file.clone()), &args.log_level)
            .context("Failed to setup logging")?;

        // let working_dir = std::env::current_dir().ok();
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
}

#[cfg(windows)]
pub use windows_service::run_as_service;

#[cfg(not(windows))]
pub fn run_as_service() -> Result<()> {
    use crate::config::Args;
    use crate::logging;
    use crate::server;
    use log::{error, info};
    use tokio::runtime::Runtime;

    let start_args = parse_service_args();
    let args = Args::from_run_args(&start_args);

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
        (None, Some(https_port)) => info!("Rust Proxy Service starting... HTTPS port: {} (HTTP disabled)", https_port),
        (None, None) => info!("Rust Proxy Service starting... (no listener enabled)"),
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    /// 服务模式参数必须由 clap 统一解析（B11 / A4 的回归）
    ///
    /// 此前是手写 `match` 逐参数解析，新增 flag 时容易漏同步；改为复用
    /// `RunAsServiceArgs` 后，`ServerRunArgs` 上新增字段自动生效。此测试固定
    /// "服务模式能识别 install_service 写入的全部参数"这一契约。
    #[test]
    fn test_service_args_cover_install_flags() {
        let parsed = RunAsServiceArgs::try_parse_from([
            "rust-proxy",
            "--run-as-service",
            "--config",
            "config.toml",
            "--port",
            "9090",
            "--https-port",
            "9443",
            "--tls-cert",
            "cert.pem",
            "--tls-key",
            "key.pem",
            "--timeout",
            "7",
            "--log-level",
            "debug",
            "--log-file",
            "proxy.log",
            "--multi-thread",
            "--proxy-protocol-mode",
            "require",
            "--proxy-protocol-trusted-ips",
            "10.0.0.1,10.0.0.2",
            "--path-proxy-prefix",
            "px",
            "--path-proxy-insecure",
        ])
        .expect("all install_service flags must be recognised");

        let a = parsed.run_args;
        assert!(parsed.run_as_service);
        assert_eq!(a.port, Some(9090));
        assert_eq!(a.https_port, Some(9443));
        assert_eq!(a.tls_cert.as_deref(), Some(std::path::Path::new("cert.pem")));
        assert_eq!(a.tls_key.as_deref(), Some(std::path::Path::new("key.pem")));
        assert_eq!(a.timeout, Some(7));
        assert_eq!(a.log_level, Some(crate::logging::LogLevel::Debug));
        assert_eq!(
            a.log_file.as_deref(),
            Some(std::path::Path::new("proxy.log"))
        );
        assert!(a.multi_thread);
        assert_eq!(a.proxy_protocol_mode, Some(crate::config::ProxyProtocolMode::Require));
        assert_eq!(a.proxy_protocol_trusted_ips.len(), 2);
        assert_eq!(a.path_proxy_prefix.as_deref(), Some("px"));
        assert!(a.path_proxy_insecure);
    }

    /// 未传参时回落到全默认值（服务被手动启动时不能 panic）
    #[test]
    fn test_service_args_default_is_empty() {
        let a = ServerRunArgs::default();
        assert!(a.port.is_none());
        assert!(a.config.is_none());
        assert!(a.proxy_protocol_trusted_ips.is_empty());
        assert!(!a.multi_thread);
    }
}
