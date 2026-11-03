//! 系统服务安装与管理
//!
//! 对外只有六个入口：[`install_service`] / [`uninstall_service`] / [`start_service`] /
//! [`stop_service`] / [`restart_service`] / [`status_service`]，以及服务进程内的
//! [`run_as_service`]。
//!
//! 平台差异被压到两个函数（各子模块的 `install` 与 `run_as_service`）：
//! - **Linux**：`systemd` 专用 manager，避开 `native()` 在容器 / 非 systemd 环境下
//!   退化成 sysv 或直接失败；
//! - **Windows**：原生 SCM manager，装完补一条 `sc description`；
//! - **其他 Unix**：平台原生 manager。
//!
//! 服务命令行的**拼装**留在本模块：它只依赖 [`ServerRunArgs`]，与平台无关。
//! 放进平台分支就意味着三份字面量各自漂移（前三轮修掉的 B10 正是这个问题）。

use anyhow::{Context, Result};
use clap::Parser;
use service_manager::{
    RestartPolicy, ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStatus,
    ServiceStatusCtx, ServiceStopCtx, ServiceUninstallCtx,
};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{RunAsServiceArgs, ServerRunArgs};

#[cfg(windows)]
mod windows;
#[cfg(not(windows))]
mod unix;

#[cfg(windows)]
pub use windows::run_as_service;
#[cfg(not(windows))]
pub use unix::run_as_service;

/// 服务名（SCM 的服务名 / systemd 的 unit 名 / `ServiceLabel`）
const SERVICE_LABEL: &str = "rust-proxy";

/// 服务描述（仅 Windows 使用：`sc description` 需要，Linux 的 systemd unit 描述另配）
#[cfg(windows)]
const DEFAULT_SERVICE_DESCRIPTION: &str = "Rust HTTP Proxy Server";

/// 停止 / 卸载后的等待：给 SCM、systemd 一点时间完成状态迁移。
/// 紧接着执行 start / uninstall 否则可能撞上 "service is marked for deletion"。
const SERVICE_STOP_GRACE: Duration = Duration::from_secs(2);

/// 构造服务名对应的 [`ServiceLabel`]
///
/// 常量非法只可能是代码写错（`ServiceLabel` 只拒绝空白与非法字符），
/// 用 `expect` 而不是 `unwrap` 把这条前提写进 panic 信息里。
fn service_label() -> ServiceLabel {
    SERVICE_LABEL
        .parse()
        .expect("SERVICE_LABEL must be a valid service label")
}

/// 平台原生 manager（uninstall / start / stop / status 共用）
fn native_manager() -> Result<Box<dyn ServiceManager>> {
    <dyn ServiceManager>::native().context("Failed to detect service management platform")
}

/// 相对路径 → 绝对路径（不要求目标存在）
///
/// 服务进程的工作目录由 SCM / systemd 决定，相对路径到那时会指向别处，
/// 因此安装时一次性转成绝对路径。
fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("Failed to get current directory")?
        .join(path))
}

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

/// 把安装时的参数翻译成服务进程的启动命令行
///
/// 返回 `(可执行文件, 工作目录, 参数列表)`。命令行只带**显式指定**的选项：
/// 没传的项留给配置文件与默认值决定，避免安装时把当时的默认值固化进服务定义
/// （改默认值后老服务仍按旧值跑）。
fn build_service_command(run_args: &ServerRunArgs) -> Result<(PathBuf, PathBuf, Vec<OsString>)> {
    let exe_path = std::env::current_exe().context("Failed to get current executable path")?;
    let exe_dir = exe_path
        .parent()
        .context("Failed to get executable directory")?
        .to_path_buf();

    let mut command_args = vec![OsString::from("--run-as-service")];

    // 配置文件额外 canonicalize：它必须存在，且服务进程的解析起点不同，
    // 相对路径在装载时会指向别处（表现为"配了认证但服务没生效"）。
    if let Some(config) = &run_args.config {
        let config = absolute_path(config)?
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
        let log_file = absolute_path(log_file)?;
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
        let tls_cert = absolute_path(tls_cert)?;
        command_args.push(OsString::from("--tls-cert"));
        command_args.push(OsString::from(tls_cert.display().to_string()));
    }
    if let Some(tls_key) = &run_args.tls_key {
        let tls_key = absolute_path(tls_key)?;
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

    // `--multi-thread` 此前漏传：安装时指定了多线程，服务进程仍跑单线程运行时
    // （`ServerRunArgs::default()` 的 `multi_thread = false`），而 CLI 侧一直被
    // 告知该选项有效。
    if run_args.multi_thread {
        command_args.push(OsString::from("--multi-thread"));
    }

    Ok((exe_path, exe_dir, command_args))
}

pub fn install_service(run_args: &ServerRunArgs) -> Result<()> {
    let (program, working_directory, args) = build_service_command(run_args)?;
    let label = service_label();

    let ctx = ServiceInstallCtx {
        label: label.clone(),
        program,
        args,
        contents: None,
        username: None,
        autostart: true,
        environment: None,
        restart_policy: RestartPolicy::default(),
        working_directory: Some(working_directory),
    };

    #[cfg(windows)]
    windows::install(ctx)?;
    #[cfg(not(windows))]
    unix::install(ctx)?;

    println!("Service installed successfully: {}", label);
    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    let label = service_label();
    let manager = native_manager()?;

    let _ = manager.stop(ServiceStopCtx {
        label: label.clone(),
    });
    std::thread::sleep(SERVICE_STOP_GRACE);

    manager
        .uninstall(ServiceUninstallCtx {
            label: label.clone(),
        })
        .context("Failed to uninstall service")?;

    println!("Service uninstalled successfully");
    Ok(())
}

pub fn start_service() -> Result<()> {
    let label = service_label();
    let manager = native_manager()?;

    manager
        .start(ServiceStartCtx {
            label: label.clone(),
        })
        .context("Failed to start service")?;

    println!("Service started successfully");
    Ok(())
}

pub fn stop_service() -> Result<()> {
    let label = service_label();
    let manager = native_manager()?;

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
    std::thread::sleep(SERVICE_STOP_GRACE);
    start_service()?;
    println!("Service restarted successfully");
    Ok(())
}

pub fn status_service() -> Result<()> {
    let label = service_label();
    let manager = native_manager()?;

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
        assert_eq!(
            a.proxy_protocol_mode,
            Some(crate::config::ProxyProtocolMode::Require)
        );
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

    /// 命令行拼装只带显式指定的项，且相对路径转绝对
    ///
    /// 服务进程的工作目录由 SCM / systemd 决定，相对路径必须在这里就固定下来；
    /// 未指定的项则不能写入（否则会把安装当时的默认值固化进服务定义）。
    #[test]
    fn test_build_service_command_only_emits_explicit_flags() {
        let run_args = ServerRunArgs {
            port: Some(8080),
            log_file: Some(PathBuf::from("logs/proxy.log")),
            multi_thread: true,
            ..Default::default()
        };

        let (_program, _dir, args) = build_service_command(&run_args).unwrap();
        let args: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        assert_eq!(args[0], "--run-as-service");
        assert!(args.windows(2).any(|w| w == ["--port", "8080"]));
        assert!(
            args.iter().any(|a| a == "--multi-thread"),
            "安装时指定多线程必须传递到服务进程"
        );

        let log_idx = args.iter().position(|a| a == "--log-file").unwrap();
        let log_path = PathBuf::from(&args[log_idx + 1]);
        assert!(
            log_path.is_absolute(),
            "日志路径必须转成绝对路径，实际：{}",
            log_path.display()
        );

        // 未显式指定的项不得出现
        for absent in [
            "--timeout",
            "--https-port",
            "--tls-cert",
            "--tls-key",
            "--path-proxy-prefix",
        ] {
            assert!(!args.iter().any(|a| a == absent), "{absent} 不该被写入");
        }
    }
}
