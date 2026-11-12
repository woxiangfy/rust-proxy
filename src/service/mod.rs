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
use std::path::PathBuf;
use std::time::Duration;

use crate::config::{RunAsServiceArgs, ServerRunArgs};

/// 服务参数适配层（`ServiceArgs` 的构造与 argv 序列化）
mod args;

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

/// start 后复检的短暂等待：Type=simple 的 unit 在 `systemctl start` 返回时可能
/// 还没完成 active/failed 迁移，立刻查一次状态会有竞态。
const SERVICE_START_VERIFY_GRACE: Duration = Duration::from_millis(300);

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

/// 查询 stopped 单元的细分状态（仅 Linux systemd 有值）
///
/// `service-manager` 把 `systemctl status` 的退出码 3 统一映射成
/// `Stopped(None)`，`failed` / `activating` 与普通 `inactive` 都落在这一类。
/// 这里补一次 `systemctl is-active`，避免把 failed 误报成 stopped。
#[cfg(not(windows))]
fn platform_inactive_state(label: &ServiceLabel) -> Option<String> {
    unix::inactive_state(label)
}

#[cfg(windows)]
fn platform_inactive_state(_label: &ServiceLabel) -> Option<String> {
    None
}

/// 状态展示文本（纯函数，便于不依赖 systemd 的字符串级测试）
fn render_status(status: &ServiceStatus, inactive_state: Option<&str>) -> String {
    match status {
        ServiceStatus::Running => "Service is running".to_string(),
        ServiceStatus::NotInstalled => "Service is not installed".to_string(),
        ServiceStatus::Stopped(reason) => {
            let suffix = reason
                .as_deref()
                .filter(|r| !r.is_empty())
                .map(|r| format!(": {r}"))
                .unwrap_or_default();
            match inactive_state {
                Some("failed") => {
                    format!("Service is failed (unit entered failed state){suffix}")
                }
                Some("activating") | Some("reloading") => {
                    format!("Service is starting (activating){suffix}")
                }
                Some("deactivating") => format!("Service is stopping (deactivating){suffix}"),
                Some(state) if state != "inactive" && state != "unknown" => {
                    format!("Service is stopped ({state}){suffix}")
                }
                _ => format!("Service is stopped{suffix}"),
            }
        }
    }
}

/// 服务日志排查提示（Linux 给出 systemd 命令，其他平台只给通用建议）
fn service_log_hints(label: &ServiceLabel) -> String {
    #[cfg(target_os = "linux")]
    {
        let name = label.to_script_name();
        format!(
            "Next steps:\n  systemctl status {name}\n  journalctl -u {name} -n 50 --no-pager"
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        format!("Check the service manager logs for '{}' for details.", label)
    }
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
/// 解析失败时 **fail-fast**：打印明确 error 并返回错误（进程以非零码退出）。
/// clap 的错误文本会指出具体参数（`--port` / 未知参数名），错误信息直接复用，
/// 避免"服务静默按默认值启动、认证配置丢失"的 fail-open 风险。
fn parse_service_args() -> Result<ServerRunArgs> {
    parse_service_args_from(std::env::args_os())
}

/// [`parse_service_args`] 的可测试版本：从给定 argv 解析服务模式参数
///
/// 单独抽出是为了在不篡改进程全局 argv 的情况下覆盖失败路径（单元测试只能
/// 安全地传自定义参数）。错误文案包含具体失败参数，便于服务日志定位。
fn parse_service_args_from<I, T>(argv: I) -> Result<ServerRunArgs>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match RunAsServiceArgs::try_parse_from(argv) {
        Ok(parsed) => Ok(parsed.run_args),
        Err(e) => {
            log::error!("Failed to parse service-mode arguments: {}", e);
            Err(anyhow::anyhow!("Invalid service-mode arguments: {}", e))
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

    // argv 拼装全部收敛到 `ServiceArgs::to_argv`（见 `service/args.rs`），
    // 这里只负责定位可执行文件与工作目录。
    let command_args = crate::config::ServiceArgs::from_run_args(run_args).to_argv()?;

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

    // Linux：`systemctl start` 对 Type=simple 的 unit 只保证"已 fork"，进程随后
    // 立刻退出时它仍返回 0。必须复检状态，否则会把失败的服务报告成启动成功。
    // 用 `cfg!` 而非 `#[cfg]`，让这段代码在所有平台都参与类型检查，运行时仅 Linux 生效。
    if cfg!(target_os = "linux") {
        let mut status = manager.status(ServiceStatusCtx {
            label: label.clone(),
        });
        if !matches!(&status, Ok(ServiceStatus::Running)) {
            std::thread::sleep(SERVICE_START_VERIFY_GRACE);
            status = manager.status(ServiceStatusCtx {
                label: label.clone(),
            });
        }

        match status {
            Ok(ServiceStatus::Running) => {}
            Ok(status) => {
                let inactive = platform_inactive_state(&label);
                eprintln!(
                    "Service did not stay running: {}\n{}",
                    render_status(&status, inactive.as_deref()),
                    service_log_hints(&label)
                );
                return Err(anyhow::anyhow!(
                    "Service '{}' failed to stay running",
                    label
                ));
            }
            Err(e) => {
                eprintln!(
                    "Failed to verify service status after start: {e}\n{}",
                    service_log_hints(&label)
                );
                return Err(anyhow::anyhow!(
                    "Failed to verify service status after start: {e}"
                ));
            }
        }
    }

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

    let inactive = match &status {
        ServiceStatus::Stopped(_) => platform_inactive_state(&label),
        _ => None,
    };
    println!("{}", render_status(&status, inactive.as_deref()));

    // failed 是启动失败后 systemd 留下的状态，普通 stopped（用户主动 stop）不需要提示。
    if inactive.as_deref() == Some("failed") {
        println!("{}", service_log_hints(&label));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// 快照夹具目录（与 `tests/config_golden.rs` 共用）
    fn golden_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/config_golden")
            .join(name)
    }

    /// 断言/更新服务 argv 金标准
    ///
    /// `UPDATE_GOLDEN=1` 时写入基线；其余情况只读。
    fn assert_golden(name: &str, actual: &str) {
        let path = golden_path(name);
        let actual = actual.replace("\r\n", "\n");
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::create_dir_all(path.parent().expect("fixture parent"))
                .expect("create fixture dir");
            std::fs::write(&path, &actual)
                .unwrap_or_else(|e| panic!("write golden {}: {e}", path.display()));
            return;
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing golden {}: {e}", path.display()));
        assert_eq!(
            expected.replace("\r\n", "\n"),
            actual,
            "golden mismatch: {}",
            path.display()
        );
    }

    /// 路径的稳定展示形式（去掉 Windows canonicalize 的 `\\?\` 前缀）
    fn norm_str(path: &Path) -> String {
        path.display()
            .to_string()
            .replace('\\', "/")
            .replace("//?/", "")
    }

    /// 把 argv 渲染成稳定文本，并归一化本机路径
    fn render_argv(args: &[OsString]) -> String {
        let cwd = std::env::current_dir().expect("cwd");
        args.iter()
            .map(|a| a.to_string_lossy().into_owned().replace('\\', "/").replace("//?/", ""))
            .collect::<Vec<_>>()
            .join("\n")
            .replace(&norm_str(&cwd), "<CWD>")
    }

    /// 服务 argv 金标准：默认空、全字段显式、auth 永不出现
    #[test]
    fn test_golden_service_argv() {
        let mut out = String::new();

        out.push_str("===== default =====\n");
        let (_, _, args) = build_service_command(&ServerRunArgs::default()).unwrap();
        out.push_str(&render_argv(&args));
        out.push('\n');

        // 全字段显式（config 用临时文件，验证 canonicalize）
        let dir = std::env::temp_dir().join(format!(
            "rust_proxy_service_golden_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.toml");
        std::fs::write(&cfg, "port = 8080\n").unwrap();

        let source = ServerRunArgs {
            config: Some(cfg.clone()),
            port: Some(8081),
            log_file: Some(PathBuf::from("logs/proxy.log")),
            timeout: Some(9),
            log_level: Some(crate::support::logging::LogLevel::Debug),
            multi_thread: true,
            https_port: Some(9443),
            tls_cert: Some(PathBuf::from("cert.pem")),
            tls_key: Some(PathBuf::from("key.pem")),
            proxy_protocol_mode: Some(crate::config::ProxyProtocolMode::Require),
            proxy_protocol: false,
            proxy_protocol_trusted_ips: vec![
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
            ],
            path_proxy_prefix: Some("px".into()),
            path_proxy_insecure: true,
        };

        out.push_str("===== all_explicit =====\n");
        let (_, _, args) = build_service_command(&source).unwrap();
        let mut rendered = render_argv(&args).replace(&norm_str(&dir), "<CONFIG_DIR>");
        if let Ok(canon) = dir.canonicalize() {
            rendered = rendered.replace(&norm_str(&canon), "<CONFIG_DIR>");
        }
        out.push_str(&rendered);
        out.push('\n');

        // 安全不变量：auth 密码不在结构里，也不得出现在 argv 中
        assert!(
            !args.iter().any(|a| {
                let s = a.to_string_lossy();
                s.contains("--auth") || s.contains("password") || s.contains("secret")
            }),
            "auth material must never reach service argv: {:?}",
            args
        );

        // 旧 `--proxy-protocol` 兼容参数单独快照
        out.push_str("===== legacy_proxy_protocol =====\n");
        let legacy = ServerRunArgs {
            proxy_protocol: true,
            ..Default::default()
        };
        let (_, _, args) = build_service_command(&legacy).unwrap();
        out.push_str(&render_argv(&args));
        out.push('\n');

        let _ = std::fs::remove_dir_all(&dir);
        assert_golden("service_argv.txt", &out);
    }

    /// 服务模式解析失败必须 fail-fast，且错误信息指出具体参数
    #[test]
    fn test_parse_service_args_fail_fast_reports_offending_argument() {
        // 非数字端口：clap 的错误包含参数名与非法值
        let err = parse_service_args_from([
            "rust-proxy",
            "--run-as-service",
            "--port",
            "not-a-port",
        ])
        .expect_err("invalid --port must fail");
        let msg = err.to_string();
        assert!(msg.contains("--port"), "error must name --port: {msg}");
        assert!(
            msg.contains("not-a-port"),
            "error must show invalid value: {msg}"
        );

        // 未知参数：错误包含未知参数名
        let err = parse_service_args_from(["rust-proxy", "--run-as-service", "--bogus"])
            .expect_err("unknown flag must fail");
        let msg = err.to_string();
        assert!(msg.contains("--bogus"), "error must name --bogus: {msg}");
    }

    /// 合法服务参数走同一条解析路径（正常路径回归）
    #[test]
    fn test_parse_service_args_accepts_valid_argv() {
        let parsed = parse_service_args_from([
            "rust-proxy",
            "--run-as-service",
            "--port",
            "9090",
            "--log-level",
            "debug",
        ])
        .expect("valid argv must parse");
        assert_eq!(parsed.port, Some(9090));
        assert_eq!(parsed.log_level, Some(crate::support::logging::LogLevel::Debug));
    }

    /// 服务模式参数必须由 clap 统一解析
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
        assert_eq!(a.log_level, Some(crate::support::logging::LogLevel::Debug));
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

    /// 服务 argv 与 CLI 子集必须逐字段可逆
    ///
    /// 这里显式列出 `ServerRunArgs` 的**全部字段**（不带 `..`）：新增字段时
    /// 该测试会编译失败，强制检查 `build_service_command` 是否同步。
    #[test]
    fn test_build_service_command_round_trips_every_explicit_field() {
        let source = ServerRunArgs {
            config: None,
            port: Some(8081),
            log_file: Some(PathBuf::from("logs/proxy.log")),
            timeout: Some(9),
            log_level: Some(crate::support::logging::LogLevel::Debug),
            multi_thread: true,
            https_port: Some(9443),
            tls_cert: Some(PathBuf::from("cert.pem")),
            tls_key: Some(PathBuf::from("key.pem")),
            proxy_protocol_mode: Some(crate::config::ProxyProtocolMode::Require),
            proxy_protocol: false,
            proxy_protocol_trusted_ips: vec![
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
            ],
            path_proxy_prefix: Some("px".into()),
            path_proxy_insecure: true,
        };

        let cwd = std::env::current_dir().unwrap();
        let expected = ServerRunArgs {
            log_file: Some(cwd.join("logs/proxy.log")),
            tls_cert: Some(cwd.join("cert.pem")),
            tls_key: Some(cwd.join("key.pem")),
            ..source.clone()
        };

        let (_program, _dir, args) = build_service_command(&source).unwrap();
        let mut argv = vec![OsString::from("rust-proxy")];
        argv.extend(args);

        let parsed = RunAsServiceArgs::try_parse_from(argv).unwrap();
        assert!(parsed.run_as_service);
        assert_eq!(parsed.run_args, expected);
    }

    /// 风险：failed 单元必须显示为 failed，不能被 systemd 退出码 3 统一吞成 "stopped"。
    #[test]
    fn test_render_status_distinguishes_failed_and_activating() {
        assert_eq!(
            render_status(&ServiceStatus::Running, None),
            "Service is running"
        );
        assert_eq!(
            render_status(&ServiceStatus::NotInstalled, None),
            "Service is not installed"
        );

        // 用户主动 stop 的普通状态保持原样
        assert_eq!(
            render_status(&ServiceStatus::Stopped(None), Some("inactive")),
            "Service is stopped"
        );

        let failed = render_status(&ServiceStatus::Stopped(None), Some("failed"));
        assert!(failed.starts_with("Service is failed"), "{failed}");

        let activating = render_status(&ServiceStatus::Stopped(None), Some("activating"));
        assert!(activating.contains("starting"), "{activating}");

        // service-manager 若将来带上 reason，后缀不能被丢掉
        let with_reason = render_status(
            &ServiceStatus::Stopped(Some("exit code 1".into())),
            Some("failed"),
        );
        assert!(with_reason.contains("exit code 1"), "{with_reason}");
    }

    /// 风险：start 复检失败时必须给出可直接执行的 systemd 排查命令，而不是只报一句错误。
    #[test]
    fn test_start_failure_hints_point_to_systemd_logs() {
        let hints = service_log_hints(&service_label());
        #[cfg(target_os = "linux")]
        {
            assert!(hints.contains("systemctl status rust-proxy"), "{hints}");
            assert!(
                hints.contains("journalctl -u rust-proxy -n 50 --no-pager"),
                "{hints}"
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(hints.contains("service manager logs"), "{hints}");
        }
    }
}
