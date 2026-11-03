//! 进程级入口编排：运行时装配、信号监听、子命令分派
//!
//! 这是从原 `main.rs` 整体搬出的"胶水层"。放在库里而不是二进制里，目的是让
//! `tests/` 下的集成测试能复用同一套启动逻辑（`run_with_cli`），而不是各自
//! 重写一遍运行时搭建。二进制侧只剩 [`crate::app::run`] 一行调用。
//!
//! 三种运行模式：
//!   1. 服务模式：命令行含 `--run-as-service`（系统服务管理器启动）
//!   2. 命令模式：`start` / `test` / `server` 子命令
//!   3. 服务管理：`server install|uninstall|start|stop|restart|status`

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::oneshot;

use crate::config::{Args, Cli, Commands, LogLevel, ServerArgs, ServerSubcommand};
use crate::{client, logging, server, service};

/// 创建 Tokio 运行时，根据参数选择单线程或多线程
fn create_runtime(multi_thread: bool) -> Result<tokio::runtime::Runtime> {
    if multi_thread {
        tokio::runtime::Runtime::new().context("无法创建多线程 Tokio 运行时")
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("无法创建单线程 Tokio 运行时")
    }
}

/// 监听前台运行时的操作系统关停信号，触发优雅关停。
///
/// 前台 `start` 命令不依赖服务管理机制（Windows 服务 / systemd），因此需要
/// 自行监听关停信号并通知 [`crate::server::run_server`] 进入优雅关停流程：
/// 停止接受新连接，等待所有活跃连接处理完成后退出。
///
/// - Unix（Linux/macOS）：监听 SIGINT（Ctrl+C）与 SIGTERM
/// - Windows：监听 Ctrl+C
///
/// 返回一个在信号到达时被唤醒的 [`oneshot::Receiver`]，供 `run_server` 的
/// `shutdown_rx` 参数接收。
fn spawn_shutdown_signal(runtime: &tokio::runtime::Runtime) -> Result<oneshot::Receiver<()>> {
    let (tx, rx) = oneshot::channel();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt()).context("无法注册 SIGINT 信号处理器")?;
        let mut sigterm = signal(SignalKind::terminate()).context("无法注册 SIGTERM 信号处理器")?;
        runtime.spawn(async move {
            tokio::select! {
                _ = sigint.recv() => {}
                _ = sigterm.recv() => {}
            }
            let _ = tx.send(());
        });
    }

    #[cfg(not(unix))]
    {
        runtime.spawn(async move {
            // 注册失败仅影响优雅关停能力，不影响代理主流程本身，故忽略错误
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = tx.send(());
            }
        });
    }

    Ok(rx)
}

/// 处理服务管理子命令
///
/// 根据子命令类型调用相应的服务管理函数，包括安装、卸载、启动、停止、重启和状态查询。
async fn handle_server_command(server_args: ServerArgs) -> Result<()> {
    match server_args.subcommand {
        ServerSubcommand::Install(run_args) => {
            // 安装系统服务，将运行参数嵌入服务命令行
            service::install_service(&run_args)?;
        }
        ServerSubcommand::Uninstall => service::uninstall_service()?,
        ServerSubcommand::Start => service::start_service()?,
        ServerSubcommand::Stop => service::stop_service()?,
        ServerSubcommand::Restart => service::restart_service()?,
        ServerSubcommand::Status => service::status_service()?,
    }

    Ok(())
}

/// 按已解析的命令行执行对应模式（`start` 会阻塞到服务器退出）
pub fn run_with_cli(cli: Cli) -> Result<()> {
    // 仅 Start 命令支持多线程运行时，Test 和 Server 管理命令始终使用单线程
    match cli.command {
        Commands::Start(start_args) => {
            let args = Args::from_run_args(&start_args);
            logging::setup_logging(&args.log_file, &args.log_level)?;
            let runtime = create_runtime(args.multi_thread)?;
            let shutdown_rx = spawn_shutdown_signal(&runtime)?;
            runtime.block_on(server::run_server(&args, Some(shutdown_rx)))?;
        }
        Commands::Test {
            proxy_url,
            url,
            username,
            password,
        } => {
            logging::setup_logging(&None, &LogLevel::Info)?;
            let runtime = create_runtime(false)?;
            runtime.block_on(client::test_proxy(
                &proxy_url,
                &url,
                username.as_deref(),
                password.as_deref(),
            ))?;
        }
        Commands::Server(server_args) => {
            let runtime = create_runtime(false)?;
            runtime.block_on(handle_server_command(server_args))?;
        }
    }

    Ok(())
}

/// 程序主入口
///
/// 先检测是否以服务模式启动（`--run-as-service`）：系统服务环境下无法使用 clap
/// 解析参数（缺少终端 / 参数由服务管理器注入），因此优先交给 [`service::run_as_service`]。
/// 其余情况解析命令行后交给 [`run_with_cli`]。
pub fn run() -> Result<()> {
    if std::env::args().any(|a| a == "--run-as-service") {
        service::run_as_service()?;
        return Ok(());
    }

    run_with_cli(Cli::parse())
}
