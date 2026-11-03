//! rust-proxy - 一个轻量级的 HTTP 代理服务器
//!
//! 该模块是 HTTP 代理应用程序的入口点，负责解析命令行参数并启动相应的服务模式。
//! 支持三种运行模式：
//!   1. 服务模式：通过 --run-as-service 参数启动，作为系统服务运行
//!   2. 命令模式：通过 start/test/server 子命令启动
//!   3. 服务管理：通过 server install/uninstall/start/stop/restart/status 管理服务

mod buffer_pool;
mod config;
mod http_body;
mod http_util;
mod io;
mod logging;
mod net;
mod path_proxy;
mod proxy;
mod proxy_protocol;
mod server;
mod service;
mod tls;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::oneshot;

use config::{Args, Cli, Commands, LogLevel, ServerArgs, ServerSubcommand};

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
/// 自行监听关停信号并通知 [`server::run_server`] 进入优雅关停流程：
/// 停止接受新连接，等待所有活跃连接处理完成后退出。
///
/// - Unix（Linux/macOS）：监听 SIGINT（Ctrl+C）与 SIGTERM
/// - Windows：监听 Ctrl+C
///
/// 返回一个在信号到达时被唤醒的 [`oneshot::Receiver`]，供 [`server::run_server`] 的
/// `shutdown_rx` 参数接收。
fn spawn_shutdown_signal(runtime: &tokio::runtime::Runtime) -> Result<oneshot::Receiver<()>> {
    let (tx, rx) = oneshot::channel();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint =
            signal(SignalKind::interrupt()).context("无法注册 SIGINT 信号处理器")?;
        let mut sigterm =
            signal(SignalKind::terminate()).context("无法注册 SIGTERM 信号处理器")?;
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

/// 程序主入口函数
///
/// 首先检测是否以服务模式启动（--run-as-service），若是则直接调用服务运行函数。
/// 否则解析命令行参数并根据子命令类型执行相应操作：
///   - start：启动 HTTP 代理服务器
///   - test：测试指定代理服务器的连通性
///   - server：执行服务管理命令（安装/卸载/启动/停止等）
fn main() -> Result<()> {
    // 服务模式优先：系统服务环境下无法使用 clap 解析参数，需手动处理
    if std::env::args().any(|a| a == "--run-as-service") {
        service::run_as_service()?;
        return Ok(());
    }

    let cli = Cli::parse();

    // 仅 Start 命令支持多线程运行时，Test 和 Server 管理命令始终使用单线程
    match cli.command {
        Commands::Start(start_args) => {
            let args = Args::from_run_args(&start_args);
            logging::setup_logging(&args.log_file, &args.log_level)?;
            let runtime = create_runtime(args.multi_thread)?;
            let shutdown_rx = spawn_shutdown_signal(&runtime)?;
            runtime.block_on(server::run_server(&args, Some(shutdown_rx)))?;
        }
        Commands::Test { proxy_url, url, username, password } => {
            logging::setup_logging(&None, &LogLevel::Info)?;
            let runtime = create_runtime(false)?;
            runtime.block_on(proxy::test_proxy(&proxy_url, &url, username.as_deref(), password.as_deref()))?;
        }
        Commands::Server(server_args) => {
            let runtime = create_runtime(false)?;
            runtime.block_on(handle_server_command(server_args))?;
        }
    }

    Ok(())
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
        ServerSubcommand::Uninstall => {
            // 卸载系统服务
            service::uninstall_service()?;
        }
        ServerSubcommand::Start => {
            // 启动已安装的系统服务
            service::start_service()?;
        }
        ServerSubcommand::Stop => {
            // 停止运行中的系统服务
            service::stop_service()?;
        }
        ServerSubcommand::Restart => {
            // 重启系统服务（先停止再启动）
            service::restart_service()?;
        }
        ServerSubcommand::Status => {
            // 查询系统服务的当前状态
            service::status_service()?;
        }
    }

    Ok(())
}
