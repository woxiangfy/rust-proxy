//! rust-proxy - 一个轻量级的 HTTP 代理服务器
//!
//! 该模块是 HTTP 代理应用程序的入口点，负责解析命令行参数并启动相应的服务模式。
//! 支持三种运行模式：
//!   1. 服务模式：通过 --run-as-service 参数启动，作为系统服务运行
//!   2. 命令模式：通过 start/test/server 子命令启动
//!   3. 服务管理：通过 server install/uninstall/start/stop/restart/status 管理服务

mod buffer_pool;
mod config;
mod logging;
mod proxy;
mod server;
mod service;

use anyhow::{Context, Result};
use clap::Parser;

use config::{Args, Cli, Commands, LogLevel, ServerArgs, ServerRunArgs, ServerSubcommand};

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
            let _guard = logging::setup_logging(&args.log_file, &args.log_level)?;
            let runtime = create_runtime(args.multi_thread)?;
            runtime.block_on(server::run_server(&args, None))?;
        }
        Commands::Test { proxy_addr, url } => {
            let _guard = logging::setup_logging(&None, &LogLevel::Info)?;
            let runtime = create_runtime(false)?;
            runtime.block_on(proxy::test_proxy(&proxy_addr, &url))?;
        }
        Commands::Server(server_args) => {
            let runtime = create_runtime(false)?;
            runtime.block_on(handle_server_command(server_args))?;
        }
    }

    Ok(())
}

/// 服务模式下的命令行参数解析函数
///
/// 在系统服务环境中（如 Windows Service 或 Linux systemd），clap 无法正确解析参数，
/// 因此需要手动解析命令行参数。支持的参数包括：
///   --config   指定配置文件路径
///   --port     指定监听端口
///   --log-file 指定日志文件路径
///   --timeout  指定连接超时时间（秒）
///   --log-level 指定日志级别
///   --multi-thread 启用多线程运行时
fn parse_service_args() -> ServerRunArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut start_args = ServerRunArgs {
        config: None,
        port: None,
        log_file: None,
        timeout: None,
        log_level: None,
        multi_thread: false,
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                if i + 1 < args.len() {
                    start_args.port = args[i + 1].parse().ok();
                    i += 2;
                    continue;
                }
            }
            "--log-file" => {
                if i + 1 < args.len() {
                    start_args.log_file = Some(args[i + 1].clone().into());
                    i += 2;
                    continue;
                }
            }
            "--timeout" => {
                if i + 1 < args.len() {
                    start_args.timeout = args[i + 1].parse().ok();
                    i += 2;
                    continue;
                }
            }
            "--log-level" => {
                if i + 1 < args.len() {
                    start_args.log_level = args[i + 1].parse().ok();
                    i += 2;
                    continue;
                }
            }
            "--config" => {
                if i + 1 < args.len() {
                    start_args.config = Some(args[i + 1].clone().into());
                    i += 2;
                    continue;
                }
            }
            "--run-as-service" => {}
            "--multi-thread" => {
                start_args.multi_thread = true;
                i += 1;
                continue;
            }
            _ => {}
        }
        i += 1;
    }

    start_args
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
