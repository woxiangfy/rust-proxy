//! rust-proxy - A simple HTTP proxy server
//!
//! This module serves as the entry point for the HTTP proxy application.

mod buffer_pool;
mod config;
mod dns_cache;
mod logging;
mod proxy;
mod server;
mod service;

use anyhow::Result;
use clap::Parser;

use config::{Args, Cli, Commands, LogLevel, ServerArgs, ServerSubcommand, StartArgs};

fn main() -> Result<()> {
    if std::env::args().any(|a| a == "--run-as-service") {
        let start_args = parse_service_args();
        let args = Args::from_start_args(&start_args);
        service::run_as_service(&args)?;
        return Ok(());
    }

    let cli = Cli::parse();

    tokio::runtime::Runtime::new()?.block_on(async move {
        match cli.command {
            Commands::Start(start_args) => {
                let args = Args::from_start_args(&start_args);
                let _guard = logging::setup_logging(&args.log_file, &args.log_level)?;
                server::run_server(&args, None).await?;
            }
            Commands::Test { proxy_addr, url } => {
                let _guard = logging::setup_logging(&None, &LogLevel::Info)?;
                proxy::test_proxy(&proxy_addr, &url).await?;
            }
            Commands::Server(server_args) => {
                handle_server_command(server_args).await?;
            }
        }

        Ok(())
    })
}

fn parse_service_args() -> StartArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut start_args = StartArgs {
        config: None,
        port: None,
        log_file: None,
        timeout: None,
        log_level: None,
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
            _ => {}
        }
        i += 1;
    }

    start_args
}

async fn handle_server_command(server_args: ServerArgs) -> Result<()> {
    let args = Args::from_start_args(&StartArgs {
        config: server_args.config,
        port: server_args.port,
        log_file: server_args.log_file,
        timeout: server_args.timeout,
        log_level: server_args.log_level,
    });

    match server_args.subcommand {
        ServerSubcommand::Install => {
            service::install_service(&args)?;
        }
        ServerSubcommand::Uninstall => {
            service::uninstall_service()?;
        }
        ServerSubcommand::Start => {
            service::start_service()?;
        }
        ServerSubcommand::Stop => {
            service::stop_service()?;
        }
        ServerSubcommand::Restart => {
            service::restart_service()?;
        }
    }

    Ok(())
}
