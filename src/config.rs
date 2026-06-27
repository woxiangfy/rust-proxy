//! Configuration module for loading and managing settings

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use tracing::Level;

/// Log level for tracing
#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[derive(PartialEq)]
pub enum LogLevel {
    #[default]
    Info,
    Debug,
    Warn,
    Error,
    Trace,
}

impl LogLevel {
    /// Convert to tracing::Level
    pub fn to_tracing_level(&self) -> Level {
        match self {
            LogLevel::Trace => Level::TRACE,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
        }
    }
}

impl std::str::FromStr for LogLevel {
    type Err = String;
    
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(format!("Invalid log level: {}", s)),
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "rust-proxy")]
#[command(about = "A simple HTTP proxy server")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(clap::Parser, Debug)]
pub struct StartArgs {
    #[arg(long)]
    pub config: Option<PathBuf>,

    #[arg(long)]
    pub port: Option<u16>,

    #[arg(long)]
    pub log_file: Option<PathBuf>,

    #[arg(long)]
    pub timeout: Option<u64>,

    #[arg(long)]
    pub log_level: Option<LogLevel>,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    Start(StartArgs),

    Test {
        proxy_addr: String,
        #[arg(default_value = "https://api.myip.la/cn")]
        url: String,
    },

    Server(ServerArgs),
}

#[derive(clap::Parser, Debug)]
pub struct ServerArgs {
    #[command(subcommand)]
    pub subcommand: ServerSubcommand,

    #[arg(long)]
    pub config: Option<PathBuf>,

    #[arg(long)]
    pub port: Option<u16>,

    #[arg(long)]
    pub log_file: Option<PathBuf>,

    #[arg(long)]
    pub timeout: Option<u64>,

    #[arg(long)]
    pub log_level: Option<LogLevel>,
}

#[derive(clap::Subcommand, Debug)]
pub enum ServerSubcommand {
    Install,
    Uninstall,
    Start,
    Stop,
    Restart,
}

#[derive(clap::Parser, Debug)]
pub struct RunAsServiceArgs {
    #[arg(long)]
    pub run_as_service: bool,

    #[arg(long)]
    pub config: Option<PathBuf>,

    #[arg(long)]
    pub port: Option<u16>,

    #[arg(long)]
    pub log_file: Option<PathBuf>,

    #[arg(long)]
    pub timeout: Option<u64>,

    #[arg(long)]
    pub log_level: Option<LogLevel>,
}

/// Final merged server configuration
#[derive(Debug, Clone)]
pub struct Args {
    pub port: u16,
    pub log_file: Option<PathBuf>,
    pub timeout: u64,
    pub log_level: LogLevel,
}

impl Args {
    pub const DEFAULT_PORT: u16 = 8080;
    pub const DEFAULT_TIMEOUT: u64 = 30;
    pub const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Info;
    pub const DEFAULT_CONFIG_FILE: &'static str = "config.toml";

    fn find_default_config() -> Option<PathBuf> {
        let config_path = std::env::current_dir().ok()?.join(Self::DEFAULT_CONFIG_FILE);
        if config_path.exists() && config_path.is_file() {
            Some(config_path)
        } else {
            None
        }
    }

    pub fn from_start_args(start_args: &StartArgs) -> Self {
        let config_path = start_args.config.clone().or_else(Self::find_default_config);
        let config = config_path.as_ref().and_then(|path| load_config(path).ok());

        Args {
            port: start_args.port
                .or(config.as_ref().and_then(|c| c.port))
                .unwrap_or(Self::DEFAULT_PORT),
            log_file: start_args.log_file.clone()
                .or(config.as_ref().and_then(|c| c.log_file.clone())),
            timeout: start_args.timeout
                .or(config.as_ref().and_then(|c| c.timeout))
                .unwrap_or(Self::DEFAULT_TIMEOUT),
            log_level: start_args.log_level
                .or(config.as_ref().and_then(|c| c.log_level))
                .unwrap_or(Self::DEFAULT_LOG_LEVEL),
        }
    }
}

/// Configuration loaded from TOML file
#[derive(Deserialize, Debug, Default)]
pub struct Config {
    /// Port to bind
    pub port: Option<u16>,
    /// Log file path
    pub log_file: Option<PathBuf>,
    /// Request timeout in seconds
    pub timeout: Option<u64>,
    /// Log level
    pub log_level: Option<LogLevel>,
}

/// Load configuration from a TOML file
pub fn load_config(config_path: &PathBuf) -> Result<Config> {
    let content = std::fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;
    let config: Config = toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", config_path.display()))?;
    Ok(config)
}