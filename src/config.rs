//! Configuration module for loading and managing settings

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;

/// Log level for logging
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

impl LogLevel {}

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

#[derive(clap::Parser, Debug, Clone)]
pub struct ServerRunArgs {
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

    /// 启用多线程运行时（默认使用单线程）
    #[arg(long)]
    pub multi_thread: bool,

    /// HTTPS 代理监听端口（启用 TLS 时需同时指定 --tls-cert 和 --tls-key）
    #[arg(long)]
    pub https_port: Option<u16>,

    /// TLS 证书文件路径（PEM 格式），需与 --tls-key 同时提供
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// TLS 私钥文件路径（PEM 格式），需与 --tls-cert 同时提供
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// 启用 PROXY Protocol 解析（v1/v2 自动检测）
    ///
    /// 适用于代理服务挂在 nginx/HAProxy 后面、通过 SNI 分流并使用
    /// `proxy_protocol on;` 转发真实客户端 IP 的场景。
    /// 启用后，每个接入连接会先解析 PROXY Protocol 头，提取真实客户端
    /// IP 用于日志和认证，而非使用 nginx/LB 的 IP。
    #[arg(long)]
    pub proxy_protocol: bool,

    /// PROXY Protocol 可信代理 IP 列表
    ///
    /// 仅当 `proxy_protocol` 启用时生效。仅接受来自这些 IP 的连接
    /// 发送的 PROXY Protocol 头，防止客户端伪造 IP。
    /// 示例：--proxy-protocol-trusted-ips 10.0.0.1,10.0.0.2
    #[arg(long, value_delimiter = ',')]
    pub proxy_protocol_trusted_ips: Vec<std::net::IpAddr>,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    Start(ServerRunArgs),

    Test {
        /// 代理服务器 URL，必须包含 http:// 或 https:// 协议头
        /// 例：http://10.0.0.1:8080 / https://10.0.0.1:8443
        /// 支持在 URL 中嵌入认证凭证：http://user:pass@host:port
        /// HTTPS 代理会跳过证书验证（等价于 curl --proxy-insecure），以支持自签证书
        proxy_url: String,
        /// 代理用户名（优先级高于 URL 中的 userinfo 部分）
        #[arg(long)]
        username: Option<String>,
        /// 代理密码（优先级高于 URL 中的 userinfo 部分）
        #[arg(long)]
        password: Option<String>,
        #[arg(default_value = "https://api.myip.la/cn")]
        url: String,
    },

    Server(ServerArgs),
}

#[derive(clap::Parser, Debug)]
pub struct ServerArgs {
    #[command(subcommand)]
    pub subcommand: ServerSubcommand,
}

#[derive(clap::Subcommand, Debug)]
pub enum ServerSubcommand {
    Install(ServerRunArgs),
    Uninstall,
    Start,
    Stop,
    Restart,
    Status,
}

#[derive(clap::Parser, Debug)]
pub struct RunAsServiceArgs {
    #[arg(long)]
    pub run_as_service: bool,

    #[command(flatten)]
    pub run_args: ServerRunArgs,
}

/// 单个代理认证用户
///
/// 通过配置文件的 `[[auth]]` 段定义。配置后，客户端必须通过 HTTP Basic 认证
/// （携带 `Proxy-Authorization` 头）才能使用代理。
#[derive(Deserialize, Debug, Clone)]
pub struct AuthUser {
    /// 用户名
    pub username: String,
    /// 密码（明文存储于配置文件中）
    pub password: String,
}

/// TLS 配置信息（证书+私钥+HTTPS监听端口）
///
/// **启用语义**：只有当用户**显式指定了 `https_port`**（命令行 `--https-port`
/// 或配置文件 `https_port`）时才会启用 HTTPS 代理。
/// 即使同时配置了 `tls_cert` + `tls_key` 但未指定 `https_port`，也**不会**启用 HTTPS。
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// HTTPS 代理监听端口
    pub https_port: u16,
    /// TLS 证书文件路径（PEM 格式），None 表示需自动生成自签证书
    pub cert_path: Option<PathBuf>,
    /// TLS 私钥文件路径（PEM 格式），None 表示需自动生成自签证书
    pub key_path: Option<PathBuf>,
}

/// Final merged server configuration
#[derive(Debug, Clone)]
pub struct Args {
    /// HTTP 代理监听端口
    ///
    /// - `Some(port)`：启用 HTTP 代理监听
    /// - `None`：不启用 HTTP 代理（仅在用户指定了 `https_port` 但未指定 `port` 时出现）
    pub port: Option<u16>,
    pub log_file: Option<PathBuf>,
    pub timeout: u64,
    pub log_level: LogLevel,
    pub multi_thread: bool,
    /// 代理认证用户列表。为 `None` 时不启用认证；为 `Some(空)` 时表示
    /// 配置了 `[auth]` 段但没有有效用户（此时任何客户端都无法通过认证）。
    pub auth: Option<Vec<AuthUser>>,
    /// TLS 配置。为 `None` 时不监听 HTTPS 端口。
    pub tls: Option<TlsConfig>,
    /// 是否启用 PROXY Protocol 解析（v1/v2 自动检测）
    pub proxy_protocol: bool,
    /// PROXY Protocol 可信代理 IP 列表（空列表表示不限制）
    pub proxy_protocol_trusted_ips: Vec<std::net::IpAddr>,
}

impl Args {
    pub const DEFAULT_PORT: u16 = 8080;
    pub const DEFAULT_TIMEOUT: u64 = 30;
    pub const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Info;
    pub const DEFAULT_CONFIG_FILE: &'static str = "config.toml";

    fn find_default_config() -> Option<PathBuf> {
        if let Ok(current_dir) = std::env::current_dir() {
            let config_path = current_dir.join(Self::DEFAULT_CONFIG_FILE);
            if config_path.exists() && config_path.is_file() {
                return Some(config_path);
            }
        }
        
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let config_path = exe_dir.join(Self::DEFAULT_CONFIG_FILE);
                if config_path.exists() && config_path.is_file() {
                    return Some(config_path);
                }
            }
        }
        
        None
    }

    pub fn from_run_args(run_args: &ServerRunArgs) -> Self {
        let config_path = run_args.config.clone().or_else(Self::find_default_config);
        let config = config_path.as_ref().and_then(|path| load_config(path).ok());

        let mut log_file = run_args.log_file.clone();
        if log_file.is_none() {
            if let Some(c) = &config {
                if let Some(lf) = &c.log_file {
                    log_file = Some(Self::resolve_log_file_path(lf, config_path.as_ref()));
                }
            }
        }

        // TLS 配置合并：命令行参数优先于配置文件
        // 新语义（严格）：
        //   只有用户**显式指定 https_port**（命令行 --https-port 或配置 https_port）
        //   才启用 HTTPS 代理。即使配置了 tls_cert + tls_key，未指定 https_port 也不启用。
        //   - https_port 已指定 + cert+key 完整 → 使用用户证书（支持热重载）
        //   - https_port 已指定 + cert/key 缺失/无效 → 自动生成 10 年自签证书
        //   - https_port 未指定 → 不启用 HTTPS（忽略 cert+key 配置）
        let https_port_from_cli = run_args.https_port;
        let https_port_from_config = config.as_ref().and_then(|c| c.https_port);
        let https_port = https_port_from_cli.or(https_port_from_config);

        let tls = if let Some(port) = https_port {
            // 用户显式启用了 HTTPS：携带 cert/key 路径（如有的话），由 server 层决定是否回退自签
            let cert_path = run_args
                .tls_cert
                .clone()
                .or_else(|| config.as_ref().and_then(|c| c.tls_cert.clone()))
                .map(|p| Self::resolve_path_relative_to_config(&p, config_path.as_ref()));
            let key_path = run_args
                .tls_key
                .clone()
                .or_else(|| config.as_ref().and_then(|c| c.tls_key.clone()))
                .map(|p| Self::resolve_path_relative_to_config(&p, config_path.as_ref()));
            Some(TlsConfig {
                https_port: port,
                cert_path,
                key_path,
            })
        } else {
            // 未指定 https_port：不启用 HTTPS（即使配置了 cert/key 也忽略）
            None
        };

        Args {
            // port 合并语义：
            //   - port 显式指定 → Some(port)
            //   - port 未指定 + https_port 显式指定 → None（仅 HTTPS 模式，不启用 HTTP）
            //   - port 未指定 + https_port 未指定 → Some(DEFAULT_PORT)（默认仅 HTTP 模式）
            port: match (
                run_args.port.or(config.as_ref().and_then(|c| c.port)),
                https_port.is_some(),
            ) {
                (Some(p), _) => Some(p),
                (None, true) => None,
                (None, false) => Some(Self::DEFAULT_PORT),
            },
            log_file,
            timeout: run_args.timeout
                .or(config.as_ref().and_then(|c| c.timeout))
                .unwrap_or(Self::DEFAULT_TIMEOUT),
            log_level: run_args.log_level
                .or(config.as_ref().and_then(|c| c.log_level))
                .unwrap_or(Self::DEFAULT_LOG_LEVEL),
            multi_thread: run_args.multi_thread
                || config.as_ref().map(|c| c.multi_thread).unwrap_or(false),
            // 认证信息仅来自配置文件（命令行不暴露用户名/密码）
            auth: config.as_ref().and_then(|c| c.auth.clone()),
            tls,
            proxy_protocol: run_args.proxy_protocol
                || config.as_ref().map(|c| c.proxy_protocol).unwrap_or(false),
            proxy_protocol_trusted_ips: {
                let cli_ips = run_args.proxy_protocol_trusted_ips.clone();
                if !cli_ips.is_empty() {
                    cli_ips
                } else {
                    config.as_ref()
                        .map(|c| c.proxy_protocol_trusted_ips.clone())
                        .unwrap_or_default()
                }
            },
        }
    }

    /// 将相对路径解析为绝对路径（相对于配置文件所在目录）
    fn resolve_path_relative_to_config(path: &PathBuf, config_path: Option<&PathBuf>) -> PathBuf {
        if path.is_absolute() {
            return path.clone();
        }

        if let Some(config_path) = config_path {
            if let Some(config_dir) = config_path.parent() {
                let resolved = config_dir.join(path);
                if let Ok(canonical) = resolved.canonicalize() {
                    return canonical;
                }
                return resolved;
            }
        }

        path.clone()
    }

    fn resolve_log_file_path(log_file: &PathBuf, config_path: Option<&PathBuf>) -> PathBuf {
        if log_file.is_absolute() {
            return log_file.clone();
        }

        if let Some(config_path) = config_path {
            if let Some(config_dir) = config_path.parent() {
                let resolved = config_dir.join(log_file);
                if let Ok(canonical) = resolved.canonicalize() {
                    return canonical;
                }
                return resolved;
            }
        }

        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                return exe_dir.join(log_file);
            }
        }

        log_file.clone()
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
    /// Use multi-threaded runtime
    #[serde(default)]
    pub multi_thread: bool,
    /// 代理认证用户列表。省略整个 `[[auth]]` 段时不启用认证。
    pub auth: Option<Vec<AuthUser>>,
    /// HTTPS 代理监听端口（需同时配置 tls_cert 和 tls_key）
    pub https_port: Option<u16>,
    /// TLS 证书文件路径（PEM 格式），需与 tls_key 同时配置
    pub tls_cert: Option<PathBuf>,
    /// TLS 私钥文件路径（PEM 格式），需与 tls_cert 同时配置
    pub tls_key: Option<PathBuf>,
    /// 是否启用 PROXY Protocol 解析（v1/v2 自动检测）
    #[serde(default)]
    pub proxy_protocol: bool,
    /// PROXY Protocol 可信代理 IP 列表（空列表表示不限制）
    #[serde(default)]
    pub proxy_protocol_trusted_ips: Vec<std::net::IpAddr>,
}

/// Load configuration from a TOML file
pub fn load_config(config_path: &PathBuf) -> Result<Config> {
    let content = std::fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;
    let config: Config = toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", config_path.display()))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_auth_multiple_users() {
        let toml_str = r#"
port = 8080

[[auth]]
username = "admin"
password = "secret"

[[auth]]
username = "user2"
password = "pass2"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let auth = config.auth.expect("auth should be present");
        assert_eq!(auth.len(), 2);
        assert_eq!(auth[0].username, "admin");
        assert_eq!(auth[0].password, "secret");
        assert_eq!(auth[1].username, "user2");
        assert_eq!(auth[1].password, "pass2");
    }

    #[test]
    fn test_parse_no_auth_keeps_backward_compatibility() {
        // 不配置 [[auth]] 段时应解析为 None，保持向后兼容
        let toml_str = r#"
port = 9090
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.auth.is_none());
    }

    #[test]
    fn test_parse_single_auth_user() {
        let toml_str = r#"
[[auth]]
username = "admin"
password = "p@ss"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let auth = config.auth.expect("auth should be present");
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0].username, "admin");
        assert_eq!(auth[0].password, "p@ss");
    }

    #[test]
    fn test_parse_tls_full_config() {
        // 完整 TLS 配置应正确解析
        let toml_str = r#"
port = 8080
https_port = 8443
tls_cert = "/etc/proxy/cert.pem"
tls_key = "/etc/proxy/key.pem"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.https_port, Some(8443));
        assert_eq!(
            config.tls_cert.as_ref().map(|p| p.display().to_string()),
            Some("/etc/proxy/cert.pem".into())
        );
        assert_eq!(
            config.tls_key.as_ref().map(|p| p.display().to_string()),
            Some("/etc/proxy/key.pem".into())
        );
    }

    #[test]
    fn test_parse_tls_partial_config_uses_default_port() {
        // 仅配置证书和私钥时，https_port 为 None，由 Args 合并时使用默认 8443
        let toml_str = r#"
tls_cert = "cert.pem"
tls_key = "key.pem"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.https_port.is_none());
        assert!(config.tls_cert.is_some());
        assert!(config.tls_key.is_some());
    }

    #[test]
    fn test_parse_no_tls_keeps_backward_compatibility() {
        // 不配置 TLS 字段时，所有 TLS 相关字段应为 None
        let toml_str = r#"
port = 8080
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.https_port.is_none());
        assert!(config.tls_cert.is_none());
        assert!(config.tls_key.is_none());
    }

    #[test]
    fn test_from_run_args_tls_enabled_when_both_cert_and_key_provided() {
        // 同时提供证书和私钥 + 显式 https_port → Args.tls 应为 Some
        let run_args = ServerRunArgs {
            config: None,
            port: Some(8080),
            log_file: None,
            timeout: None,
            log_level: None,
            multi_thread: false,
            https_port: Some(9443),
            tls_cert: Some("/tmp/cert.pem".into()),
            tls_key: Some("/tmp/key.pem".into()),
            proxy_protocol: false,
            proxy_protocol_trusted_ips: Vec::new(),
        };
        let args = Args::from_run_args(&run_args);
        let tls = args.tls.expect("TLS should be enabled");
        assert_eq!(tls.https_port, 9443);
        assert_eq!(
            tls.cert_path.as_ref().map(|p| p.display().to_string()),
            Some("/tmp/cert.pem".into())
        );
        assert_eq!(
            tls.key_path.as_ref().map(|p| p.display().to_string()),
            Some("/tmp/key.pem".into())
        );
    }

    #[test]
    fn test_from_run_args_tls_disabled_when_only_cert_provided() {
        // 新语义：显式 https_port → 必启用 HTTPS；
        // 仅提供 cert 而无 key（cert/key 不完整）→ Args.tls 仍为 Some，
        // cert_path=Some(key 文件缺失), key_path=None，由 server 层回退到自签证书
        let run_args = ServerRunArgs {
            config: None,
            port: Some(8080),
            log_file: None,
            timeout: None,
            log_level: None,
            multi_thread: false,
            https_port: Some(9443),
            tls_cert: Some("/tmp/cert.pem".into()),
            tls_key: None,
            proxy_protocol: false,
            proxy_protocol_trusted_ips: Vec::new(),
        };
        let args = Args::from_run_args(&run_args);
        let tls = args.tls.expect(
            "TLS should be enabled when https_port is explicitly set (even if only cert provided)",
        );
        assert_eq!(tls.https_port, 9443);
        assert!(tls.cert_path.is_some());
        assert!(tls.key_path.is_none());
    }

    #[test]
    fn test_from_run_args_tls_disabled_when_no_https_port_even_with_cert_and_key() {
        // 新语义（严格）：未指定 https_port → 不启用 HTTPS，
        // 即使同时提供了 cert + key 也必须忽略
        let run_args = ServerRunArgs {
            config: None,
            port: Some(8080),
            log_file: None,
            timeout: None,
            log_level: None,
            multi_thread: false,
            https_port: None,
            tls_cert: Some("/tmp/cert.pem".into()),
            tls_key: Some("/tmp/key.pem".into()),
            proxy_protocol: false,
            proxy_protocol_trusted_ips: Vec::new(),
        };
        let args = Args::from_run_args(&run_args);
        assert!(
            args.tls.is_none(),
            "TLS must NOT be enabled when https_port is not specified, even with cert+key"
        );
    }

    #[test]
    fn test_from_run_args_command_line_overrides_config_tls() {
        // 命令行参数的 https_port 应优先于配置文件
        // 使用相对路径的证书文件（相对于配置文件目录解析）
        let toml_str = r#"
port = 8080
https_port = 8443
tls_cert = "cert.pem"
tls_key = "key.pem"
"#;
        let tmp_dir = std::env::temp_dir().join("test_tls_override_dir");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let config_file = tmp_dir.join("config.toml");
        std::fs::write(&config_file, toml_str).unwrap();

        let run_args = ServerRunArgs {
            config: Some(config_file.clone()),
            port: None,
            log_file: None,
            timeout: None,
            log_level: None,
            multi_thread: false,
            https_port: Some(9999), // 命令行覆盖
            tls_cert: None,
            tls_key: None,
            proxy_protocol: false,
            proxy_protocol_trusted_ips: Vec::new(),
        };
        let args = Args::from_run_args(&run_args);
        let tls = args.tls.expect("TLS should be enabled");
        assert_eq!(tls.https_port, 9999, "命令行 https_port 应覆盖配置文件");
        // 证书路径应解析为配置文件目录下的相对路径
        assert_eq!(tls.cert_path, Some(tmp_dir.join("cert.pem")));
        assert_eq!(tls.key_path, Some(tmp_dir.join("key.pem")));
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_port_none_when_only_https_port_specified() {
        // 新语义：指定 https_port 但未指定 port → args.port == None（仅 HTTPS 模式）
        let run_args = ServerRunArgs {
            config: None,
            port: None,
            log_file: None,
            timeout: None,
            log_level: None,
            multi_thread: false,
            https_port: Some(8443),
            tls_cert: None,
            tls_key: None,
            proxy_protocol: false,
            proxy_protocol_trusted_ips: Vec::new(),
        };
        let args = Args::from_run_args(&run_args);
        assert_eq!(args.port, None, "port must be None when only https_port is specified");
        assert!(args.tls.is_some(), "TLS must be enabled");
    }

    #[test]
    fn test_port_uses_default_when_neither_specified() {
        // 都未指定 → args.port == Some(DEFAULT_PORT)（默认仅 HTTP 模式）
        let run_args = ServerRunArgs {
            config: None,
            port: None,
            log_file: None,
            timeout: None,
            log_level: None,
            multi_thread: false,
            https_port: None,
            tls_cert: None,
            tls_key: None,
            proxy_protocol: false,
            proxy_protocol_trusted_ips: Vec::new(),
        };
        let args = Args::from_run_args(&run_args);
        assert_eq!(args.port, Some(Args::DEFAULT_PORT));
        assert!(args.tls.is_none(), "TLS must be disabled when https_port not specified");
    }

    #[test]
    fn test_port_explicit_overrides_default() {
        // 显式指定 port → 使用指定值（即使 https_port 也指定）
        let run_args = ServerRunArgs {
            config: None,
            port: Some(9090),
            log_file: None,
            timeout: None,
            log_level: None,
            multi_thread: false,
            https_port: Some(8443),
            tls_cert: None,
            tls_key: None,
            proxy_protocol: false,
            proxy_protocol_trusted_ips: Vec::new(),
        };
        let args = Args::from_run_args(&run_args);
        assert_eq!(args.port, Some(9090), "explicit port should be preserved");
        assert!(args.tls.is_some());
    }

    #[test]
    fn test_port_from_config_when_only_port_in_config() {
        // 配置文件指定 port 但未指定 https_port → args.port == Some(配置 port)
        let toml_str = r#"
port = 7777
"#;
        let tmp_dir = std::env::temp_dir().join("test_port_from_config_dir");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let config_file = tmp_dir.join("config.toml");
        std::fs::write(&config_file, toml_str).unwrap();

        let run_args = ServerRunArgs {
            config: Some(config_file.clone()),
            port: None,
            log_file: None,
            timeout: None,
            log_level: None,
            multi_thread: false,
            https_port: None,
            tls_cert: None,
            tls_key: None,
            proxy_protocol: false,
            proxy_protocol_trusted_ips: Vec::new(),
        };
        let args = Args::from_run_args(&run_args);
        assert_eq!(args.port, Some(7777));
        assert!(args.tls.is_none());
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    // ─── PROXY Protocol 可信 IP 测试 ───

    #[test]
    fn test_parse_proxy_protocol_trusted_ips_from_config() {
        let toml_str = r#"
port = 8080
proxy_protocol = true
proxy_protocol_trusted_ips = ["10.0.0.1", "192.168.1.100"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.proxy_protocol);
        assert_eq!(config.proxy_protocol_trusted_ips.len(), 2);
        assert_eq!(
            config.proxy_protocol_trusted_ips[0],
            "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            config.proxy_protocol_trusted_ips[1],
            "192.168.1.100".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_parse_proxy_protocol_trusted_ips_default_empty() {
        let toml_str = r#"
port = 8080
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.proxy_protocol_trusted_ips.is_empty());
    }

    #[test]
    fn test_from_run_args_proxy_protocol_trusted_ips_cli_override() {
        // CLI 参数应覆盖配置文件中的可信 IP
        let toml_str = r#"
port = 8080
proxy_protocol = true
proxy_protocol_trusted_ips = ["10.0.0.1"]
"#;
        let tmp_dir = std::env::temp_dir().join("test_pp_trusted_ips_dir");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let config_file = tmp_dir.join("config.toml");
        std::fs::write(&config_file, toml_str).unwrap();

        let cli_ips = vec![
            "192.168.1.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
        ];
        let run_args = ServerRunArgs {
            config: Some(config_file.clone()),
            port: None,
            log_file: None,
            timeout: None,
            log_level: None,
            multi_thread: false,
            https_port: None,
            tls_cert: None,
            tls_key: None,
            proxy_protocol: true,
            proxy_protocol_trusted_ips: cli_ips.clone(),
        };
        let args = Args::from_run_args(&run_args);
        assert_eq!(args.proxy_protocol_trusted_ips, cli_ips);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_from_run_args_proxy_protocol_trusted_ips_from_config() {
        // CLI 未指定时应使用配置文件中的可信 IP
        let toml_str = r#"
port = 8080
proxy_protocol = true
proxy_protocol_trusted_ips = ["10.0.0.1", "10.0.0.2"]
"#;
        let tmp_dir = std::env::temp_dir().join("test_pp_trusted_ips_dir2");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let config_file = tmp_dir.join("config.toml");
        std::fs::write(&config_file, toml_str).unwrap();

        let run_args = ServerRunArgs {
            config: Some(config_file.clone()),
            port: None,
            log_file: None,
            timeout: None,
            log_level: None,
            multi_thread: false,
            https_port: None,
            tls_cert: None,
            tls_key: None,
            proxy_protocol: true,
            proxy_protocol_trusted_ips: Vec::new(),
        };
        let args = Args::from_run_args(&run_args);
        assert_eq!(args.proxy_protocol_trusted_ips.len(), 2);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}