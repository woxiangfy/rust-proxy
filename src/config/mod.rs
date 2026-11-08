//! 配置层：模型定义、加载、CLI 合并与运行时派生

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;

// `LogLevel` 属于日志域，定义在 `logging` 模块（见 B4）。
// 这里重新导出，既保持 `config::LogLevel` 这个既有路径可用，又让依赖方向变成
// `config → support::logging`（单向），避免 logging 为了一个枚举反查配置模块。
pub use crate::support::logging::LogLevel;

// 声明层：配置项的唯一真源。`ServerRunArgs` / `Config` / `ServiceArgs`
// 均由 `src/config/schema.rs` 的字段表生成，这里重导出以保持既有路径
// `config::ServerRunArgs` / `config::Config` 不变。
mod schema;
pub use schema::{Config, ServerRunArgs, ServiceArgs};

#[derive(Parser, Debug)]
#[command(name = "rust-proxy")]
#[command(about = "A simple HTTP proxy server")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolMode {
    /// 完全禁用 PROXY Protocol
    Disable,
    /// 自动检测（默认）：连接开头匹配 PROXY v1/v2 签名时解析，否则按普通流量处理
    #[default]
    Auto,
    /// 强制要求：所有连接必须以 PROXY Protocol 头开头，否则断开
    Require,
}

impl std::fmt::Display for ProxyProtocolMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyProtocolMode::Disable => write!(f, "disable"),
            ProxyProtocolMode::Auto => write!(f, "auto"),
            ProxyProtocolMode::Require => write!(f, "require"),
        }
    }
}

impl std::str::FromStr for ProxyProtocolMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "disable" | "off" | "false" => Ok(ProxyProtocolMode::Disable),
            "auto" | "detect" => Ok(ProxyProtocolMode::Auto),
            "require" | "on" | "true" | "forced" => Ok(ProxyProtocolMode::Require),
            _ => Err(format!(
                "Invalid proxy_protocol mode: {} (valid: disable, auto, require)",
                s
            )),
        }
    }
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

/// 服务管理子命令
///
/// `Install` 携带完整的运行参数（与 `start` 一致），因此该枚举各变体大小差异较大；
/// 枚举仅在启动时构造一次，装箱带来的间接访问反而无收益。
#[allow(clippy::large_enum_variant)]
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
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuthUser {
    /// 用户名
    pub username: String,
    /// 密码（明文存储于配置文件中）
    pub password: String,
}

/// 手写 `Debug`：密码不进入任何日志或调试输出（安全不变量）。
impl std::fmt::Debug for AuthUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthUser")
            .field("username", &self.username)
            .field("password", &"***")
            .finish()
    }
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
    /// HTTP 端口实际使用的 PROXY Protocol 模式（缺省回退到全局默认）
    pub http_proxy_protocol: ProxyProtocolMode,
    /// HTTPS 端口实际使用的 PROXY Protocol 模式（缺省回退到全局默认）
    pub https_proxy_protocol: ProxyProtocolMode,
    /// PROXY Protocol 全局默认模式（供日志/回退使用；http/https 字段已给出每个端口的最终值）
    pub proxy_protocol: ProxyProtocolMode,
    /// PROXY Protocol 可信代理 IP 列表（空列表表示不限制）
    pub proxy_protocol_trusted_ips: Vec<std::net::IpAddr>,
    /// 路径前缀直连模式的前缀（`None` 表示不启用该模式）
    ///
    /// 启用后 `/px/https://example.com/` 这类请求会由代理服务器直连上游并回传内容。
    /// 前缀合法性在 `server` 层构造 [`crate::protocol::path_proxy::PathProxyConfig`] 时校验。
    pub path_proxy_prefix: Option<String>,
    /// 路径前缀直连模式是否跳过上游 TLS 证书校验
    pub path_proxy_insecure_tls: bool,
    /// 路径前缀直连模式是否重写 3xx 响应的 `Location`（默认 true）
    pub path_proxy_rewrite_location: bool,
}

impl Args {
    pub const DEFAULT_PORT: u16 = 8080;
    pub const DEFAULT_TIMEOUT: u64 = 30;
    pub const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Info;
    pub const DEFAULT_CONFIG_FILE: &'static str = "config.toml";

    /// 启动前校验运行时配置
    ///
    /// 把「至少启用一个端口」与「HTTP/HTTPS 端口冲突」前移到配置层：
    /// 错误文案保持与 `server` 原先的实现逐字一致，调用方只需在绑定端口前
    /// 调一次。证书缺失/加载失败不在这里处理——那是自签回退路径，不是配置错误。
    pub fn validate(&self) -> Result<()> {
        if self.timeout == 0 {
            anyhow::bail!("timeout must be greater than 0 (got 0)");
        }

        if self.port.is_none() && self.tls.is_none() {
            anyhow::bail!(
                "Neither HTTP nor HTTPS proxy is enabled. Specify --port and/or --https-port."
            );
        }

        if let (Some(http_port), Some(tls)) = (self.port, self.tls.as_ref()) {
            if http_port == tls.https_port {
                anyhow::bail!(
                    "HTTP port {} conflicts with HTTPS port {}; please specify different ports",
                    http_port,
                    tls.https_port
                );
            }
        }

        Ok(())
    }

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

    /// 从 CLI 子集解析出运行时配置
    ///
    /// 流程：加载 TOML（唯一完整模型）→ CLI 覆盖进配置 → 派生运行时视图。
    /// 配置文件是核心信息：显式指定或自动发现到的文件读取/解析失败都直接返回错误；
    /// 只有在完全没有找到配置文件时，才按 CLI 与默认值启动。
    pub fn from_run_args(run_args: &ServerRunArgs) -> Result<Self> {
        let config_path = run_args.config.clone().or_else(Self::find_default_config);
        let mut config = match config_path.as_ref() {
            Some(path) => load_config(path)?,
            None => Config::default(),
        };
        config.apply_cli(run_args)?;
        Ok(Self::from_config(&config, config_path.as_ref()))
    }

    /// 由有效 TOML 配置派生运行时视图（默认值、端口规则、TLS、PROXY Protocol）
    ///
    /// 这里只做派生，不再引入第二套并行配置来源。
    fn from_config(config: &Config, config_path: Option<&PathBuf>) -> Self {
        // TLS 启用语义（严格）：
        //   只有显式 https_port 才启用 HTTPS；cert/key 缺失由 server 层回退自签证书。
        //   未指定 https_port 时忽略 cert/key。
        let tls = config.https_port.map(|port| TlsConfig {
            https_port: port,
            cert_path: config
                .tls_cert
                .as_ref()
                .map(|p| Self::resolve_path_relative_to_config(p, config_path)),
            key_path: config
                .tls_key
                .as_ref()
                .map(|p| Self::resolve_path_relative_to_config(p, config_path)),
        });

        let global_pp = config.proxy_protocol_mode.unwrap_or(ProxyProtocolMode::Auto);

        Self {
            // port 派生语义：
            //   - port 显式指定 → Some(port)
            //   - port 未指定 + https_port 指定 → None（仅 HTTPS 模式，不启用 HTTP）
            //   - port 未指定 + https_port 未指定 → Some(DEFAULT_PORT)（默认仅 HTTP 模式）
            port: match (config.port, config.https_port.is_some()) {
                (Some(p), _) => Some(p),
                (None, true) => None,
                (None, false) => Some(Self::DEFAULT_PORT),
            },
            log_file: config
                .log_file
                .as_ref()
                .map(|lf| Self::resolve_log_file_path(lf, config_path)),
            timeout: config.timeout.unwrap_or(Self::DEFAULT_TIMEOUT),
            log_level: config.log_level.unwrap_or(Self::DEFAULT_LOG_LEVEL),
            multi_thread: config.multi_thread,
            // 认证信息仅来自配置文件（命令行不暴露用户名/密码）
            auth: config.auth.clone(),
            tls,
            // PROXY Protocol：http/https 端口使用全局默认或各自覆盖值
            http_proxy_protocol: config.http_proxy_protocol.unwrap_or(global_pp),
            https_proxy_protocol: config.https_proxy_protocol.unwrap_or(global_pp),
            proxy_protocol: global_pp,
            proxy_protocol_trusted_ips: config.proxy_protocol_trusted_ips.clone(),
            path_proxy_prefix: config.path_proxy_prefix.clone(),
            path_proxy_insecure_tls: config.path_proxy_insecure_tls,
            path_proxy_rewrite_location: config.path_proxy_rewrite_location.unwrap_or(true),
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

    /// 日志文件路径解析：相对配置目录，其次相对可执行文件目录
    ///
    /// 与 [`Self::resolve_path_relative_to_config`] 的差别只在最后一级回退：日志文件
    /// 在"没有配置文件"时仍需要一个稳定落点。服务模式下工作目录不可靠
    /// （Windows SCM 默认 `System32`、systemd 默认 `/`），因此回退到可执行文件同目录，
    /// 而不是 `cwd`。
    fn resolve_log_file_path(log_file: &PathBuf, config_path: Option<&PathBuf>) -> PathBuf {
        if log_file.is_absolute() {
            return log_file.clone();
        }

        // 有配置文件时与证书/密钥走同一套解析规则（内含 canonicalize 尝试）
        if config_path.and_then(|c| c.parent()).is_some() {
            return Self::resolve_path_relative_to_config(log_file, config_path);
        }

        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                return exe_dir.join(log_file);
            }
        }

        log_file.clone()
    }
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

    /// 至少启用一个端口的校验：错误文案必须与 `server` 原先的实现逐字一致
    #[test]
    fn test_validate_requires_at_least_one_port() {
        let args = Args {
            port: None,
            log_file: None,
            timeout: Args::DEFAULT_TIMEOUT,
            log_level: Args::DEFAULT_LOG_LEVEL,
            multi_thread: false,
            auth: None,
            tls: None,
            http_proxy_protocol: ProxyProtocolMode::Auto,
            https_proxy_protocol: ProxyProtocolMode::Auto,
            proxy_protocol: ProxyProtocolMode::Auto,
            proxy_protocol_trusted_ips: Vec::new(),
            path_proxy_prefix: None,
            path_proxy_insecure_tls: false,
            path_proxy_rewrite_location: true,
        };
        let err = args.validate().expect_err("no listener must fail");
        assert_eq!(
            err.to_string(),
            "Neither HTTP nor HTTPS proxy is enabled. Specify --port and/or --https-port."
        );
    }

    /// 端口冲突校验：仅在 HTTP 与 HTTPS 同时启用时触发
    #[test]
    fn test_validate_rejects_port_conflict() {
        let run_args = ServerRunArgs {
            port: Some(18080),
            https_port: Some(18080),
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        let err = args.validate().expect_err("port conflict must fail");
        assert_eq!(
            err.to_string(),
            "HTTP port 18080 conflicts with HTTPS port 18080; please specify different ports"
        );
    }

    /// `timeout = 0` 会让每一次读/写都在零时限内失败（写方向接入超时后尤其明显：
    /// 连错误响应都写不出去），必须在启动时拒绝而不是带着坏配置跑起来。
    #[test]
    fn test_validate_rejects_zero_timeout() {
        let args = Args::from_run_args(&ServerRunArgs {
            port: Some(8080),
            timeout: Some(0),
            ..Default::default()
        })
        .unwrap();
        let err = args.validate().expect_err("timeout=0 must fail");
        assert_eq!(err.to_string(), "timeout must be greater than 0 (got 0)");
    }

    /// 仅 HTTPS（无 HTTP 端口）与双端口不冲突时校验通过
    #[test]
    fn test_validate_allows_only_https_and_distinct_ports() {
        let only_https = Args::from_run_args(&ServerRunArgs {
            https_port: Some(9443),
            ..Default::default()
        })
        .unwrap();
        only_https.validate().expect("only HTTPS must be valid");

        let both = Args::from_run_args(&ServerRunArgs {
            port: Some(8080),
            https_port: Some(9443),
            ..Default::default()
        })
        .unwrap();
        both.validate().expect("distinct ports must be valid");
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
        // 仅配置证书和私钥时，https_port 为 None，不启用 HTTPS
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
            port: Some(8080),
            https_port: Some(9443),
            tls_cert: Some("/tmp/cert.pem".into()),
            tls_key: Some("/tmp/key.pem".into()),
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
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
            port: Some(8080),
            https_port: Some(9443),
            tls_cert: Some("/tmp/cert.pem".into()),
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
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
            port: Some(8080),
            tls_cert: Some("/tmp/cert.pem".into()),
            tls_key: Some("/tmp/key.pem".into()),
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
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
            https_port: Some(9999), // 命令行覆盖
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
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
            https_port: Some(8443),
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        assert_eq!(args.port, None, "port must be None when only https_port is specified");
        assert!(args.tls.is_some(), "TLS must be enabled");
    }

    #[test]
    fn test_port_uses_default_when_neither_specified() {
        // 都未指定 → args.port == Some(DEFAULT_PORT)（默认仅 HTTP 模式）
        let run_args = ServerRunArgs {
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        assert_eq!(args.port, Some(Args::DEFAULT_PORT));
        assert!(args.tls.is_none(), "TLS must be disabled when https_port not specified");
    }

    #[test]
    fn test_port_explicit_overrides_default() {
        // 显式指定 port → 使用指定值（即使 https_port 也指定）
        let run_args = ServerRunArgs {
            port: Some(9090),
            https_port: Some(8443),
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
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
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        assert_eq!(args.port, Some(7777));
        assert!(args.tls.is_none());
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    // ─── PROXY Protocol 可信 IP 测试 ───

    #[test]
    fn test_parse_proxy_protocol_trusted_ips_from_config() {
        let toml_str = r#"
port = 8080
proxy_protocol_mode = "auto"
proxy_protocol_trusted_ips = ["10.0.0.1", "192.168.1.100"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.proxy_protocol_mode,
            Some(ProxyProtocolMode::Auto)
        );
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
            proxy_protocol: true,
            proxy_protocol_trusted_ips: cli_ips.clone(),
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        assert_eq!(args.proxy_protocol_trusted_ips, cli_ips);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_from_run_args_proxy_protocol_trusted_ips_from_config() {
        // CLI 未指定时应使用配置文件中的可信 IP
        let toml_str = r#"
port = 8080
proxy_protocol_trusted_ips = ["10.0.0.1", "10.0.0.2"]
"#;
        let tmp_dir = std::env::temp_dir().join("test_pp_trusted_ips_dir2");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let config_file = tmp_dir.join("config.toml");
        std::fs::write(&config_file, toml_str).unwrap();

        let run_args = ServerRunArgs {
            config: Some(config_file.clone()),
            proxy_protocol: true,
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        assert_eq!(args.proxy_protocol_trusted_ips.len(), 2);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    // ─── ProxyProtocolMode 枚举单元测试 ───

    #[test]
    fn test_pp_mode_default_is_auto() {
        let run_args = ServerRunArgs {
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        assert_eq!(args.proxy_protocol, ProxyProtocolMode::Auto);
    }

    #[test]
    fn test_pp_mode_cli_flag_true_is_auto() {
        // 旧 `--proxy-protocol` 布尔参数现在映射为 Auto（全自动识别），不再强制 Require
        let run_args = ServerRunArgs {
            proxy_protocol: true,
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        assert_eq!(args.proxy_protocol, ProxyProtocolMode::Auto);
    }

    #[test]
    fn test_pp_mode_cli_mode_overrides_flag() {
        let run_args = ServerRunArgs {
            proxy_protocol_mode: Some(ProxyProtocolMode::Auto),
            proxy_protocol: true,
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        assert_eq!(args.proxy_protocol, ProxyProtocolMode::Auto);
    }

    #[test]
    fn test_pp_mode_from_config_mode_field() {
        let toml_str = r#"
port = 8080
proxy_protocol_mode = "auto"
"#;
        let tmp_dir = std::env::temp_dir().join("test_pp_mode_cfg");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let config_file = tmp_dir.join("config.toml");
        std::fs::write(&config_file, toml_str).unwrap();

        let run_args = ServerRunArgs {
            config: Some(config_file.clone()),
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        assert_eq!(args.proxy_protocol, ProxyProtocolMode::Auto);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_pp_mode_unknown_legacy_key_is_fatal() {
        // 旧的布尔 `proxy_protocol = true` 已从 Config 移除；现在它属于未知键，
        // 配置文件解析失败，必须直接退出而不是静默按默认值启动。
        let toml_str = r#"
port = 8080
proxy_protocol = true
"#;
        let tmp_dir = std::env::temp_dir().join("test_pp_mode_flag_cfg");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let config_file = tmp_dir.join("config.toml");
        std::fs::write(&config_file, toml_str).unwrap();

        let run_args = ServerRunArgs {
            config: Some(config_file.clone()),
            ..Default::default()
        };
        assert!(
            Args::from_run_args(&run_args).is_err(),
            "unknown legacy key must fail closed"
        );
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_pp_mode_http_https_independent_overrides() {
        // 全局默认 auto，http 覆盖为 disable、https 覆盖为 require，
        // 两个端口应各自使用覆盖值，互不影响
        let toml_str = r#"
port = 8080
proxy_protocol_mode = "auto"
http_proxy_protocol = "disable"
https_proxy_protocol = "require"
"#;
        let tmp_dir = std::env::temp_dir().join("test_pp_mode_http_https_cfg");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let config_file = tmp_dir.join("config.toml");
        std::fs::write(&config_file, toml_str).unwrap();

        let run_args = ServerRunArgs {
            config: Some(config_file.clone()),
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        // 全局默认仍为 auto
        assert_eq!(args.proxy_protocol, ProxyProtocolMode::Auto);
        // http/https 各用覆盖值
        assert_eq!(args.http_proxy_protocol, ProxyProtocolMode::Disable);
        assert_eq!(args.https_proxy_protocol, ProxyProtocolMode::Require);

        // 未配置覆盖时，两端都回退到全局默认
        let toml_str2 = r#"
port = 8080
proxy_protocol_mode = "auto"
"#;
        std::fs::write(&config_file, toml_str2).unwrap();
        let args2 = Args::from_run_args(&ServerRunArgs {
            config: Some(config_file.clone()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(args2.http_proxy_protocol, ProxyProtocolMode::Auto);
        assert_eq!(args2.https_proxy_protocol, ProxyProtocolMode::Auto);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_pp_mode_config_disable_overrides_default_auto() {
        // 默认是 Auto，但配置文件显式指定 disable 应覆盖默认
        let toml_str = r#"
port = 8080
proxy_protocol_mode = "disable"
"#;
        let tmp_dir = std::env::temp_dir().join("test_pp_mode_disable_cfg");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let config_file = tmp_dir.join("config.toml");
        std::fs::write(&config_file, toml_str).unwrap();

        let run_args = ServerRunArgs {
            config: Some(config_file.clone()),
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        assert_eq!(args.proxy_protocol, ProxyProtocolMode::Disable);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_pp_mode_fromstr_aliases() {
        use std::str::FromStr;
        assert_eq!(
            ProxyProtocolMode::from_str("disable").unwrap(),
            ProxyProtocolMode::Disable
        );
        assert_eq!(
            ProxyProtocolMode::from_str("off").unwrap(),
            ProxyProtocolMode::Disable
        );
        assert_eq!(
            ProxyProtocolMode::from_str("false").unwrap(),
            ProxyProtocolMode::Disable
        );
        assert_eq!(
            ProxyProtocolMode::from_str("auto").unwrap(),
            ProxyProtocolMode::Auto
        );
        assert_eq!(
            ProxyProtocolMode::from_str("detect").unwrap(),
            ProxyProtocolMode::Auto
        );
        assert_eq!(
            ProxyProtocolMode::from_str("require").unwrap(),
            ProxyProtocolMode::Require
        );
        assert_eq!(
            ProxyProtocolMode::from_str("on").unwrap(),
            ProxyProtocolMode::Require
        );
        assert_eq!(
            ProxyProtocolMode::from_str("true").unwrap(),
            ProxyProtocolMode::Require
        );
        assert!(ProxyProtocolMode::from_str("invalid").is_err());
    }

    #[test]
    fn test_pp_mode_display_roundtrip() {
        for mode in [
            ProxyProtocolMode::Disable,
            ProxyProtocolMode::Auto,
            ProxyProtocolMode::Require,
        ] {
            let s = mode.to_string();
            assert_eq!(s.parse::<ProxyProtocolMode>().unwrap(), mode);
        }
    }

    // ─── 路径前缀直连模式配置测试 ───

    #[test]
    fn test_parse_path_proxy_from_config() {
        let toml_str = r#"
port = 8080
path_proxy_prefix = "px"
path_proxy_insecure_tls = true
path_proxy_rewrite_location = false
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.path_proxy_prefix.as_deref(), Some("px"));
        assert!(config.path_proxy_insecure_tls);
        assert_eq!(config.path_proxy_rewrite_location, Some(false));
    }

    #[test]
    fn test_path_proxy_defaults_when_absent() {
        // 未配置时：模式关闭、默认校验证书、默认重写 Location
        let config: Config = toml::from_str("port = 8080\n").unwrap();
        assert!(config.path_proxy_prefix.is_none());
        assert!(!config.path_proxy_insecure_tls);
        assert_eq!(config.path_proxy_rewrite_location, None);
    }

    #[test]
    fn test_from_run_args_path_proxy_cli_overrides_config() {
        let toml_str = r#"
port = 8080
path_proxy_prefix = "from-config"
path_proxy_rewrite_location = false
"#;
        let tmp_dir = std::env::temp_dir().join("test_path_proxy_cli_dir");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let config_file = tmp_dir.join("config.toml");
        std::fs::write(&config_file, toml_str).unwrap();

        let run_args = ServerRunArgs {
            config: Some(config_file.clone()),
            proxy_protocol_trusted_ips: Vec::new(),
            path_proxy_prefix: Some("px".into()),
            path_proxy_insecure: true,
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        assert_eq!(
            args.path_proxy_prefix.as_deref(),
            Some("px"),
            "CLI 前缀应覆盖配置文件"
        );
        assert!(args.path_proxy_insecure_tls);
        assert!(
            !args.path_proxy_rewrite_location,
            "配置文件的关闭开关应生效"
        );
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_from_run_args_path_proxy_disabled_by_default() {
        let run_args = ServerRunArgs {
            ..Default::default()
        };
        let args = Args::from_run_args(&run_args).unwrap();
        assert!(args.path_proxy_prefix.is_none());
        assert!(args.path_proxy_rewrite_location, "默认应重写 Location");
    }

    // ─── 路径解析（C2 合并后的一致性） ───

    #[test]
    fn test_resolve_keeps_absolute_paths() {
        let abs = std::env::temp_dir().join("abs.log");
        let cfg = std::env::temp_dir().join("config.toml");
        assert_eq!(Args::resolve_log_file_path(&abs, Some(&cfg)), abs);
        assert_eq!(
            Args::resolve_path_relative_to_config(&abs, Some(&cfg)),
            abs,
            "绝对路径不应被改写"
        );
    }

    #[test]
    fn test_resolve_relative_to_config_dir() {
        let dir = std::env::temp_dir().join("rust_proxy_cfg_resolve");
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.toml");
        let rel = std::path::PathBuf::from("proxy.log");

        // 日志与证书走同一套规则：相对配置文件所在目录
        assert_eq!(
            Args::resolve_log_file_path(&rel, Some(&cfg)),
            dir.join("proxy.log")
        );
        assert_eq!(
            Args::resolve_path_relative_to_config(&rel, Some(&cfg)),
            dir.join("proxy.log")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_resolve_log_file_falls_back_to_exe_dir() {
        // 无配置文件时日志落到可执行文件同目录（服务模式下 cwd 不可靠）
        let rel = std::path::PathBuf::from("fallback.log");
        let resolved = Args::resolve_log_file_path(&rel, None);
        assert!(resolved.is_absolute(), "应返回绝对路径：{resolved:?}");
        assert!(resolved.ends_with("fallback.log"));
    }

    // ─── 严格解析：拼错/放错键必须报错（而非静默忽略） ───

    #[test]
    fn test_config_rejects_unknown_key() {
        let dir = std::env::temp_dir().join("rust_proxy_cfg_unknown");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("config.toml");
        // 典型拼写错误：proxy_protocal_mode（少一个 o）
        std::fs::write(&f, "proxy_protocal_mode = \"auto\"\n").unwrap();
        let err = load_config(&f).expect_err("拼错的键必须报错");
        assert!(
            format!("{err:#}").contains("Failed to parse config"),
            "错误信息应指出解析失败：{err:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_config_rejects_wrong_value_type() {
        // 风险：类型错误（如把端口写成字符串）必须失败关闭，不能静默落回默认值——
        // 静默降级会让用户以为改过了，实际仍监听旧端口。
        let dir = std::env::temp_dir().join("rust_proxy_cfg_wrong_type");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("config.toml");
        std::fs::write(&f, "port = \"8080\"\n").unwrap();
        let err = load_config(&f).expect_err("类型错误必须报错");
        assert!(
            format!("{err:#}").contains("Failed to parse config"),
            "错误信息应指出解析失败：{err:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_config_rejects_top_level_key_placed_after_auth_table() {
        // TOML 语义：开过 [[auth]] 之后写的键都属于该数组元素。
        // 把顶层键写在其后会被当成 AuthUser 的字段，必须报错，
        // 否则用户会以为"路径前缀已启用"而实际没有。
        let dir = std::env::temp_dir().join("rust_proxy_cfg_misplaced");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("config.toml");
        std::fs::write(
            &f,
            "[[auth]]\nusername = \"a\"\npassword = \"b\"\npath_proxy_prefix = \"px\"\n",
        )
        .unwrap();
        assert!(load_config(&f).is_err(), "错位的键必须报错");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── fail-closed：配置是核心信息，读取/解析失败必须退出 ───

    #[test]
    fn test_missing_explicit_config_is_fatal() {
        let missing = std::env::temp_dir().join("rust_proxy_missing_config.toml");
        let _ = std::fs::remove_file(&missing);
        let run_args = ServerRunArgs {
            config: Some(missing),
            ..Default::default()
        };
        assert!(
            Args::from_run_args(&run_args).is_err(),
            "显式指定的配置文件不存在时必须失败"
        );
    }

    #[test]
    fn test_invalid_config_is_fatal_from_run_args() {
        let dir = std::env::temp_dir().join("rust_proxy_fail_closed");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("config.toml");
        std::fs::write(&f, "proxy_protocal_mode = \"auto\"\n").unwrap();
        let run_args = ServerRunArgs {
            config: Some(f),
            ..Default::default()
        };
        let err = Args::from_run_args(&run_args).expect_err("损坏的配置必须失败");
        assert!(
            format!("{err:#}").contains("Failed to parse config"),
            "错误信息应指出解析失败：{err:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── 敏感信息：密码不得进入 Debug/日志 ───

    #[test]
    fn test_auth_password_is_redacted_in_debug() {
        let user = AuthUser {
            username: "admin".into(),
            password: "top-secret".into(),
        };
        let user_debug = format!("{user:?}");
        assert!(!user_debug.contains("top-secret"));
        assert!(user_debug.contains("***"));

        let config = Config {
            auth: Some(vec![user]),
            ..Default::default()
        };
        let config_debug = format!("{config:?}");
        assert!(!config_debug.contains("top-secret"));
    }
}