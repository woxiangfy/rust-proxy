//! 声明层：配置项的**唯一真源**
//!
//! 本文件用一张 `macro_rules!` 字段表同时生成三处载体，避免 CLI 属性、TOML 键名与
//! 服务安装参数各自漂移：
//!
//! - [`ServerRunArgs`]：命令行适配层（`clap::Parser`）
//! - [`Config`]：TOML 完整模型（`serde::Deserialize`，`deny_unknown_fields`）
//! - [`ServiceArgs`]：服务安装参数（只含 CLI 子集，结构上不含 `auth`）
//!
//! 每个字段的声明形状：
//!
//! ```text
//! (
//!     Type,
//!     cli { 字段名, [ doc = help 文案 ]?, [ clap 属性... ] }?,        // 无 CLI 入口则省略
//!     cfg { TOML 字段名, 字段文档 }?,                                // 无 TOML 键则省略
//!     merge { CLI 字段名, TOML 字段名, 合并规则 }?                     // CLI 可覆盖 TOML 时给出
//! )
//! ```
//!
//! **名称映射**必须显式写在声明里，不依赖命名巧合：例如 CLI 的
//! `path_proxy_insecure` 对应 TOML 的 `path_proxy_insecure_tls`。
//!
//! 分区由字段自身声明的 `cli` / `cfg` 决定：
//! - 两者都有：双源字段（CLI 覆盖 TOML，可进服务 argv）
//! - 只有 `cli`：加载器参数（`--config`）或兼容参数（旧 `--proxy-protocol`）
//! - 只有 `cfg`：仅 TOML 字段（`auth`、分端口 PROXY Protocol、Location 重写）
//!   这些字段没有 CLI 入口，也不会出现在 [`ServiceArgs`] 里。

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

use super::{AuthUser, LogLevel, ProxyProtocolMode};

/// 合并层：把 CLI 字段按声明中的规则覆盖到 TOML 字段
///
/// 规则语义：
/// - `copy_opt` / `clone_opt`：CLI 显式给出才覆盖（标量复制、路径/字符串克隆）
/// - `bool_union`：布尔取并集（CLI 只能把 false 置为 true）
/// - `list_clone`：列表仅在 CLI 非空时覆盖
/// - `log_file_path`：CLI 相对路径相对**当前进程目录**转绝对（历史行为）
/// - `legacy_pp`：旧 `--proxy-protocol` 仅在未显式给 `--proxy-protocol-mode` 时生效
macro_rules! merge_field {
    (copy_opt, $this:ident, $cli:ident, $from:ident, $to:ident) => {
        if let Some(value) = $cli.$from {
            $this.$to = Some(value);
        }
    };
    (clone_opt, $this:ident, $cli:ident, $from:ident, $to:ident) => {
        if let Some(value) = &$cli.$from {
            $this.$to = Some(value.clone());
        }
    };
    (bool_union, $this:ident, $cli:ident, $from:ident, $to:ident) => {
        if $cli.$from {
            $this.$to = true;
        }
    };
    (list_clone, $this:ident, $cli:ident, $from:ident, $to:ident) => {
        if !$cli.$from.is_empty() {
            $this.$to = $cli.$from.clone();
        }
    };
    (log_file_path, $this:ident, $cli:ident, $from:ident, $to:ident) => {
        if let Some(log_file) = &$cli.$from {
            $this.$to = Some(if log_file.is_absolute() {
                log_file.clone()
            } else {
                std::env::current_dir()
                    .context("Failed to resolve --log-file relative to current directory")?
                    .join(log_file)
            });
        }
    };
    (legacy_pp, $this:ident, $cli:ident, $from:ident, $to:ident) => {
        if $cli.proxy_protocol_mode.is_none() && $cli.$from {
            $this.$to = Some(ProxyProtocolMode::Auto);
        }
    };
}

/// CLI 字段：字段名 + help 文案 + `clap` 属性
///
/// 本宏只生成 `clap` 适配层（[`ServerRunArgs`]）与服务参数的**类型化视图**
/// （[`ServiceArgs`]）；服务命令行的逐字段序列化在 `ServiceArgs::to_argv` 中手写，
/// 顺序由服务命令格式决定，不由此声明生成。新增 CLI 字段时必须同步修改
/// `ServiceArgs::from_run_args` 与 `to_argv`，遗漏会被 `service` 模块的逐字段
/// round-trip 测试拦住。
macro_rules! config_schema {
    (
        server_doc = $server_doc:literal,
        config_doc = $config_doc:literal,
        fields = [
            $(
                (
                    $ty:ty,
                    $( cli { $cli:ident, $( doc = $cli_doc:literal, )? [ $($cli_arg:tt)* ] }, )?
                    $( cfg { $cfg:ident, $cfg_doc:literal }, )?
                    $( merge { $mcli:ident, $mcfg:ident, $merge:ident } )?
                ),
            )*
        ]
    ) => {
        #[doc = $server_doc]
        #[derive(clap::Parser, Debug, Clone, Default, PartialEq)]
        pub struct ServerRunArgs {
            $(
                $(
                    $(
                        #[doc = $cli_doc]
                    )?
                    #[arg($($cli_arg)*)]
                    pub $cli: $ty,
                )?
            )*
        }

        #[doc = $config_doc]
        #[derive(Deserialize, Debug, Clone, Default)]
        #[serde(default, deny_unknown_fields)]
        pub struct Config {
            $(
                $(
                    #[doc = $cfg_doc]
                    pub $cfg: $ty,
                )?
            )*
        }

        /// 服务安装参数：CLI 子集的类型化视图
        ///
        /// 只由 `cli` 分区生成，因此 `auth` 等仅 TOML 字段在类型上就不存在，
        /// 密码不可能被顺手塞进服务命令行。
        #[derive(Debug, Clone, Default, PartialEq)]
        pub struct ServiceArgs {
            $(
                $(
                    pub $cli: $ty,
                )?
            )*
        }

        impl Config {
            /// 把命令行子集覆盖到 TOML 配置上（CLI > TOML）
            ///
            /// 由声明层的 `merge` 分区生成：只处理"命令行支持"的字段，未声明的
            /// 字段保持 TOML 原值。规则见 [`merge_field`]。
            pub(crate) fn apply_cli(&mut self, cli: &ServerRunArgs) -> Result<()> {
                $(
                    $(
                        merge_field!($merge, self, cli, $mcli, $mcfg);
                    )?
                )*
                Ok(())
            }
        }
    };
}

// ─────────────────────────── 字段表（唯一真源） ───────────────────────────

config_schema! {
    server_doc = r#"命令行支持的配置子集（CLI 适配层）

这里只声明"命令行能修改哪些配置"，不是完整配置模型；完整模型以 [`Config`]（TOML）
为准，CLI 值最终由 [`Config::apply_cli`] 覆盖进配置。"#,
    config_doc = r#"完整的配置模型（唯一真源，来自 TOML）

字段全集以本结构为准；CLI 只是它的一个可选覆盖入口，不反向扩充字段。
`deny_unknown_fields`：拼错键名（如把 `proxy_protocol_mode` 写成
`proxy_protocal_mode`）必须报错而不是被静默忽略——配置里既有代理认证也有
来源校验，静默丢一个键等于静默降低安全性。"#,
    fields = [
        // ── 仅 CLI：加载器参数 ──
        (
            Option<PathBuf>,
            cli { config, [ long ] },
        ),
        // ── 双源：标量 ──
        (
            Option<u16>,
            cli { port, [ long ] },
            cfg { port, "Port to bind" },
            merge { port, port, copy_opt }
        ),
        (
            Option<PathBuf>,
            cli { log_file, [ long ] },
            cfg { log_file, "Log file path" },
            merge { log_file, log_file, log_file_path }
        ),
        (
            Option<u64>,
            cli { timeout, [ long ] },
            cfg { timeout, "Request timeout in seconds" },
            merge { timeout, timeout, copy_opt }
        ),
        (
            Option<LogLevel>,
            cli { log_level, [ long ] },
            cfg { log_level, "Log level" },
            merge { log_level, log_level, copy_opt }
        ),
        (
            bool,
            cli { multi_thread, doc = "启用多线程运行时（默认使用单线程）", [ long ] },
            cfg { multi_thread, "Use multi-threaded runtime" },
            merge { multi_thread, multi_thread, bool_union }
        ),
        // ── 仅 TOML（敏感）：认证 ──
        (
            Option<Vec<AuthUser>>,
            cfg { auth, "代理认证用户列表。省略整个 `[[auth]]` 段时不启用认证。" },
        ),
        // ── 双源：HTTPS/TLS ──
        (
            Option<u16>,
            cli { https_port, doc = "HTTPS 代理监听端口（启用 TLS 时需同时指定 --tls-cert 和 --tls-key）", [ long ] },
            cfg { https_port, "HTTPS 代理监听端口（需同时配置 tls_cert 和 tls_key）" },
            merge { https_port, https_port, copy_opt }
        ),
        (
            Option<PathBuf>,
            cli { tls_cert, doc = "TLS 证书文件路径（PEM 格式），需与 --tls-key 同时提供", [ long ] },
            cfg { tls_cert, "TLS 证书文件路径（PEM 格式），需与 tls_key 同时配置" },
            merge { tls_cert, tls_cert, clone_opt }
        ),
        (
            Option<PathBuf>,
            cli { tls_key, doc = "TLS 私钥文件路径（PEM 格式），需与 --tls-cert 同时提供", [ long ] },
            cfg { tls_key, "TLS 私钥文件路径（PEM 格式），需与 tls_cert 同时配置" },
            merge { tls_key, tls_key, clone_opt }
        ),
        // ── 双源：PROXY Protocol ──
        (
            Option<ProxyProtocolMode>,
            cli { proxy_protocol_mode, doc = r#"PROXY Protocol 模式（disable / auto / require）

- `disable`：完全禁用 PROXY Protocol
- `auto`：自动检测（默认），连接开头匹配 PROXY v1/v2 签名时解析真实 IP，
  否则按普通流量处理（HTTP 直连、不带 PROXY 头的 HTTPS 均兼容）
- `require`：强制要求所有连接必须以 PROXY Protocol 头开头，否则断开连接

注意：该模式同时作为 HTTP/HTTPS 端口的缺省值；如需分别控制可在配置文件中
使用 `http_proxy_protocol` / `https_proxy_protocol` 覆盖。"#, [ long, value_name = "MODE" ] },
            cfg { proxy_protocol_mode, r#"PROXY Protocol 全局默认模式（disable / auto / require）

均作为 HTTP/HTTPS 端口的缺省模式；若同时配置了
`http_proxy_protocol` / `https_proxy_protocol` 覆盖项，则对应端口优先使用覆盖值。"# },
            merge { proxy_protocol_mode, proxy_protocol_mode, copy_opt }
        ),
        // 旧参数：不写 TOML，等价于 mode auto；优先级低于显式 mode
        (
            bool,
            cli { proxy_protocol, doc = r#"启用 PROXY Protocol 自动识别（等价于 `--proxy-protocol-mode auto`）

旧参数，为了 CLI 兼容保留。不会强制任何端口，连接仍全自动检测。"#, [ long ] },
            merge { proxy_protocol, proxy_protocol_mode, legacy_pp }
        ),
        // ── 仅 TOML：分端口 PROXY Protocol 覆盖 ──
        // 顺序与既有 `Config` 字段一致：`deny_unknown_fields` 的报错会按声明顺序
        // 列出可选键，字段顺序变化会改变用户可见的错误文案。
        (
            Option<ProxyProtocolMode>,
            cfg { http_proxy_protocol, r#"HTTP 端口覆盖模式（可选；缺省回退到 `proxy_protocol_mode`）

典型用法：HTTP 为普通直连、HTTPS 走 PROXY Protocol 时，
分别设 `http_proxy_protocol = "disable"`、`https_proxy_protocol = "auto"`。"# },
        ),
        (
            Option<ProxyProtocolMode>,
            cfg { https_proxy_protocol, "HTTPS 端口覆盖模式（可选；缺省回退到 `proxy_protocol_mode`）" },
        ),
        (
            Vec<std::net::IpAddr>,
            cli { proxy_protocol_trusted_ips, doc = r#"PROXY Protocol 可信代理 IP 列表

仅当 `proxy_protocol_mode` 为 auto/require 时生效。
仅接受来自这些 IP 的连接发送的 PROXY Protocol 头，防止客户端伪造 IP。
示例：--proxy-protocol-trusted-ips 10.0.0.1,10.0.0.2"#, [ long, value_delimiter = ',' ] },
            cfg { proxy_protocol_trusted_ips, "PROXY Protocol 可信代理 IP 列表（空列表表示不限制）" },
            merge { proxy_protocol_trusted_ips, proxy_protocol_trusted_ips, list_clone }
        ),
        // ── 双源：路径前缀直连模式（CLI/TOML 名称不同，显式映射） ──
        (
            Option<String>,
            cli { path_proxy_prefix, doc = r#"启用路径前缀直连模式并指定前缀（如 px）

启用后，请求 `http://代理地址/px/https://example.com/` 会被代理服务器
直连到 `https://example.com/`，客户端无需配置代理即可使用（类似 gh-proxy）。
前缀本身相当于一个路径口令，未命中前缀的请求仍返回 404。"#, [ long, value_name = "PREFIX" ] },
            cfg { path_proxy_prefix, r#"路径前缀直连模式前缀（如 "px"）。省略即不启用该模式。

启用后：`http://代理地址/px/https://example.com/` → 直连 `https://example.com/`。"# },
            merge { path_proxy_prefix, path_proxy_prefix, clone_opt }
        ),
        (
            bool,
            cli { path_proxy_insecure, doc = r#"路径前缀直连模式下跳过上游 TLS 证书校验（默认校验）

仅对 https 上游生效，用于自签证书/证书链不完整的内网站点。"#, [ long ] },
            cfg { path_proxy_insecure_tls, "路径前缀直连模式下跳过上游 TLS 证书校验（默认 false）" },
            merge { path_proxy_insecure, path_proxy_insecure_tls, bool_union }
        ),
        // ── 仅 TOML：Location 重写开关 ──
        (
            Option<bool>,
            cfg { path_proxy_rewrite_location, r#"是否把 3xx 响应的 `Location` 重写为 `/<prefix>/<绝对URL>`（默认 true）

开启后重定向仍由本代理转发；关闭则原样透传上游 Location（客户端会直连上游）。"# },
        ),
    ]
}
