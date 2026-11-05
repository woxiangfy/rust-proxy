//! 服务参数适配层：把 CLI 配置翻译成系统服务启动命令行
//!
//! [`ServiceArgs`] 的类型由声明层（`config::schema`）生成，只包含 CLI 字段；
//! `auth` 等仅 TOML 字段在类型上就不存在，因此密码在结构上不可能进入服务 argv。
//!
//! 序列化规则（与安装命令行完全等价）：
//! - 只写**显式指定**的项，不把安装时的默认值固化进服务定义；
//! - `config` 额外 canonicalize（服务进程解析起点不同，且文件必须存在）；
//! - `log_file` / `tls_cert` / `tls_key` 转绝对路径，其余标量原样；
//! - 布尔项为真才写 flag；列表非空才写，逗号拼接；
//! - 旧 `--proxy-protocol` 仅在未显式给出 `--proxy-protocol-mode` 时写入。

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::config::{ServerRunArgs, ServiceArgs};

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

/// 追加一个长参数（不带值）
fn push_flag(args: &mut Vec<OsString>, flag: &str) {
    args.push(OsString::from(flag));
}

/// 追加一个「长参数 + 值」对
fn push_pair(args: &mut Vec<OsString>, flag: &str, value: impl std::fmt::Display) {
    push_flag(args, flag);
    args.push(OsString::from(value.to_string()));
}

impl ServiceArgs {
    /// 从已解析的 CLI 参数构造服务参数
    ///
    /// 逐字段显式复制而不是 `Default` 兜底：声明层新增 CLI 字段时，这里会因
    /// 结构体初始化缺少字段而编译失败，从而强迫适配层同步。
    pub fn from_run_args(run_args: &ServerRunArgs) -> Self {
        Self {
            config: run_args.config.clone(),
            port: run_args.port,
            log_file: run_args.log_file.clone(),
            timeout: run_args.timeout,
            log_level: run_args.log_level,
            multi_thread: run_args.multi_thread,
            https_port: run_args.https_port,
            tls_cert: run_args.tls_cert.clone(),
            tls_key: run_args.tls_key.clone(),
            proxy_protocol_mode: run_args.proxy_protocol_mode,
            proxy_protocol: run_args.proxy_protocol,
            proxy_protocol_trusted_ips: run_args.proxy_protocol_trusted_ips.clone(),
            path_proxy_prefix: run_args.path_proxy_prefix.clone(),
            path_proxy_insecure: run_args.path_proxy_insecure,
        }
    }

    /// 生成服务进程的完整 argv（含 `--run-as-service`）
    ///
    /// 参数顺序被金标准快照固定（`tests/fixtures/config_golden/service_argv.txt`），
    /// 不要在无行为变更理由时调整顺序。
    pub fn to_argv(&self) -> Result<Vec<OsString>> {
        let mut args = vec![OsString::from("--run-as-service")];

        // 配置文件额外 canonicalize：它必须存在。
        if let Some(config) = &self.config {
            let config = absolute_path(config)?
                .canonicalize()
                .context("Failed to canonicalize config path")?;
            push_pair(&mut args, "--config", config.display());
        }

        if let Some(port) = self.port {
            push_pair(&mut args, "--port", port);
        }

        if let Some(log_file) = &self.log_file {
            push_pair(&mut args, "--log-file", absolute_path(log_file)?.display());
        }

        if let Some(timeout) = self.timeout {
            push_pair(&mut args, "--timeout", timeout);
        }

        if let Some(log_level) = self.log_level {
            push_pair(&mut args, "--log-level", log_level);
        }

        // HTTPS/TLS 配置参数
        if let Some(https_port) = self.https_port {
            push_pair(&mut args, "--https-port", https_port);
        }
        if let Some(tls_cert) = &self.tls_cert {
            push_pair(&mut args, "--tls-cert", absolute_path(tls_cert)?.display());
        }
        if let Some(tls_key) = &self.tls_key {
            push_pair(&mut args, "--tls-key", absolute_path(tls_key)?.display());
        }

        // 显式 mode 优先；旧参数等价于 auto。
        if let Some(pp_mode) = self.proxy_protocol_mode {
            push_pair(&mut args, "--proxy-protocol-mode", pp_mode);
        } else if self.proxy_protocol {
            push_flag(&mut args, "--proxy-protocol");
        }

        if !self.proxy_protocol_trusted_ips.is_empty() {
            let ips = self
                .proxy_protocol_trusted_ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(",");
            push_pair(&mut args, "--proxy-protocol-trusted-ips", ips);
        }

        // 路径前缀直连模式
        if let Some(prefix) = &self.path_proxy_prefix {
            push_pair(&mut args, "--path-proxy-prefix", prefix);
        }
        if self.path_proxy_insecure {
            push_flag(&mut args, "--path-proxy-insecure");
        }

        // `--multi-thread` 位置保持在末尾（与历史 argv 一致）。
        if self.multi_thread {
            push_flag(&mut args, "--multi-thread");
        }

        Ok(args)
    }
}
