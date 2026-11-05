//! 配置层金标准快照测试（阶段 0）
//!
//! 目的：在重构前冻结当前对外行为，后续阶段用同一组夹具逐项比对，任何
//! 用户可见差异（CLI 名、TOML 键、help 文案、合并优先级、服务 argv、错误文案）
//! 都会在这里暴露。
//!
//! 夹具位于 `tests/fixtures/config_golden/`。首次生成或有意更新基线时：
//!
//! ```text
//! $env:UPDATE_GOLDEN = "1"; cargo test --test config_golden
//! ```
//!
//! 除更新模式外，测试只读夹具，绝不写文件。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::{CommandFactory, Parser};
use tokio::net::TcpStream;

use rust_proxy::config::{
    load_config, Args, Cli, Commands, LogLevel, ProxyProtocolMode, ServerRunArgs, TlsConfig,
};
use rust_proxy::server;

// ─────────────────────────── 夹具脚手架 ───────────────────────────

/// 连续生成的临时目录序号，避免并行测试互相覆盖
static TEMP_SEQ: AtomicUsize = AtomicUsize::new(0);

/// 夹具目录（编译期写入，避免依赖测试进程的工作目录）
fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config_golden")
}

/// 断言 `actual` 与夹具 `name` 完全一致；`UPDATE_GOLDEN=1` 时改为写入夹具。
///
/// 统一把 CRLF 归一为 LF，Windows 与 Linux 上读出的内容才会逐字一致。
fn assert_golden(name: &str, actual: &str) {
    let path = fixture_dir().join(name);
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

/// 创建一个独立的临时配置目录，并写入 `config.toml`
fn temp_config(name: &str, toml: &str) -> (PathBuf, PathBuf) {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "rust_proxy_golden_{}_{}_{}",
        name,
        std::process::id(),
        seq
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp config dir");
    let cfg = dir.join("config.toml");
    std::fs::write(&cfg, toml).expect("write temp config");
    (dir, cfg)
}

/// 路径的稳定展示形式：统一 `/`，去掉 Windows canonicalize 的 `\\?\` 前缀
fn norm_path(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "/")
        .trim_start_matches("//?/")
        .to_string()
}

/// 把快照里的绝对路径替换成稳定占位符，保证跨机器/跨目录比对一致
fn normalize(text: &str, config_dir: Option<&Path>) -> String {
    let mut out = text.replace('\\', "/").replace("//?/", "");
    if let Some(dir) = config_dir {
        // 路径同时可能是原始形式或 canonicalize 后的形式，两种都归一
        out = out.replace(&norm_path(dir), "<CONFIG_DIR>");
        if let Ok(canon) = dir.canonicalize() {
            out = out.replace(&norm_path(&canon), "<CONFIG_DIR>");
        }
    }
    let manifest = norm_path(Path::new(env!("CARGO_MANIFEST_DIR")));
    out.replace(&manifest, "<CRATE>")
}

/// 路径的可读快照形式（`None` 与绝对路径都稳定输出）
fn fmt_path(path: &Option<PathBuf>) -> String {
    match path {
        Some(p) => format!("Some({})", norm_path(p)),
        None => "None".to_string(),
    }
}

/// 把运行时 `Args` 的**全部字段**转成稳定文本。
///
/// 不直接依赖 `Debug`：`Debug` 的排版会随结构体字段顺序改变，而金标准要固定的是
/// 字段值本身；这里显式逐字段输出，新增字段也必须在这里出现（编译期会提醒）。
fn format_args(a: &Args) -> String {
    let auth = match &a.auth {
        None => "None".to_string(),
        Some(users) => {
            let names: Vec<&str> = users.iter().map(|u| u.username.as_str()).collect();
            format!("Some(len={}, users=[{}])", users.len(), names.join(","))
        }
    };
    let tls = match &a.tls {
        None => "None".to_string(),
        Some(t) => format!(
            "Some(https_port={}, cert_path={:?}, key_path={:?})",
            t.https_port,
            t.cert_path.as_ref().map(|p| norm_path(p)),
            t.key_path.as_ref().map(|p| norm_path(p))
        ),
    };
    let ips: Vec<String> = a
        .proxy_protocol_trusted_ips
        .iter()
        .map(|ip| ip.to_string())
        .collect();

    let mut out = String::new();
    out.push_str(&format!("port: {:?}\n", a.port));
    out.push_str(&format!("log_file: {}\n", fmt_path(&a.log_file)));
    out.push_str(&format!("timeout: {}\n", a.timeout));
    out.push_str(&format!("log_level: {:?}\n", a.log_level));
    out.push_str(&format!("multi_thread: {}\n", a.multi_thread));
    out.push_str(&format!("auth: {}\n", auth));
    out.push_str(&format!("tls: {}\n", tls));
    out.push_str(&format!(
        "http_proxy_protocol: {}\n",
        a.http_proxy_protocol
    ));
    out.push_str(&format!(
        "https_proxy_protocol: {}\n",
        a.https_proxy_protocol
    ));
    out.push_str(&format!("proxy_protocol: {}\n", a.proxy_protocol));
    out.push_str(&format!("proxy_protocol_trusted_ips: {:?}\n", ips));
    out.push_str(&format!(
        "path_proxy_prefix: {:?}\n",
        a.path_proxy_prefix
    ));
    out.push_str(&format!(
        "path_proxy_insecure_tls: {}\n",
        a.path_proxy_insecure_tls
    ));
    out.push_str(&format!(
        "path_proxy_rewrite_location: {}\n",
        a.path_proxy_rewrite_location
    ));
    out
}

/// 用真实 clap 解析 `start` 命令行，覆盖 CLI 参数名与解析语义
fn parse_start(argv: &[&str]) -> ServerRunArgs {
    let mut full = vec!["rust-proxy".to_string(), "start".to_string()];
    full.extend(argv.iter().map(|s| s.to_string()));
    let cli = Cli::try_parse_from(full).expect("CLI should parse");
    match cli.command {
        Commands::Start(args) => args,
        _ => panic!("expected start subcommand"),
    }
}

/// 解析「配置文件 + 可选 CLI」组合，返回归一化后的运行配置快照
fn resolve_case(name: &str, toml: &str, extra: &[&str]) -> String {
    let (dir, cfg) = temp_config(name, toml);
    let cfg_arg = cfg.display().to_string();
    let mut argv: Vec<&str> = vec!["--config", &cfg_arg];
    argv.extend(extra.iter().copied());

    let run_args = parse_start(&argv);
    let args = Args::from_run_args(&run_args).expect("config should resolve");
    let out = normalize(&format_args(&args), Some(&dir));

    let _ = std::fs::remove_dir_all(&dir);
    out
}

/// 拼接多个命名段，便于一份夹具容纳一组用例
fn section(out: &mut String, name: &str, body: &str) {
    out.push_str(&format!("===== {} =====\n", name));
    out.push_str(body);
    if !body.ends_with('\n') {
        out.push('\n');
    }
}

// ─────────────────────────── 1. Args 全字段快照 ───────────────────────────

#[test]
fn test_golden_args_all_fields() {
    let mut out = String::new();

    // 空配置：所有默认值
    section(&mut out, "empty_config", &resolve_case("args_empty", "", &[]));

    // 命令行显式给出全部可写字段
    let (dir, _cfg) = temp_config("args_cli_all", "");
    let cert = dir.join("cert.pem").display().to_string();
    let key = dir.join("key.pem").display().to_string();
    let log = dir.join("proxy.log").display().to_string();
    let run_args = parse_start(&[
        "--port",
        "9090",
        "--https-port",
        "9443",
        "--tls-cert",
        &cert,
        "--tls-key",
        &key,
        "--timeout",
        "7",
        "--log-level",
        "debug",
        "--log-file",
        &log,
        "--multi-thread",
        "--proxy-protocol-mode",
        "require",
        "--proxy-protocol-trusted-ips",
        "10.0.0.1,10.0.0.2",
        "--path-proxy-prefix",
        "px",
        "--path-proxy-insecure",
    ]);
    let args = Args::from_run_args(&run_args).expect("CLI-only config should resolve");
    section(
        &mut out,
        "cli_all_fields",
        &normalize(&format_args(&args), Some(&dir)),
    );
    let _ = std::fs::remove_dir_all(&dir);

    // 完整 TOML：覆盖仅 TOML 可写的字段（auth / 分端口 PP / Location 重写）
    let toml = r#"
port = 8080
timeout = 60
log_level = "warn"
multi_thread = true
https_port = 8443
tls_cert = "cert.pem"
tls_key = "key.pem"
proxy_protocol_mode = "disable"
http_proxy_protocol = "auto"
https_proxy_protocol = "require"
proxy_protocol_trusted_ips = ["10.0.0.1"]
path_proxy_prefix = "cfg"
path_proxy_insecure_tls = true
path_proxy_rewrite_location = false

[[auth]]
username = "admin"
password = "secret"

[[auth]]
username = "user2"
password = "pass2"
"#;
    section(
        &mut out,
        "toml_full_fields",
        &resolve_case("args_toml_full", toml, &[]),
    );

    assert_golden("args_fields.txt", &out);
}

// ─────────────────────────── 2. CLI/TOML 组合矩阵 ───────────────────────────

#[test]
fn test_golden_cli_toml_matrix() {
    let mut out = String::new();

    let base = r#"
port = 8080
timeout = 60
log_level = "debug"
multi_thread = false
https_port = 8443
tls_cert = "cert.pem"
tls_key = "key.pem"
proxy_protocol_mode = "disable"
proxy_protocol_trusted_ips = ["10.0.0.1", "10.0.0.2"]
path_proxy_prefix = "cfg"
path_proxy_insecure_tls = false
path_proxy_rewrite_location = false
"#;
    section(&mut out, "toml_only", &resolve_case("m_toml", base, &[]));

    section(
        &mut out,
        "cli_overrides_scalar_and_paths",
        &resolve_case(
            "m_cli_override",
            base,
            &[
                "--port",
                "9090",
                "--timeout",
                "5",
                "--log-level",
                "warn",
                "--https-port",
                "9443",
                "--tls-cert",
                "cli-cert.pem",
                "--tls-key",
                "cli-key.pem",
                "--path-proxy-prefix",
                "px",
                "--path-proxy-insecure",
                "--multi-thread",
            ],
        ),
    );

    section(
        &mut out,
        "bool_union_toml_true",
        &resolve_case(
            "m_bool_toml",
            "port = 8080\nmulti_thread = true\n",
            &[],
        ),
    );
    section(
        &mut out,
        "bool_union_cli_true",
        &resolve_case(
            "m_bool_cli",
            "port = 8080\nmulti_thread = false\n",
            &["--multi-thread"],
        ),
    );

    section(
        &mut out,
        "list_toml_only",
        &resolve_case(
            "m_list_toml",
            "port = 8080\nproxy_protocol_trusted_ips = [\"10.0.0.1\"]\n",
            &[],
        ),
    );
    section(
        &mut out,
        "list_cli_overrides",
        &resolve_case(
            "m_list_cli",
            "port = 8080\nproxy_protocol_trusted_ips = [\"10.0.0.1\"]\n",
            &["--proxy-protocol-trusted-ips", "192.168.1.1,192.168.1.2"],
        ),
    );

    section(
        &mut out,
        "pp_cli_mode_beats_legacy_and_toml",
        &resolve_case(
            "m_pp_cli_mode",
            "port = 8080\nproxy_protocol_mode = \"disable\"\n",
            &["--proxy-protocol-mode", "require", "--proxy-protocol"],
        ),
    );
    section(
        &mut out,
        "pp_legacy_beats_toml_mode",
        &resolve_case(
            "m_pp_legacy",
            "port = 8080\nproxy_protocol_mode = \"disable\"\n",
            &["--proxy-protocol"],
        ),
    );
    section(
        &mut out,
        "pp_toml_mode",
        &resolve_case(
            "m_pp_toml",
            "port = 8080\nproxy_protocol_mode = \"require\"\n",
            &[],
        ),
    );
    section(
        &mut out,
        "pp_port_overrides",
        &resolve_case(
            "m_pp_ports",
            "port = 8080\nproxy_protocol_mode = \"auto\"\nhttp_proxy_protocol = \"disable\"\nhttps_proxy_protocol = \"require\"\n",
            &[],
        ),
    );

    section(
        &mut out,
        "path_insecure_toml_true",
        &resolve_case(
            "m_ins_toml",
            "port = 8080\npath_proxy_insecure_tls = true\n",
            &[],
        ),
    );
    section(
        &mut out,
        "path_insecure_cli_true",
        &resolve_case(
            "m_ins_cli",
            "port = 8080\npath_proxy_insecure_tls = false\n",
            &["--path-proxy-insecure"],
        ),
    );

    section(
        &mut out,
        "tls_enabled_without_cert_paths",
        &resolve_case("m_tls_no_paths", "port = 8080\nhttps_port = 8443\n", &[]),
    );
    section(
        &mut out,
        "tls_ignored_without_https_port",
        &resolve_case(
            "m_tls_no_port",
            "tls_cert = \"cert.pem\"\ntls_key = \"key.pem\"\n",
            &[],
        ),
    );
    section(
        &mut out,
        "port_default_when_absent",
        &resolve_case("m_port_default", "", &[]),
    );
    section(
        &mut out,
        "port_none_when_only_https",
        &resolve_case("m_port_https", "https_port = 8443\n", &[]),
    );

    section(
        &mut out,
        "log_file_relative_to_config",
        &resolve_case(
            "m_log_file",
            "port = 8080\nlog_file = \"logs/proxy.log\"\n",
            &[],
        ),
    );
    section(
        &mut out,
        "rewrite_location_default_true",
        &resolve_case("m_rewrite", "port = 8080\n", &[]),
    );

    assert_golden("matrix.txt", &out);
}

// ─────────────────────────── 3. help 逐字快照 ───────────────────────────

/// 用真实解析路径触发 `--help`，确保 Usage 行与子命令层级和用户看到的一致
fn help_of(argv: &[&str]) -> String {
    match Cli::try_parse_from(argv) {
        Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => {
            normalize(&e.to_string(), None)
        }
        other => panic!("expected DisplayHelp for {:?}: {:?}", argv, other),
    }
}

#[test]
fn test_golden_help_verbatim() {
    // 同时校验 `Cli` 自身没有被意外改动（例如 name/about 变化）
    let about = Cli::command().get_about().map(|s| s.to_string());
    assert_eq!(about.as_deref(), Some("A simple HTTP proxy server"));

    let mut out = String::new();
    section(&mut out, "top", &help_of(&["rust-proxy", "--help"]));
    section(
        &mut out,
        "start",
        &help_of(&["rust-proxy", "start", "--help"]),
    );
    section(
        &mut out,
        "server",
        &help_of(&["rust-proxy", "server", "--help"]),
    );
    section(
        &mut out,
        "server_install",
        &help_of(&["rust-proxy", "server", "install", "--help"]),
    );
    section(
        &mut out,
        "test",
        &help_of(&["rust-proxy", "test", "--help"]),
    );

    assert_golden("help.txt", &out);
}

// ─────────────────────────── 4. 未知键失败 ───────────────────────────

#[test]
fn test_golden_unknown_keys() {
    let cases: &[(&str, &str)] = &[
        (
            "unknown_top_level",
            "proxy_protocal_mode = \"auto\"\n",
        ),
        (
            "misplaced_after_auth",
            "[[auth]]\nusername = \"a\"\npassword = \"b\"\npath_proxy_prefix = \"px\"\n",
        ),
        (
            "legacy_boolean_proxy_protocol",
            "port = 8080\nproxy_protocol = true\n",
        ),
        (
            "unknown_auth_field",
            "[[auth]]\nusername = \"a\"\npassword = \"b\"\nfoo = \"x\"\n",
        ),
        (
            "auth_missing_password",
            "[[auth]]\nusername = \"a\"\n",
        ),
        ("wrong_type_port", "port = \"abc\"\n"),
    ];

    let mut out = String::new();
    for (name, toml) in cases {
        let (dir, cfg) = temp_config(&format!("unknown_{name}"), toml);
        let err = load_config(&cfg).expect_err("config must be rejected");
        let body = normalize(&format!("{err:#}\n"), Some(&dir));
        section(&mut out, name, &body);
        let _ = std::fs::remove_dir_all(&dir);
    }

    assert_golden("unknown_keys.txt", &out);
}

// ─────────────────────────── 5. 服务 argv（单元测试侧） ───────────────────────────
//
// `build_service_command` 是私有函数，快照在 `src/service/mod.rs` 的单元测试中生成，
// 与这里共用同一夹具目录。

// ─────────────────────────── 6. 端口冲突 / 仅 HTTPS / 自签回退 ───────────────────────────

/// 运行时 Args 的最小构造（不读任何配置文件）
fn base_args() -> Args {
    Args {
        port: None,
        log_file: None,
        timeout: 10,
        log_level: LogLevel::Error,
        multi_thread: false,
        auth: None,
        tls: None,
        http_proxy_protocol: ProxyProtocolMode::Disable,
        https_proxy_protocol: ProxyProtocolMode::Disable,
        proxy_protocol: ProxyProtocolMode::Disable,
        proxy_protocol_trusted_ips: Vec::new(),
        path_proxy_prefix: None,
        path_proxy_insecure_tls: false,
        path_proxy_rewrite_location: true,
    }
}

#[tokio::test]
async fn test_golden_validation_and_self_signed_fallback() {
    let mut out = String::new();

    // 端口冲突：在绑定前就失败，不依赖真实端口
    let mut conflict = base_args();
    conflict.port = Some(18080);
    conflict.tls = Some(TlsConfig {
        https_port: 18080,
        cert_path: None,
        key_path: None,
    });
    let err = server::run_server(&conflict, None)
        .await
        .expect_err("port conflict must fail");
    section(&mut out, "port_conflict", &format!("{err}\n"));

    // 两个端口都没有启用
    let err = server::run_server(&base_args(), None)
        .await
        .expect_err("no listener must fail");
    section(&mut out, "no_listener", &format!("{err}\n"));

    // 仅 HTTPS + 证书缺失：必须回退自签并成功绑定，而不是硬错误
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
    let https_port = probe.local_addr().expect("probe addr").port();
    drop(probe);

    let mut only_https = base_args();
    only_https.tls = Some(TlsConfig {
        https_port: 0, // 占位，下面改为真实端口
        cert_path: None,
        key_path: None,
    });
    if let Some(tls) = only_https.tls.as_mut() {
        tls.https_port = https_port;
    }

    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move { server::run_server(&only_https, Some(rx)).await });

    // 轮询直到监听就绪；绑定失败会表现为此处超时
    let mut reachable = false;
    for _ in 0..40 {
        if TcpStream::connect(("127.0.0.1", https_port)).await.is_ok() {
            reachable = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        reachable,
        "HTTPS listener must be reachable after self-signed fallback"
    );
    let _ = tx.send(());
    task.await
        .expect("server task panicked")
        .expect("server must shut down cleanly");

    section(&mut out, "self_signed_fallback", "reachable=true\n");

    assert_golden("validation.txt", &out);
}
