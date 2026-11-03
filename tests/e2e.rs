//! 端到端集成测试
//!
//! 每条用例都起**真实 TCP 监听器**：一个假上游（origin）+ 一个真代理
//! （[`rust_proxy::server::run_server_with_listener`]，绑定 `127.0.0.1:0` 取临时端口），
//! 然后用手写 HTTP 报文驱动，断言字节级响应。
//!
//! 覆盖 5 条主链路（对应评审报告 A1）：
//! 1. 反扫描：非代理格式请求 → 最小化 404，且不带 `Server` 头
//! 2. 认证：无凭据 / 错凭据 → 407；正确凭据 → 转发，且凭据不出现在上游请求里
//! 3. CONNECT 隧道：200 Connection Established 后双向透传
//! 4. 路径前缀直连：`/px/http://host/path` → 上游收到重写后的 origin-form 请求
//! 5. PROXY Protocol：Auto 模式兼容带/不带 v1 头；Require 模式拒绝无头连接
//!
//! 全部走 loopback，不依赖外网，可在 CI 稳定运行。

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use rust_proxy::config::{Args, AuthUser, LogLevel, ProxyProtocolMode};
use rust_proxy::server;

/// 单条用例的 IO 宽限：任何链路都不该超过这个时间，超时即视为失败而非挂死
const IO_TIMEOUT: Duration = Duration::from_secs(5);

// ─────────────────────────── 测试脚手架 ───────────────────────────

/// 构造一份最小可用的配置（不读文件，避免受工作目录里的 `config.toml` 影响）
fn base_args() -> Args {
    Args {
        port: None, // 由调用方绑定监听器，端口不参与
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

/// 运行中的测试代理；`Drop` 时发送关停信号，避免用例结束后留下 accept 循环
struct Proxy {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// 在临时端口上启动代理
async fn spawn_proxy(args: Args) -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let addr = listener.local_addr().expect("proxy local_addr");
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        server::run_server_with_listener(listener, &args, Some(rx))
            .await
            .expect("proxy exited with error");
    });

    Proxy {
        addr,
        shutdown: Some(tx),
    }
}

/// 假上游：读完整请求头后，把请求头原文回显进响应体，便于断言 Host / 路径 / 头部过滤
async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin local_addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let Some(head) = read_head(&mut sock).await else {
                    return;
                };
                let body = head.clone();
                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                resp.extend_from_slice(&body);
                let _ = sock.write_all(&resp).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    addr
}

/// 回声上游：用于 CONNECT 隧道，收到什么原样吐回
async fn spawn_echo_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo local_addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });

    addr
}

/// 读到 `\r\n\r\n` 为止（返回包含该终止符的头部原文）
async fn read_head(sock: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
            return Some(buf);
        }
    }
}

/// 发一段原始报文，读到 EOF 为止（服务端凡涉及错误/转发均带 `Connection: close`）
async fn request_raw(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut sock = TcpStream::connect(addr).await.expect("connect proxy");
    sock.write_all(req).await.expect("write request");
    let mut resp = Vec::new();
    if tokio::time::timeout(IO_TIMEOUT, sock.read_to_end(&mut resp))
        .await
        .is_err()
    {
        panic!("proxy did not close the connection within {IO_TIMEOUT:?}");
    }
    resp
}

/// 取状态码（`HTTP/1.1 404 Not Found` → 404）
fn status_code(resp: &[u8]) -> u16 {
    let head = String::from_utf8_lossy(resp);
    let line = head.lines().next().unwrap_or_default();
    line.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status code in response: {:?}", line))
}

fn body_of(resp: &[u8]) -> String {
    let text = String::from_utf8_lossy(resp);
    text.split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default()
}

fn basic(user: &str, pass: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
}

// ─────────────────────────── 用例 ───────────────────────────

/// 链路 1：反扫描
///
/// 扫描器直接 `GET /` 访问代理端口时，必须得到与普通静态服务器无异的 404：
/// 不带 `Server` / `X-Powered-By`，也不能出现 `Proxy-Authenticate` 之类的代理特征。
#[tokio::test]
async fn non_proxy_request_returns_minimal_404() {
    let proxy = spawn_proxy(base_args()).await;

    let resp = request_raw(
        proxy.addr,
        b"GET / HTTP/1.1\r\nHost: whatever\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert_eq!(status_code(&resp), 404);
    assert_eq!(body_of(&resp), "404 Not Found");

    let lower = String::from_utf8_lossy(&resp).to_lowercase();
    assert!(!lower.contains("\r\nserver:"), "404 不得暴露 Server 头");
    assert!(
        !lower.contains("proxy-authenticate"),
        "404 不得暗示这是代理端口"
    );
}

/// 链路 2：代理认证
///
/// 三条断言：无凭据 → 407；错误密码 → 407；正确凭据 → 200 且凭据被剔除。
#[tokio::test]
async fn proxy_auth_challenges_then_forwards_without_credentials() {
    let origin = spawn_origin().await;
    let mut args = base_args();
    args.auth = Some(vec![AuthUser {
        username: "alice".into(),
        password: "s3cret".into(),
    }]);
    let proxy = spawn_proxy(args).await;

    let target = format!("http://{origin}/hello");

    // (a) 无凭据
    let resp = request_raw(
        proxy.addr,
        format!("GET {target} HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 407);
    assert!(
        String::from_utf8_lossy(&resp)
            .to_lowercase()
            .contains("proxy-authenticate: basic"),
        "407 必须带 Basic 质询头"
    );

    // (b) 错误密码
    let resp = request_raw(
        proxy.addr,
        format!(
            "GET {target} HTTP/1.1\r\nHost: {origin}\r\nProxy-Authorization: Basic {}\r\nConnection: close\r\n\r\n",
            basic("alice", "wrong")
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 407);

    // (c) 正确凭据 → 转发成功，且凭据不得泄漏给上游
    let resp = request_raw(
        proxy.addr,
        format!(
            "GET {target} HTTP/1.1\r\nHost: {origin}\r\nProxy-Authorization: Basic {}\r\nConnection: close\r\n\r\n",
            basic("alice", "s3cret")
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 200);
    let upstream_head = body_of(&resp).to_lowercase();
    assert!(
        upstream_head.contains("get /hello http/1.1"),
        "上游应收到 origin-form 请求行，实际：{upstream_head}"
    );
    assert!(
        !upstream_head.contains("proxy-authorization"),
        "Proxy-Authorization 不得转发给上游"
    );
}

/// 链路 3：CONNECT 隧道
///
/// 建隧道后 200 只表示"通道已建立"，真正的连通性要把字节打进去再收回来才算验证。
#[tokio::test]
async fn connect_tunnel_relays_bytes() {
    let echo = spawn_echo_origin().await;
    let proxy = spawn_proxy(base_args()).await;

    let mut sock = TcpStream::connect(proxy.addr).await.expect("connect proxy");
    sock.write_all(format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").as_bytes())
        .await
        .expect("write CONNECT");

    let head = tokio::time::timeout(IO_TIMEOUT, read_head(&mut sock))
        .await
        .expect("CONNECT response timed out")
        .expect("CONNECT response closed early");
    assert_eq!(status_code(&head), 200, "CONNECT 应返回 200");
    assert!(String::from_utf8_lossy(&head).contains("Connection Established"));

    // 隧道内写什么就该读回什么
    let payload = b"ping-through-tunnel";
    sock.write_all(payload).await.expect("tunnel write");
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(IO_TIMEOUT, sock.read_exact(&mut buf))
        .await
        .expect("tunnel read timed out")
        .expect("tunnel read failed");
    assert_eq!(buf, payload);
}

/// 链路 4：路径前缀直连
///
/// `/px/http://host:port/path` 应由代理自己发起上游连接，并把请求行重写成
/// origin-form、`Host` 改成上游 authority——客户端完全没配代理也能用。
#[tokio::test]
async fn path_prefix_rewrites_and_forwards() {
    let origin = spawn_origin().await;
    let mut args = base_args();
    args.path_proxy_prefix = Some("px".into());
    let proxy = spawn_proxy(args).await;

    let resp = request_raw(
        proxy.addr,
        format!(
            "GET /px/http://{origin}/deep/path?a=1 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            proxy.addr
        )
        .as_bytes(),
    )
    .await;

    assert_eq!(status_code(&resp), 200, "前缀直连应返回上游的 200");
    let upstream_head = body_of(&resp).to_lowercase();
    assert!(
        upstream_head.contains("get /deep/path?a=1 http/1.1"),
        "路径与查询串必须保留，实际：{upstream_head}"
    );
    assert!(
        upstream_head.contains(&format!("host: {origin}")),
        "Host 必须改写为上游 authority，实际：{upstream_head}"
    );
    assert!(
        !upstream_head.contains("/px/"),
        "前缀不得泄漏给上游，实际：{upstream_head}"
    );
}

/// 链路 5a：PROXY Protocol `auto` 模式对两种流量的兼容
///
/// 同一端口既要能吃 v1 头（反代场景），也要能吃裸请求（直连场景），且不能丢首包。
#[tokio::test]
async fn proxy_protocol_auto_accepts_both_flows() {
    let origin = spawn_origin().await;
    let mut args = base_args();
    args.http_proxy_protocol = ProxyProtocolMode::Auto;
    args.proxy_protocol = ProxyProtocolMode::Auto;
    let proxy = spawn_proxy(args).await;
    let target = format!("http://{origin}/pp");

    // (a) 带 PROXY v1 头：真实地址被解析，后续请求正常转发
    let mut req = b"PROXY TCP4 203.0.113.9 127.0.0.1 40000 80\r\n".to_vec();
    req.extend_from_slice(
        format!("GET {target} HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    let resp = request_raw(proxy.addr, &req).await;
    assert_eq!(status_code(&resp), 200, "带 PROXY 头的请求应被正常代理");

    // (b) 不带 PROXY 头：回退为普通流量，首包不得丢失
    let resp = request_raw(
        proxy.addr,
        format!("GET {target} HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 200, "无 PROXY 头应回退为直连处理");
    assert!(body_of(&resp).contains("GET /pp HTTP/1.1"));
}

/// 链路 5b：PROXY Protocol `require` 模式必须拒绝无头连接
///
/// 这是安全边界：Require 下若还能被静默降级成直连，等于可绕过来源校验。
#[tokio::test]
async fn proxy_protocol_require_rejects_plain_request() {
    let mut args = base_args();
    args.http_proxy_protocol = ProxyProtocolMode::Require;
    args.proxy_protocol = ProxyProtocolMode::Require;
    let proxy = spawn_proxy(args).await;

    let mut sock = TcpStream::connect(proxy.addr).await.expect("connect proxy");
    sock.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("write plain request");

    let mut buf = Vec::new();
    match tokio::time::timeout(IO_TIMEOUT, sock.read_to_end(&mut buf)).await {
        // 超时 = 服务端既没回包也没断开，等于把非法连接挂在半开状态，视为失败
        Err(_) => panic!("Require 模式下无 PROXY 头的连接应被立即关闭"),
        Ok(Ok(n)) => assert_eq!(
            n, 0,
            "被拒绝的连接不得收到任何响应字节：{:?}",
            String::from_utf8_lossy(&buf)
        ),
        // Windows 上直接关闭未读数据的 socket 会发 RST，客户端表现为 ConnectionReset；
        // 语义与 EOF 相同（连接被拒），一并接受。
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(Err(e)) => panic!("unexpected io error while reading: {e}"),
    }
}
