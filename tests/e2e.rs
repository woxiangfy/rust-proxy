//! 端到端集成测试
//!
//! 每条用例都起**真实 TCP 监听器**：一个假上游（origin）+ 一个真代理
//! （[`rust_proxy::server::run_server_with_listener`]，绑定 `127.0.0.1:0` 取临时端口），
//! 然后用手写 HTTP 报文驱动，断言字节级响应。
//!
//! 覆盖的主链路（对应评审报告 A1）：
//! 1. 反扫描：非代理格式请求 → 最小化 404，且不带 `Server` 头
//! 2. 认证：无凭据 / 错凭据 → 407；正确凭据 → 转发，且凭据不出现在上游请求里
//! 3. CONNECT 隧道：200 Connection Established 后双向透传
//! 4. 路径前缀直连：`/px/http://host/path` → 上游收到重写后的 origin-form 请求
//! 5. PROXY Protocol：Auto 模式兼容带/不带 v1 头；Require 模式拒绝无头连接
//! 6. `Expect: 100-continue`：代理自己回 100，不等上游
//! 7. TLS 监听：自签证书握手成功，转发与反扫描在 TLS 下同样成立
//! 8. chunked 请求体：分帧字节原样转发，不补 `Content-Length`
//! 9. 上游不可达：HTTP 与 CONNECT 均回 502（不得静默关闭）
//! 10. 超长请求头：超过 64KB 回 431，且不把截断的头转发给上游
//!
//! 全部走 loopback，不依赖外网，可在 CI 稳定运行。

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_native_tls::{native_tls, TlsConnector};

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

/// 在临时端口上启动**自签 TLS** 代理
///
/// 证书由服务端在进程内生成，测试侧不需要也不应该读磁盘上的证书文件：
/// 乱序执行的工作目录里可能有个 `config.toml`，任何外部文件依赖都会让用例变得不可靠。
async fn spawn_tls_proxy(args: Args) -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tls proxy");
    let addr = listener.local_addr().expect("tls proxy local_addr");
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        server::run_server_with_self_signed_tls(listener, &args, Some(rx))
            .await
            .expect("tls proxy exited with error");
    });

    Proxy {
        addr,
        shutdown: Some(tx),
    }
}

/// 与代理建立 TLS 连接（自签证书，跳过验证）
async fn connect_tls(addr: SocketAddr) -> tokio_native_tls::TlsStream<TcpStream> {
    let mut builder = native_tls::TlsConnector::builder();
    builder.danger_accept_invalid_certs(true);
    let connector = TlsConnector::from(builder.build().expect("build tls connector"));
    let tcp = TcpStream::connect(addr).await.expect("connect tls proxy");

    tokio::time::timeout(IO_TIMEOUT, connector.connect("localhost", tcp))
        .await
        .expect("tls handshake timed out")
        .expect("tls handshake failed")
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

/// 需要完整 body 的假上游：读完头 + `Content-Length` 字节的 body 后才响应，
/// 响应体回显请求头（不包含 body），用于验证 `Expect: 100-continue` 这类契约。
async fn spawn_body_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind body origin");
    let addr = listener.local_addr().expect("body origin local_addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let Some(head) = read_head(&mut sock).await else {
                    return;
                };
                // 头里已含 body 前缀时先扣掉，剩余部分按 Content-Length 补齐
                let head_len = head
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4)
                    .unwrap_or(head.len());
                let text = String::from_utf8_lossy(&head[..head_len]).to_ascii_lowercase();
                let cl: usize = text
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut got = head.len() - head_len;
                let mut chunk = [0u8; 512];
                while got < cl {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got += n,
                    }
                }

                let body = &head[..head_len];
                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                resp.extend_from_slice(body);
                let _ = sock.write_all(&resp).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    addr
}

/// chunked 假上游：读完头与 chunked 分帧体（直到终止块），把**原始字节**回显
///
/// 回显而不是解码，是为了让测试直接断言"代理有没有动过分帧"——
/// 一旦代理偷偷把 chunked 解成 `Content-Length`，回显里就再也找不到 `0\r\n\r\n`。
async fn spawn_chunked_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind chunked origin");
    let addr = listener.local_addr().expect("chunked origin local_addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let Some(head) = read_head(&mut sock).await else {
                    return;
                };
                let head_len = head
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4)
                    .unwrap_or(head.len());
                let mut raw = head.clone();

                // 用例只发单块 body，终止序列为 `0\r\n\r\n`（块数据后跟空块）
                let mut chunk = [0u8; 512];
                while !contains(&raw[head_len..], b"0\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => raw.extend_from_slice(&chunk[..n]),
                    }
                }

                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    raw.len()
                )
                .into_bytes();
                resp.extend_from_slice(&raw);
                let _ = sock.write_all(&resp).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    addr
}

/// 子串查找（`[u8]::windows` 的薄封装，只在本文件用）
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
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

/// 取一个"确定没人监听"的地址：绑定后立即释放端口
///
/// 不能写死 `127.0.0.1:1` 之类的端口——那可能被系统服务占用而表现成"能连上"。
/// loopback 上刚释放的临时端口在用例生命周期内被抢占的概率可忽略。
async fn dead_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("ephemeral local_addr");
    drop(listener);
    addr
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

/// 链路 7：`Expect: 100-continue`
///
/// 代理必须**自己**回 `100 Continue`：客户端声明该头后不会立刻发 body，
/// 而是在等临时响应；若代理把 `Expect` 转发给上游、自己却先阻塞在读 body 上，
/// 客户端就会白等到自己的超时（curl 默认 1s）才补发。
///
/// 用例只发请求头，随后在 1s 内必须收到 100；再发 body 才能拿到 200。
#[tokio::test]
async fn expect_100_continue_answered_by_proxy_not_upstream() {
    let origin = spawn_body_origin().await;
    let proxy = spawn_proxy(base_args()).await;

    let mut sock = TcpStream::connect(proxy.addr).await.expect("connect proxy");
    let head = format!(
        "POST http://{origin}/upload HTTP/1.1\r\nHost: {origin}\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"
    );
    sock.write_all(head.as_bytes()).await.expect("write head");

    // 只发头、不发 body：临时响应必须在一个很短的等待内到达
    let mut interim = [0u8; 25];
    tokio::time::timeout(Duration::from_secs(1), sock.read_exact(&mut interim))
        .await
        .expect("proxy must answer 100-continue immediately")
        .expect("read interim response");
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");

    sock.write_all(b"hello").await.expect("write body");

    let mut rest = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, sock.read_to_end(&mut rest))
        .await
        .expect("final response timed out")
        .expect("read final response");

    assert_eq!(status_code(&rest), 200, "body: {:?}", body_of(&rest));
    assert!(
        !body_of(&rest).to_ascii_lowercase().contains("expect:"),
        "Expect 不得转发给上游：{}",
        body_of(&rest)
    );
}

/// 链路 8：TLS 监听
///
/// 明文 listener 的用例无法证明 TLS 分支（握手 → `handle_client_with_addr`）可用：
/// 该分支的流类型是 `TlsStream`，与明文 `TcpStream` 走的是不同的调用点。
/// 这里用自签证书握手后跑一次完整转发，再验证反扫描特性在 TLS 下同样成立。
#[tokio::test]
async fn tls_listener_proxies_and_keeps_anti_scan() {
    let origin = spawn_origin().await;
    let proxy = spawn_tls_proxy(base_args()).await;

    // (a) 真实 TLS 握手 + 绝对 URL 转发
    let mut sock = connect_tls(proxy.addr).await;
    let req = format!(
        "GET http://{origin}/secure HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
    );
    sock.write_all(req.as_bytes())
        .await
        .expect("write over tls");
    let mut resp = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, sock.read_to_end(&mut resp))
        .await
        .expect("tls response timed out")
        .expect("read tls response");

    assert_eq!(status_code(&resp), 200, "TLS 下应正常转发");
    assert!(
        body_of(&resp).contains("GET /secure HTTP/1.1"),
        "上游应收到 origin-form 请求行，实际：{}",
        body_of(&resp)
    );

    // (b) TLS 下反扫描同样成立：扫描器在 TLS 端口上也只看得到普通 404
    let mut sock = connect_tls(proxy.addr).await;
    sock.write_all(b"GET / HTTP/1.1\r\nHost: whatever\r\nConnection: close\r\n\r\n")
        .await
        .expect("write scan over tls");
    let mut resp = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, sock.read_to_end(&mut resp))
        .await
        .expect("scan response timed out")
        .expect("read scan response");

    assert_eq!(status_code(&resp), 404);
    let lower = String::from_utf8_lossy(&resp).to_lowercase();
    assert!(!lower.contains("\r\nserver:"), "TLS 404 同样不得暴露 Server 头");
}

/// 链路 9：chunked 请求体
///
/// 两个容易出错的点：
/// 1. 分帧必须**原样**转发（含终止块），代理不能自行解码后改发 `Content-Length`；
/// 2. 不得同时出现 `Content-Length`，否则上游按两种长度解析，构成请求走私面。
#[tokio::test]
async fn chunked_request_body_forwarded_with_framing_intact() {
    let origin = spawn_chunked_origin().await;
    let proxy = spawn_proxy(base_args()).await;

    let req = format!(
        "POST http://{origin}/chunk HTTP/1.1\r\n\
         Host: {origin}\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\
         \r\n\
         5\r\nhello\r\n0\r\n\r\n"
    );
    let resp = request_raw(proxy.addr, req.as_bytes()).await;

    assert_eq!(status_code(&resp), 200, "上游应完成分帧读取");
    let echoed = body_of(&resp);
    let lower = echoed.to_lowercase();

    assert!(
        lower.contains("transfer-encoding: chunked"),
        "上游必须收到 chunked 分帧头：{lower}"
    );
    assert!(
        !lower.contains("content-length:"),
        "chunked 请求不得被补上 Content-Length（请求走私面）：{lower}"
    );
    assert!(
        echoed.ends_with("5\r\nhello\r\n0\r\n\r\n"),
        "分帧字节必须原样转发，实际：{echoed:?}"
    );
}

/// 链路 10：上游不可达
///
/// 历史实现对两种形态都要么静默 `return`（客户端只看得到 EOF），要么文档承诺
/// 502 而实现没做。这里把"明确回 502"钉死：客户端必须能区分"代理到目标不通"
/// 与"目标自己拒绝"，否则无从重试与排障。
#[tokio::test]
async fn unreachable_upstream_returns_502() {
    let proxy = spawn_proxy(base_args()).await;
    let dead = dead_addr().await;

    // (a) 明文 HTTP 代理：连接上游失败 → 502
    let resp = request_raw(
        proxy.addr,
        format!("GET http://{dead}/gone HTTP/1.1\r\nHost: {dead}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert_eq!(
        status_code(&resp),
        502,
        "上游不可达必须回 502 而不是空 EOF，body: {:?}",
        body_of(&resp)
    );
    assert!(
        String::from_utf8_lossy(&resp)
            .to_lowercase()
            .contains("connection: close"),
        "502 必须带 Connection: close，否则客户端会等后续字节"
    );

    // (b) CONNECT：隧道建不起来时同样回 502（客户端不会把 EOF 当成隧道异常）
    let resp = request_raw(
        proxy.addr,
        format!("CONNECT {dead} HTTP/1.1\r\nHost: {dead}\r\n\r\n").as_bytes(),
    )
    .await;
    assert_eq!(
        status_code(&resp),
        502,
        "CONNECT 到不可达目标应回 502，body: {:?}",
        body_of(&resp)
    );
}

/// 链路 11：超长请求头
///
/// 超过 `MAX_HEAD_BYTES`（64KB）时必须**拒绝而不是截断**：截断的头没有 `\r\n\r\n`，
/// 上游会一直等剩余头部，代理却已开始发 body，两边各自卡到超时；若截断点正好落在
/// 合法请求行之后，畸形流量还会被当成正常代理请求放行。
///
/// 报文构造有两点讲究：
/// 1. **顶满上限且不含头结束符**——这正是超限的真实形态（超大 Cookie / 慢速续期）。
///    若报文恰好 64KB 且带 `\r\n\r\n`，会先命中"头已完整"分支而正常转发；
/// 2. 长度精确对齐到 8 × 8KB 读缓冲，服务端读满后接收缓冲已空，关闭时不会因
///    残留未读字节触发 RST（Windows 上 RST 会把尚未取走的响应冲掉，
///    客户端只看到空响应，与待验证行为无关）。
#[tokio::test]
async fn oversized_request_head_rejected_before_forwarding() {
    let proxy = spawn_proxy(base_args()).await;

    const LIMIT: usize = 64 * 1024;
    let prefix = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Pad: ";
    let oversized = format!("{prefix}{}", "a".repeat(LIMIT - prefix.len()));
    assert_eq!(oversized.len(), LIMIT, "报文必须正好顶到上限");
    assert!(
        !oversized.ends_with("\r\n\r\n"),
        "本用例要复现的是「读满上限仍无结束符」"
    );

    let sock = TcpStream::connect(proxy.addr).await.expect("connect proxy");
    let (mut rd, mut wr) = sock.into_split();
    let writer = tokio::spawn(async move { wr.write_all(oversized.as_bytes()).await });

    let mut resp = Vec::new();
    let _ = tokio::time::timeout(IO_TIMEOUT, rd.read_to_end(&mut resp)).await;
    // 写入在服务端提前关闭后可能报错，属预期，不影响断言
    let _ = writer.await;

    assert_eq!(
        status_code(&resp),
        431,
        "超长请求头必须回 431 而不是截断转发，实际响应：{:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        !String::from_utf8_lossy(&resp).contains("Example Domain"),
        "超长请求绝不能被转发到上游"
    );
}
