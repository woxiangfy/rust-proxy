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
//! 11. 分帧头互斥：`Content-Length` 与 `Transfer-Encoding` 并存时丢弃 CL，
//!     多个不一致的 CL 回 400（请求走私面）
//! 12. `Host` 头按绝对 URL 重写 / 缺失时补写（RFC 7230 §5.4）
//! 13. 截断的请求头（客户端发完半截就关闭）直接丢弃，不转发给上游
//! 14. 经典代理收到 `https://` absolute-form 直接回 400，不尝试连接（https 必须走 CONNECT）
//! 15. `Connection` 头点名的自定义逐跳字段不转发给上游（RFC 7230 §6.1）
//! 16. 配置认证后，非代理请求仍 404（407 只出现在合法代理请求上）
//! 17. PROXY Protocol 畸形头（未知命令 / 超长 len / 超长 v1）直接断开；不可信来源不解析
//! 18. 路径前缀直连：非法目标 400、上游不可达 502、前缀边界仍 404
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
///
/// 客户端 TLS 统一走 crate 内的 rustls 配置（与自检客户端同一份实现），
/// 这里显式用 insecure 分支以接受 `tls::self_signed` 生成的测试证书。
async fn connect_tls(addr: SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.expect("connect tls proxy");
    rust_proxy::tls_client::connect_tls(tcp, "localhost", true, IO_TIMEOUT)
        .await
        .expect("tls handshake failed")
}

/// 读取 TLS 响应直到连接关闭
///
/// 代理在本项目里的连接收尾是"直接关 TCP"，不会发送 TLS `close_notify`；
/// rustls 客户端会把它报成 `UnexpectedEof`。这与 native-tls 时代的 `Ok(0)` 语义相同，
/// 因此按正常 EOF 处理（响应完整性由后续状态行/body 断言保证）。
async fn read_tls_response<S>(sock: &mut S) -> Vec<u8>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut resp = Vec::new();
    match tokio::time::timeout(IO_TIMEOUT, sock.read_to_end(&mut resp)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Ok(Err(e)) => panic!("read tls response failed: {e}"),
        Err(_) => panic!("tls response timed out"),
    }
    resp
}

/// 假上游：读完整请求头后，把请求头原文回显进响应体，便于断言 Host / 路径 / 头部过滤
async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    spawn_origin_on(listener).await
}

/// 在指定监听器上启动假上游（IPv6 用例需要绑定 `[::1]`，因此把监听器外置）
async fn spawn_origin_on(listener: TcpListener) -> SocketAddr {
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
    spawn_echo_origin_on(listener).await
}

/// 在指定监听器上启动回声上游（IPv6 用例需要绑定 `[::1]`）
async fn spawn_echo_origin_on(listener: TcpListener) -> SocketAddr {
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

/// CONNECT 目标为 IPv6 字面量（`[::1]:port`）时必须能建隧道
///
/// `parse_host_port` 对带方括号的 IPv6 保留方括号形式（`[::1]`），而 socket/DNS
/// 层只接受裸地址（`::1`）。若 CONNECT 路径漏掉剥离，会稳定 502 而不是 200。
/// 本用例把回声上游绑在 `[::1]`，直接验证“确实连到了 IPv6 loopback”。
#[tokio::test]
async fn connect_tunnel_relays_bytes_over_ipv6() {
    let Ok(listener) = TcpListener::bind("[::1]:0").await else {
        eprintln!("当前环境不支持 IPv6 loopback，跳过 connect_tunnel_relays_bytes_over_ipv6");
        return;
    };
    let echo = spawn_echo_origin_on(listener).await;
    let proxy = spawn_proxy(base_args()).await;

    let mut sock = TcpStream::connect(proxy.addr).await.expect("connect proxy");
    sock.write_all(format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").as_bytes())
        .await
        .expect("write CONNECT");

    let head = tokio::time::timeout(IO_TIMEOUT, read_head(&mut sock))
        .await
        .expect("CONNECT response timed out")
        .expect("CONNECT response closed early");
    assert_eq!(
        status_code(&head),
        200,
        "IPv6 字面量 CONNECT 目标不得返回 502，实际响应：{:?}",
        String::from_utf8_lossy(&head)
    );

    let payload = b"ping-through-ipv6-tunnel";
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
    let resp = read_tls_response(&mut sock).await;

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
    let resp = read_tls_response(&mut sock).await;

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

/// 链路 11a：`Content-Length` 与 `Transfer-Encoding` 并存
///
/// RFC 7230 §3.3.3 要求代理在转发前**丢弃** `Content-Length`。两者同时到达上游时，
/// 若上游按 CL 解析，会把分帧字节当成 body 内容，随后管道化的请求就被拼进同一个
/// 请求——请求走私。
///
/// 路径前缀模式早已这样做（`test_build_upstream_request_chunked_drops_content_length`），
/// 经典代理此前是原样转发，同一项目两种行为。
#[tokio::test]
async fn chunked_with_content_length_drops_cl_before_upstream() {
    let origin = spawn_chunked_origin().await;
    let proxy = spawn_proxy(base_args()).await;

    let req = format!(
        "POST http://{origin}/smuggle HTTP/1.1\r\n\
         Host: {origin}\r\n\
         Content-Length: 5\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\
         \r\n\
         5\r\nhello\r\n0\r\n\r\n"
    );
    let resp = request_raw(proxy.addr, req.as_bytes()).await;

    assert_eq!(status_code(&resp), 200, "上游应正常完成分帧读取");
    let echoed = body_of(&resp).to_lowercase();
    assert!(
        echoed.contains("transfer-encoding: chunked"),
        "分帧头必须保留：{echoed}"
    );
    assert!(
        !echoed.contains("content-length:"),
        "CL 与 TE 不得同时转发给上游：{echoed}"
    );
}

/// 链路 11b：多个不一致的 `Content-Length`
///
/// 代理与上游对 body 边界的理解必然不同，只能拒绝，不能"挑一个用"。
/// 用可达的 origin 做对照：若被误转发，用例会看到 200 而不是 400。
#[tokio::test]
async fn conflicting_duplicate_content_length_returns_400() {
    let origin = spawn_origin().await;
    let proxy = spawn_proxy(base_args()).await;

    let req = format!(
        "POST http://{origin}/ambiguous HTTP/1.1\r\n\
         Host: {origin}\r\n\
         Content-Length: 5\r\n\
         Content-Length: 6\r\n\
         Connection: close\r\n\
         \r\n\
         hello"
    );
    let resp = request_raw(proxy.addr, req.as_bytes()).await;

    assert_eq!(
        status_code(&resp),
        400,
        "多个不一致的 CL 必须拒绝，实际：{:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        !body_of(&resp).contains("/ambiguous"),
        "畸形请求不得转发到上游"
    );
}

/// 链路 12：`Host` 头必须以请求目标的 authority 为准
///
/// RFC 7230 §5.4：代理收到 absolute-form 请求时必须忽略客户端的 `Host`，改用请求目标
/// 的 host；客户端漏发 `Host` 时也要补写（HTTP/1.1 上游没有 `Host` 直接回 400）。
/// 历史实现原样透传客户端的 `Host`，客户端只要填错就会让上游收到错误的虚拟主机名。
#[tokio::test]
async fn classic_proxy_rewrites_and_synthesizes_host() {
    let origin = spawn_origin().await;
    let proxy = spawn_proxy(base_args()).await;

    // (a) 客户端 Host 与 URL 不一致 → 以 URL 为准
    let resp = request_raw(
        proxy.addr,
        format!(
            "GET http://{origin}/host HTTP/1.1\r\nHost: wrong.example:9999\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 200);
    let upstream_head = body_of(&resp).to_lowercase();
    assert!(
        upstream_head.contains(&format!("host: {origin}\r\n")),
        "Host 必须按绝对 URL 重写，实际上游收到：{upstream_head}"
    );
    assert!(
        !upstream_head.contains("wrong.example"),
        "客户端的 Host 不得转发给上游：{upstream_head}"
    );

    // (b) 客户端完全没发 Host → 代理补写
    let resp = request_raw(
        proxy.addr,
        format!("GET http://{origin}/no-host HTTP/1.1\r\nUser-Agent: e2e\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 200);
    let upstream_head = body_of(&resp).to_lowercase();
    assert!(
        upstream_head.contains(&format!("host: {origin}\r\n")),
        "缺失 Host 必须补写，实际上游收到：{upstream_head}"
    );
}

/// 链路 13：客户端在请求头结束前关闭 → 直接丢弃
///
/// 旧实现把 EOF 当作"头已读完"，`UpstreamHead::build` 还会补上结束空行，
/// 于是半截头被当成合法请求发给上游（客户端早已不在，白耗一条上游连接）。
/// 断言"代理不回应且不转发"：旧实现会返回 200 回显，新实现读到的是空响应。
#[tokio::test]
async fn truncated_request_head_is_not_forwarded() {
    let origin = spawn_origin().await;
    let proxy = spawn_proxy(base_args()).await;

    let mut sock = TcpStream::connect(proxy.addr)
        .await
        .expect("connect proxy");
    sock.write_all(format!("GET http://{origin}/partial HT").as_bytes())
        .await
        .expect("write partial head");
    sock.shutdown().await.expect("close write half");

    let mut resp = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, sock.read_to_end(&mut resp))
        .await
        .expect("proxy must close the connection after a truncated head")
        .expect("read response after truncated head");
    assert!(
        resp.is_empty(),
        "截断的请求头不得被转发或回应，实际：{:?}",
        String::from_utf8_lossy(&resp)
    );
}

/// 链路 14：`https://` absolute-form 必须以 400 拒绝，而不是尝试连接
///
/// 经典代理只服务明文 http；访问 https 站点必须先 CONNECT。这里特意指向一个
/// **已释放的端口**：如果代理仍然去连接，会得到 502（而不是 400），据此可以
/// 区分"未连接"与"连接失败"。同一条用例再跑一次普通 http absolute-form，
/// 确认拒绝逻辑没有误伤正常转发。
#[tokio::test]
async fn https_absolute_form_is_rejected_with_400() {
    // 取一个已释放的本地端口：监听后立即 drop，端口处于"无人监听"
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind temporary listener");
        listener.local_addr().expect("temporary local_addr")
    };
    let proxy = spawn_proxy(base_args()).await;

    let resp = request_raw(
        proxy.addr,
        format!(
            "GET https://{dead}/secure HTTP/1.1\r\nHost: {dead}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;

    assert_eq!(
        status_code(&resp),
        400,
        "https absolute-form 必须回 400（若尝试连接会变成 502），实际：{:?}",
        String::from_utf8_lossy(&resp)
    );
    let body = body_of(&resp);
    assert!(
        !body.contains("502 Bad Gateway"),
        "不应出现上游连接失败的痕迹：{body}"
    );

    // 对照：普通 http absolute-form 不受影响
    let origin = spawn_origin().await;
    let resp = request_raw(
        proxy.addr,
        format!("GET http://{origin}/ok HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 200, "http absolute-form 仍应正常转发");
}

/// 断言非法 PROXY 头的连接被服务端直接丢弃（零字节或 RST），且不挂起。
///
/// Windows 上关闭仍有未读数据的 socket 会发 RST，客户端表现为 `ConnectionReset`；
/// 语义与 EOF 相同（连接被拒），一并接受。
async fn assert_connection_dropped(addr: SocketAddr, payload: &[u8]) {
    let mut sock = TcpStream::connect(addr).await.expect("connect proxy");
    sock.write_all(payload).await.expect("write pp payload");

    let mut buf = Vec::new();
    match tokio::time::timeout(IO_TIMEOUT, sock.read_to_end(&mut buf)).await {
        Err(_) => panic!("非法 PROXY 头应被立即断开，不能挂在半开状态"),
        Ok(Ok(n)) => assert_eq!(
            n, 0,
            "非法 PROXY 头不得得到任何响应字节：{:?}",
            String::from_utf8_lossy(&buf)
        ),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(Err(e)) => panic!("unexpected io error while reading: {e}"),
    }
}

/// 风险：配置认证后，非代理请求仍必须 404 且不带任何质询头。
///
/// 若把 407 放在请求分类之前，扫描器发一行 `GET /` 就能确认这是代理端口；
/// 对照组同时确认 407 仍然只作用于合法代理请求，没有被"反扫描"误伤。
#[tokio::test]
async fn auth_challenge_is_only_for_valid_proxy_requests() {
    let mut args = base_args();
    args.auth = Some(vec![AuthUser {
        username: "alice".into(),
        password: "s3cret".into(),
    }]);
    let proxy = spawn_proxy(args).await;

    let resp = request_raw(
        proxy.addr,
        b"GET / HTTP/1.1\r\nHost: whatever\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status_code(&resp), 404, "非代理请求不得得到 407");
    let lower = String::from_utf8_lossy(&resp).to_lowercase();
    assert!(
        !lower.contains("proxy-authenticate") && !lower.contains("www-authenticate"),
        "404 不得携带任何认证质询头：{lower}"
    );

    // 对照组：合法代理请求无凭据时必须是 407
    let origin = spawn_origin().await;
    let resp = request_raw(
        proxy.addr,
        format!(
            "GET http://{origin}/auth HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 407, "合法代理请求必须接受认证质询");
}

/// 风险：PROXY v2 的未知命令与超长 len 必须让连接直接失效。
///
/// 未知命令若被当作普通流量放行，等于绕过来源校验；len 不设上限则一个 4 字节字段
/// 就能让服务端分配 64KB 级缓冲（`vec![0u8; len]`），是廉价的远程内存放大。
#[tokio::test]
async fn proxy_protocol_rejects_malformed_v2_headers() {
    let mut args = base_args();
    args.http_proxy_protocol = ProxyProtocolMode::Auto;
    let proxy = spawn_proxy(args).await;
    let signature = b"\r\n\r\n\x00\r\nQUIT\n";

    // (a) cmd = 2（未定义命令）
    let mut payload = signature.to_vec();
    payload.extend_from_slice(&[0x22, 0x11, 0x00, 0x00]);
    assert_connection_dropped(proxy.addr, &payload).await;

    // (b) len = 513，超过 PP_MAX_HEADER_LEN（512）；服务端读到长度字段就必须拒绝，
    //     不需要真的把 513 字节地址数据发完
    let mut payload = signature.to_vec();
    payload.extend_from_slice(&[0x21, 0x11, 0x02, 0x01]);
    assert_connection_dropped(proxy.addr, &payload).await;
}

/// 风险：v1 头超过规范上限（107 字节）时必须停止读取并断开。
///
/// 不设上限会让攻击者用一条连接持续灌入文本行，占用连接名额与内存
/// （`PP_HEADER_TIMEOUT_SECS` 只能限制时间，不能限制字节）。
#[tokio::test]
async fn proxy_protocol_rejects_oversized_v1_header() {
    let mut args = base_args();
    args.http_proxy_protocol = ProxyProtocolMode::Auto;
    let proxy = spawn_proxy(args).await;

    let mut payload = b"PROXY TCP4 ".to_vec();
    payload.extend_from_slice(&[b'a'; 200]);
    payload.extend_from_slice(b"\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_connection_dropped(proxy.addr, &payload).await;
}

/// 风险：来自不可信 IP 的 PROXY 头不得被解析（否则客户端可伪造真实 IP）。
///
/// 把可信列表设成另一个网段，让 loopback 成为不可信来源：伪造头应被当作普通数据，
/// 请求行 `PROXY TCP4 ...` 无法分类而返回 404，而不是按正常代理请求转发。
#[tokio::test]
async fn proxy_protocol_untrusted_source_is_not_parsed() {
    let origin = spawn_origin().await;
    let mut args = base_args();
    args.http_proxy_protocol = ProxyProtocolMode::Auto;
    args.proxy_protocol_trusted_ips = vec!["10.0.0.1".parse().unwrap()];
    let proxy = spawn_proxy(args).await;

    let mut req = b"PROXY TCP4 203.0.113.9 127.0.0.1 40000 80\r\n".to_vec();
    req.extend_from_slice(
        format!("GET http://{origin}/forged HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    );
    let resp = request_raw(proxy.addr, &req).await;

    assert_eq!(
        status_code(&resp),
        404,
        "不可信来源的 PROXY 头必须被忽略（否则会得到 200）"
    );
}

/// 风险：路径前缀模式的错误分支与边界必须可区分。
///
/// 非法目标不能把任意 scheme 交给连接层；上游不可达要明确回 502；`/pxx/...`
/// 不能被当成 `/px/...`，否则前缀口令可被同前缀路径绕过。
#[tokio::test]
async fn path_prefix_rejects_invalid_target_and_unreachable_upstream() {
    let mut args = base_args();
    args.path_proxy_prefix = Some("px".into());
    let proxy = spawn_proxy(args).await;

    // (a) 非 http(s) scheme → 400
    let resp = request_raw(
        proxy.addr,
        b"GET /px/ftp://example.com/a HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status_code(&resp), 400, "只允许 http/https 目标");

    // (b) 目标不是合法 URL → 400
    let resp = request_raw(
        proxy.addr,
        b"GET /px/not-a-url HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status_code(&resp), 400, "非法目标 URL 不得进入连接层");

    // (c) 上游不可达 → 502（与经典代理一致，不能静默 EOF）
    let dead = dead_addr().await;
    let resp = request_raw(
        proxy.addr,
        format!("GET /px/http://{dead}/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 502, "路径前缀模式的上游不可达应回 502");

    // (d) 前缀边界：`/pxx/...` 不得命中 `/px`
    let origin = spawn_origin().await;
    let resp = request_raw(
        proxy.addr,
        format!(
            "GET /pxx/http://{origin}/boundary HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 404, "前缀边界必须精确匹配");
}

/// 链路 15：`Connection` 头点名的自定义逐跳字段不得转发给上游
///
/// RFC 7230 §6.1：`Connection: X-Hop` 表示 `X-Hop` 只对当前这一跳有效，代理必须连同
/// `Connection` 一起丢弃。仅过滤固定名单（Keep-Alive / Proxy-* / TE 等）会漏掉这类
/// 自定义字段，等于把上一跳的私有语义泄漏给上游。两条建头链路（经典代理与路径前缀
/// 直连）共用同一套判定，因此同一条用例两处都验。
#[tokio::test]
async fn connection_named_headers_are_not_forwarded() {
    let origin = spawn_origin().await;

    // (a) 经典代理（absolute-form）
    let proxy = spawn_proxy(base_args()).await;
    let resp = request_raw(
        proxy.addr,
        format!(
            "GET http://{origin}/hop HTTP/1.1\r\nHost: {origin}\r\nConnection: close, X-Hop\r\nX-Hop: leak\r\nX-Keep: ok\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 200);
    let upstream_head = body_of(&resp).to_lowercase();
    assert!(
        !upstream_head.contains("x-hop: leak"),
        "Connection 点名的字段必须丢弃，实际上游收到：{upstream_head}"
    );
    assert!(
        upstream_head.contains("x-keep: ok"),
        "未被点名的字段必须保留，实际上游收到：{upstream_head}"
    );

    // (b) 路径前缀直连（origin-form）
    let mut args = base_args();
    args.path_proxy_prefix = Some("px".into());
    let path_proxy = spawn_proxy(args).await;
    let resp = request_raw(
        path_proxy.addr,
        format!(
            "GET /px/http://{origin}/hop HTTP/1.1\r\nHost: {}\r\nConnection: close, X-Hop\r\nX-Hop: leak\r\nX-Keep: ok\r\n\r\n",
            path_proxy.addr
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 200);
    let upstream_head = body_of(&resp).to_lowercase();
    assert!(
        !upstream_head.contains("x-hop: leak"),
        "路径前缀直连同样必须丢弃 Connection 点名的字段：{upstream_head}"
    );
    assert!(
        upstream_head.contains("x-keep: ok"),
        "路径前缀直连也必须保留未被点名的字段：{upstream_head}"
    );
}

/// 链路 16：IPv6 字面量目标（经典 absolute-form）
///
/// `url::Url::host_str()` 对 IPv6 返回带方括号的 `[::1]`，而 socket/DNS 层需要裸地址。
/// 若解析结果只保存一种形式，`GET http://[::1]:port/` 会稳定 502。本用例把上游绑在
/// `[::1]`，直接验证“代理确实连到了 ::1”而不是碰巧连到 127.0.0.1。
#[tokio::test]
async fn ipv6_literal_absolute_form_forwards() {
    let Ok(listener) = TcpListener::bind("[::1]:0").await else {
        eprintln!("当前环境不支持 IPv6 loopback，跳过 ipv6_literal_absolute_form_forwards");
        return;
    };
    let origin = spawn_origin_on(listener).await;
    let proxy = spawn_proxy(base_args()).await;

    let resp = request_raw(
        proxy.addr,
        format!(
            "GET http://{origin}/ipv6 HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;

    assert_eq!(status_code(&resp), 200, "IPv6 字面量目标不得返回 502");
    let upstream_head = body_of(&resp).to_lowercase();
    assert!(
        upstream_head.contains("get /ipv6 http/1.1"),
        "请求行必须改写为 origin-form，实际：{upstream_head}"
    );
    assert!(
        upstream_head.contains(&format!("host: {origin}")),
        "Host 必须保留 IPv6 方括号形式，实际：{upstream_head}"
    );
}

/// 链路 17：路径前缀模式的畸形分帧必须 fail-closed
///
/// 两类 Content-Length 在任何转发链路上都不能“挑一个”：非数字无法确定边界，
/// 多个不一致值会让代理与上游对同一条请求的 body 边界理解不同——这正是请求走私
/// 的入口。经典代理已返回 400，路径前缀模式也必须一致。
#[tokio::test]
async fn path_prefix_rejects_malformed_content_length() {
    let origin = spawn_origin().await;
    let mut args = base_args();
    args.path_proxy_prefix = Some("px".into());
    let proxy = spawn_proxy(args).await;

    // (a) 多个不一致的 Content-Length
    let resp = request_raw(
        proxy.addr,
        format!(
            "POST /px/http://{origin}/dup HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello!",
            proxy.addr
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 400, "冲突的 Content-Length 必须 400");

    // (b) 非数字 Content-Length
    let resp = request_raw(
        proxy.addr,
        format!(
            "POST /px/http://{origin}/nan HTTP/1.1\r\nHost: {}\r\nContent-Length: abc\r\nConnection: close\r\n\r\nhello",
            proxy.addr
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(status_code(&resp), 400, "非数字 Content-Length 必须 400");
}

/// 链路 18：`Transfer-Encoding` 必须整行原样转发
///
/// `Transfer-Encoding: gzip, chunked` 表示“先 gzip 再 chunked”两层编码。把声明折叠成
/// 只有 `chunked` 会让上游在解完分帧后把仍是 gzip 的字节当明文，属于内容解码错误。
/// 两条建头链路共用同一实现后，此处应看到完整原行。
#[tokio::test]
async fn path_prefix_preserves_full_transfer_encoding() {
    let origin = spawn_chunked_origin().await;
    let mut args = base_args();
    args.path_proxy_prefix = Some("px".into());
    let proxy = spawn_proxy(args).await;

    let resp = request_raw(
        proxy.addr,
        format!(
            "POST /px/http://{origin}/te HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: gzip, chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            proxy.addr
        )
        .as_bytes(),
    )
    .await;

    assert_eq!(status_code(&resp), 200, "上游应正常收下 chunked 请求");
    let upstream = body_of(&resp).to_lowercase();
    assert!(
        upstream.contains("transfer-encoding: gzip, chunked"),
        "Transfer-Encoding 必须整行保留，实际：{upstream}"
    );
}

/// 链路 19：两条链路的建头结果必须逐字节一致
///
/// 同一语义的请求（去掉 absolute-form 与 `/px/` 前缀差异后完全相同）经过经典代理与
/// 路径前缀直连，上游收到的头块不允许有任何差异——否则修一处漏一处只是时间问题。
/// 这里特意让 `Connection` 出现在普通头之前，用来固定“改写位置”。
#[tokio::test]
async fn classic_and_path_prefix_build_identical_upstream_head() {
    let origin = spawn_origin().await;

    let classic = spawn_proxy(base_args()).await;
    let classic_resp = request_raw(
        classic.addr,
        format!(
            "GET http://{origin}/same HTTP/1.1\r\nConnection: close\r\nX-Test: 1\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;

    let mut args = base_args();
    args.path_proxy_prefix = Some("px".into());
    let path_proxy = spawn_proxy(args).await;
    let path_resp = request_raw(
        path_proxy.addr,
        format!(
            "GET /px/http://{origin}/same HTTP/1.1\r\nConnection: close\r\nX-Test: 1\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;

    assert_eq!(status_code(&classic_resp), 200);
    assert_eq!(status_code(&path_resp), 200);
    assert_eq!(
        body_of(&classic_resp),
        body_of(&path_resp),
        "两条链路上游收到的头块必须逐字节一致"
    );
}
