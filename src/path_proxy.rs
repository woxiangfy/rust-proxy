//! 路径前缀直连模式（Path-Prefix Direct Proxy）
//!
//! 让代理服务器同时充当「URL 前缀网关」（类似 gh-proxy.com 的用法）：
//! 客户端把目标完整 URL 拼在前缀路径之后，由代理服务器直连上游并原样回传内容。
//!
//! ```text
//! GET http://1.2.3.4:80/px/https://www.baidu.com/   ⟶   实际访问 https://www.baidu.com/
//! GET http://1.2.3.4:80/px/http://example.com/a.txt ⟶   实际访问 http://example.com/a.txt
//! ```
//!
//! 前缀 `px` 由配置文件 `path_proxy_prefix`（或命令行 `--path-proxy-prefix`）定义。
//!
//! 与既有 HTTP 代理模式的区别：
//! - 普通代理模式：客户端必须把代理地址配置为 HTTP 代理，请求行是绝对 URL 或 CONNECT
//! - 本模式：客户端**完全无感知**，直接请求形如 `http://proxy/px/<目标URL>` 的普通网址即可
//!
//! 设计要点：
//! 1. **仅当前缀精确匹配时才接管**，其余相对路径请求仍返回 404（保持反扫描特性，
//!    前缀本身即相当于一个「路径口令」）。
//! 2. 支持 http / https 上游：https 上游使用系统 CA 校验证书（可用 `path_proxy_insecure_tls`
//!    关闭校验，适合自签内网站点）。
//! 3. 请求头过滤逐跳头（Connection / Proxy-* / Upgrade / Expect 等），Host 重写为上游主机，
//!    body 按 Content-Length / chunked 流式转发，不缓冲整个请求体。
//! 4. 响应按原始字节流式转发（chunked / gzip 保持原样），仅在 3xx 时按需把 `Location`
//!    重写为 `/<prefix>/<绝对URL>`，使重定向后的请求继续走本代理。

use crate::buffer_pool::{AdaptiveBuffer, BufferPool};
use crate::http_body::forward_chunked_body;
use crate::http_util::{authority_of, find_header_end, is_hop_by_hop, MAX_HEAD_BYTES};
use crate::net::{connect_host, is_benign_close_error, AsyncStream};
use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_native_tls::{native_tls, TlsConnector};

/// 路径前缀直连模式配置
#[derive(Debug, Clone)]
pub struct PathProxyConfig {
    /// 路径前缀（不含 `/`），如 `px` → `/px/https://example.com/`
    prefix: String,
    /// 是否跳过上游 TLS 证书校验（自签证书场景）
    pub insecure_tls: bool,
    /// 是否把 3xx 响应的 `Location` 重写为 `/<prefix>/<绝对URL>`
    pub rewrite_location: bool,
}

impl PathProxyConfig {
    /// 构造配置并校验前缀合法性。
    ///
    /// 前缀会自动去除首尾空白与 `/`；仅允许 ASCII 字母、数字、`-`、`_`、`.`。
    /// 其它字符（空白、`/`、`?`、`#`、`%`、非 ASCII）会破坏路径匹配的确定性，
    /// 或被客户端 percent-encode 后导致匹配不到。
    pub fn new(prefix: &str, insecure_tls: bool, rewrite_location: bool) -> Result<Self> {
        let p = prefix.trim().trim_matches('/');
        if p.is_empty() {
            anyhow::bail!("path proxy prefix must not be empty");
        }
        if let Some(c) = p
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        {
            anyhow::bail!(
                "invalid character '{}' in path proxy prefix '{}' (allowed: ASCII letters, digits, '-', '_', '.')",
                c,
                p
            );
        }
        Ok(Self {
            prefix: p.to_string(),
            insecure_tls,
            rewrite_location,
        })
    }

    #[inline]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// 判断请求目标是否命中前缀，命中则返回去掉前缀后的目标 URL。
    ///
    /// 例如前缀为 `px` 且请求目标为 `/px/https://a.com/b` → 返回 `https://a.com/b`。
    /// 未命中（含 `/px` 自身、`/pxx/...`）返回 `None`。
    pub fn match_target<'a>(&self, request_target: &'a str) -> Option<&'a str> {
        let rest = request_target.strip_prefix('/')?;
        let rest = rest.strip_prefix(self.prefix.as_str())?;
        // 前缀后必须紧跟 '/'，避免 `/pxx/` 被误判为 `/px`
        let rest = rest.strip_prefix('/')?;
        if rest.is_empty() {
            None
        } else {
            Some(rest)
        }
    }
}

/// 一次路径前缀直连请求的输入（调用方已从报文中解析出的请求描述）
///
/// 把这些字段打包，一是为了压住参数个数，二是让"哪些是逐请求的、哪些是进程级的"
/// 在签名上显式可见（后者见 [`PathProxyRuntime`]）。
pub(crate) struct PathProxyRequest<'a> {
    /// 请求方法（GET / POST / ...）
    pub method: &'a str,
    /// 目标 URL（含 scheme），由 [`PathProxyConfig::match_target`] 解析得到
    pub target_url: &'a str,
    /// 已读入的原始数据（头 + 可能的 body 前缀），保持与普通代理一致的零拷贝思路
    pub data: &'a [u8],
    /// body 起始偏移（`data` 中头结束位置）
    pub head_end: usize,
    /// 本次用于认证的请求头名；认证成功后转发上游前必须剔除，避免凭据泄漏
    pub drop_header: Option<&'static str>,
}

/// 路径前缀直连的运行期参数（与单次请求无关，整个进程共用）
#[derive(Clone, Copy)]
pub(crate) struct PathProxyRuntime<'a> {
    pub cfg: &'a PathProxyConfig,
    pub timeout: Duration,
    pub buffer_pool: &'a BufferPool,
}

/// 处理一次路径前缀直连请求。
pub(crate) async fn handle_path_proxy<S>(
    mut client: S,
    client_addr: SocketAddr,
    req: PathProxyRequest<'_>,
    rt: PathProxyRuntime<'_>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // 解构后沿用原有变量名，函数体无需改动
    let PathProxyRequest {
        method,
        target_url,
        data: request_data,
        head_end,
        drop_header,
    } = req;
    let PathProxyRuntime {
        cfg,
        timeout,
        buffer_pool,
    } = rt;

    // ── 1. 解析目标 URL ──
    let parsed = match url::Url::parse(target_url) {
        Ok(u) => u,
        Err(e) => {
            warn!(
                "Path-proxy: invalid target URL '{}' from {}: {}",
                target_url, client_addr, e
            );
            send_error(
                &mut client,
                400,
                "Bad Request",
                &format!("invalid target URL, expected /{}/http://host/path", cfg.prefix()),
            )
            .await;
            return;
        }
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        send_error(
            &mut client,
            400,
            "Bad Request",
            "only http and https targets are supported",
        )
        .await;
        return;
    }
    if parsed.host_str().is_none() {
        send_error(&mut client, 400, "Bad Request", "target URL has no host").await;
        return;
    }

    info!(
        "{} -> PATH {} {} (prefix /{}/)",
        client_addr,
        method,
        target_url,
        cfg.prefix()
    );

    // ── 2. 连接上游（http 明文 / https TLS）──
    let mut upstream = match connect_upstream(&parsed, cfg, timeout).await {
        Ok(s) => s,
        Err(e) => {
            error!(
                "Path-proxy: failed to connect upstream '{}' for {}: {:#}",
                target_url, client_addr, e
            );
            send_error(&mut client, 502, "Bad Gateway", "upstream connection failed").await;
            return;
        }
    };

    // ── 3. 重写并发送请求头 ──
    let request_head = String::from_utf8_lossy(&request_data[..head_end]).to_string();
    let upstream_req = build_upstream_request(method, &parsed, &request_head, drop_header);

    if upstream.write_all(upstream_req.head.as_bytes()).await.is_err() {
        return;
    }

    // 客户端声明 `Expect: 100-continue` 时先给临时响应，否则它会等上游的 100（已丢弃
    // 该头，上游不会发）而白等一个 RTT 甚至超时。`Expect` 本身不转发给上游。
    if upstream_req.expect_continue
        && client
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .is_err()
    {
        return;
    }

    // ── 4. 转发请求体（已缓冲前缀 + 流式剩余部分）──
    let buffered_body = &request_data[head_end..];
    let body_result = forward_request_body(
        &mut client,
        &mut upstream,
        buffered_body,
        upstream_req.content_length,
        upstream_req.chunked,
        timeout,
        buffer_pool,
    )
    .await;
    if let Err(e) = body_result {
        if !is_benign_close_error(&e) {
            warn!(
                "Path-proxy: failed to forward request body from {}: {}",
                client_addr, e
            );
        }
        return;
    }

    // ── 5. 回传响应（必要时重写 Location）──
    match forward_response(&mut client, &mut upstream, cfg, &parsed, timeout, buffer_pool).await {
        Ok(()) => info!("Path-proxy completed: {} {}", method, target_url),
        Err(e) if is_benign_close_error(&e) => {
            debug!("Path-proxy response ended early: {}", e)
        }
        Err(e) => warn!("Path-proxy response error for '{}': {}", target_url, e),
    }
}

/// 连接上游：http 直连，https 在 TCP 之上做 TLS 握手。
async fn connect_upstream(
    parsed: &url::Url,
    cfg: &PathProxyConfig,
    timeout: Duration,
) -> Result<Box<dyn AsyncStream>> {
    let host = parsed.host_str().context("target URL has no host")?;
    // IPv6 字面量 `url` 返回带方括号形式（`[::1]`），DNS 解析与 SNI 需去掉方括号
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = parsed
        .port_or_known_default()
        .context("target URL has no known port")?;

    let tcp = connect_host(host, port, timeout)
        .await
        .with_context(|| format!("cannot connect to {}:{}", host, port))?;
    // 小包（HTTP 头）立即发出，降低下载类请求的首字节延迟
    let _ = tcp.set_nodelay(true);

    if parsed.scheme() == "https" {
        let mut builder = native_tls::TlsConnector::builder();
        if cfg.insecure_tls {
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }
        let connector = TlsConnector::from(
            builder
                .build()
                .context("failed to build TLS connector for upstream")?,
        );
        let tls = tokio::time::timeout(timeout, connector.connect(host, tcp))
            .await
            .with_context(|| format!("TLS handshake with {} timed out", host))?
            .with_context(|| format!("TLS handshake with {} failed", host))?;
        debug!("Path-proxy: TLS established with {}:{}", host, port);
        Ok(Box::new(tls))
    } else {
        Ok(Box::new(tcp))
    }
}

/// 发往上游的请求（头 + 分帧信息）
struct UpstreamRequest {
    /// 完整的请求头（已含结束空行）
    head: String,
    /// `Content-Length` 值（未声明则为 `None`）
    content_length: Option<u64>,
    /// body 是否以 chunked 分帧转发
    chunked: bool,
    /// 客户端是否发送了 `Expect: 100-continue`
    expect_continue: bool,
}

/// 构造发往上游的请求：origin-form 请求行 + 重写后的 Host + 过滤逐跳头。
///
/// `drop_header` 是在代理侧用于认证的请求头名，必须从上游请求中移除。
fn build_upstream_request(
    method: &str,
    parsed: &url::Url,
    request_head: &str,
    drop_header: Option<&'static str>,
) -> UpstreamRequest {
    let mut out = String::with_capacity(request_head.len() + 64);

    // 请求行：origin-form（path + query），这是直连上游的标准形式
    out.push_str(method);
    out.push(' ');
    out.push_str(parsed.path());
    if let Some(q) = parsed.query() {
        out.push('?');
        out.push_str(q);
    }
    out.push_str(" HTTP/1.1\r\n");

    // Host：以目标 URL 为准重写（客户端原本的 Host 是代理服务器地址）
    out.push_str("Host: ");
    out.push_str(&authority_of(parsed));
    out.push_str("\r\n");

    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    let mut expect_continue = false;
    let mut body_headers: Vec<&str> = Vec::new();

    for line in request_head.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let (name, value) = match line.split_once(':') {
            Some(pair) => pair,
            // 无冒号的非法行（含折行续行）直接丢弃，避免把上一请求的字节拼进头部
            None => continue,
        };
        let name = name.trim();
        let value = value.trim();

        // Host 已重写；Connection 由代理统一为 close
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("connection") {
            continue;
        }
        // 分帧头单独处理：不能与逐跳头黑名单混在一起，且二者互斥（见下）
        if name.eq_ignore_ascii_case("transfer-encoding") {
            // 只要声明了 chunked 就按 chunked 转发；其它编码（如 gzip）不作请求体分帧依据
            chunked = value
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("chunked"));
            continue;
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse::<u64>().ok();
            continue;
        }
        if name.eq_ignore_ascii_case("expect") {
            // 100-continue 由代理直接应答，不转发
            expect_continue = value.eq_ignore_ascii_case("100-continue");
            continue;
        }
        if is_hop_by_hop(name) {
            continue;
        }
        if drop_header.is_some_and(|h| name.eq_ignore_ascii_case(h)) {
            // 代理自身的认证凭据：绝不能转发给目标站点
            continue;
        }
        body_headers.push(line);
    }

    // 分帧头二选一：chunked 优先并丢弃 Content-Length，避免上游收到互相矛盾的长度
    // 而产生请求走私（RFC 7230 §3.3.3 要求代理这样做）。
    if chunked {
        content_length = None;
        out.push_str("Transfer-Encoding: chunked\r\n");
    } else if let Some(cl) = content_length {
        out.push_str("Content-Length: ");
        out.push_str(&cl.to_string());
        out.push_str("\r\n");
    }

    for line in body_headers {
        out.push_str(line);
        out.push_str("\r\n");
    }

    out.push_str("Connection: close\r\n\r\n");
    UpstreamRequest {
        head: out,
        content_length,
        chunked,
        expect_continue,
    }
}

/// 转发请求体：先发已缓冲字节，再按 Content-Length / chunked 流式转发。
async fn forward_request_body<S, T>(
    client: &mut S,
    upstream: &mut T,
    buffered: &[u8],
    content_length: Option<u64>,
    chunked: bool,
    timeout: Duration,
    buffer_pool: &BufferPool,
) -> std::io::Result<()>
where
    S: AsyncRead + Unpin,
    T: AsyncWrite + Unpin,
{
    // chunked：已缓冲字节属于分帧的一部分，必须交给状态机消费（否则会挂住等结束块）
    if chunked {
        return forward_chunked_body(client, upstream, buffered, timeout, buffer_pool).await;
    }

    // 已缓冲部分可能属于管道化请求的下一个请求（客户端连续发了两个请求）：
    // 超出 Content-Length 的字节不能当作本次 body 发给上游，否则污染请求体。
    let mut buffered = buffered;
    if let Some(cl) = content_length {
        if buffered.len() as u64 > cl {
            buffered = &buffered[..cl as usize];
        }
    }
    if !buffered.is_empty() {
        upstream.write_all(buffered).await?;
    }

    if let Some(cl) = content_length {
        let already_sent = buffered.len() as u64;
        if cl <= already_sent {
            return Ok(());
        }
        let mut remaining = cl - already_sent;
        let mut tmp = buffer_pool.get();
        let tmp_slice = tmp.as_mut_slice();
        while remaining > 0 {
            let want = std::cmp::min(remaining as usize, tmp_slice.len());
            let n = match tokio::time::timeout(timeout, client.read(&mut tmp_slice[..want])).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "timeout reading request body",
                    ))
                }
            };
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "client closed before sending complete request body",
                ));
            }
            upstream.write_all(&tmp_slice[..n]).await?;
            remaining -= n as u64;
        }
    }

    Ok(())
}

/// 读取上游响应头（可能连带读到 body 前缀），可选重写 Location，随后流式转发 body。
async fn forward_response<S, T>(
    client: &mut S,
    upstream: &mut T,
    cfg: &PathProxyConfig,
    base: &url::Url,
    timeout: Duration,
    buffer_pool: &BufferPool,
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
    T: AsyncRead + Unpin,
{
    let mut buf = buffer_pool.get();
    let slice = buf.as_mut_slice();

    // ── 读响应头 ──
    let mut head_data: Vec<u8> = Vec::with_capacity(2048);
    let mut head_end: Option<usize> = None;
    loop {
        let n = match tokio::time::timeout(timeout, upstream.read(slice)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timeout reading upstream response head",
                ))
            }
        };
        if n == 0 {
            break; // 上游直接关闭：下面按已读内容原样透传
        }
        head_data.extend_from_slice(&slice[..n]);
        if let Some(p) = find_header_end(&head_data) {
            head_end = Some(p);
            break;
        }
        if head_data.len() >= MAX_HEAD_BYTES {
            // 响应头异常大：不改写，原样透传（此处 break 时 head_end 仍为 None）
            warn!("Path-proxy: upstream response head exceeds {} bytes, passing through", MAX_HEAD_BYTES);
            break;
        }
    }

    if head_data.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "upstream closed without any response",
        ));
    }

    match head_end {
        Some(p) => {
            let status = parse_status_code(&head_data[..p]);
            let new_head = rebuild_response_head(&head_data[..p], status, cfg, base);
            if client.write_all(new_head.as_bytes()).await.is_err() {
                return Ok(());
            }
            if p < head_data.len() && client.write_all(&head_data[p..]).await.is_err() {
                return Ok(());
            }
        }
        None => {
            // 头不完整（超限或上游提前关闭）：原样写出，避免破坏字节流
            if client.write_all(&head_data).await.is_err() {
                return Ok(());
            }
        }
    }

    // ── 流式转发 body：保持 chunked / gzip 等原始编码不变 ──
    // 头部读完即归还池化缓冲区，body 阶段改用自适应缓冲
    drop(buf);
    let mut copy = AdaptiveBuffer::new();
    loop {
        copy.prepare();
        let n = match tokio::time::timeout(timeout, upstream.read(copy.as_mut_slice())).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timeout reading upstream response body",
                ))
            }
        };
        if n == 0 {
            debug!(
                "Path-proxy: response done, copy buffer {} KB",
                copy.current_size() / 1024
            );
            return Ok(());
        }
        copy.note_copied(n);
        if client.write_all(&copy.as_mut_slice()[..n]).await.is_err() {
            return Ok(()); // 客户端已断开，正常结束
        }
    }
}

/// 从状态行解析状态码（`HTTP/1.1 200 OK` → `Some(200)`）
fn parse_status_code(head: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(head);
    let first = text.lines().next()?;
    first.split_whitespace().nth(1)?.parse::<u16>().ok()
}

/// 重建响应头：Connection 改 close；3xx 时按需把 Location 重写回本代理前缀。
fn rebuild_response_head(
    head: &[u8],
    status: Option<u16>,
    cfg: &PathProxyConfig,
    base: &url::Url,
) -> String {
    let text = String::from_utf8_lossy(head);
    let mut out = String::with_capacity(head.len() + 64);

    let mut lines = text.split("\r\n");
    if let Some(first) = lines.next() {
        out.push_str(first);
        out.push_str("\r\n");
    }

    let rewrite = cfg.rewrite_location
        && matches!(status, Some(301) | Some(302) | Some(303) | Some(307) | Some(308));
    let mut connection_written = false;

    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = match line.split_once(':') {
            Some(pair) => pair,
            None => {
                out.push_str(line);
                out.push_str("\r\n");
                continue;
            }
        };
        if name.trim().eq_ignore_ascii_case("connection") {
            if !connection_written {
                out.push_str("Connection: close\r\n");
                connection_written = true;
            }
            continue;
        }
        if rewrite && name.trim().eq_ignore_ascii_case("location") {
            if let Some(new_loc) = rewrite_location(value.trim(), cfg, base) {
                out.push_str("Location: ");
                out.push_str(&new_loc);
                out.push_str("\r\n");
                continue;
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
    }

    // 上游未声明 Connection 时也要显式告知客户端：本响应结束后连接即关闭
    if !connection_written {
        out.push_str("Connection: close\r\n");
    }

    out.push_str("\r\n");
    out
}

/// 把上游返回的 Location 重写为 `/<prefix>/<绝对URL>`。
///
/// 相对路径按目标 URL 解析为绝对 URL（`/a` 与 `//host/a` 都支持）；
/// 非 http(s) 协议（如 `mailto:`）不重写，返回 `None` 保持原值。
fn rewrite_location(location: &str, cfg: &PathProxyConfig, base: &url::Url) -> Option<String> {
    if location.is_empty() {
        return None;
    }
    let abs = base.join(location).ok()?;
    if !matches!(abs.scheme(), "http" | "https") {
        return None;
    }
    Some(format!("/{}/{}", cfg.prefix(), abs.as_str()))
}

/// 发送最小化错误响应（用于 400 / 502，不暴露运行时细节）
async fn send_error<W: AsyncWrite + Unpin>(client: &mut W, code: u16, reason: &str, msg: &str) {
    let body = msg.as_bytes();
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        code,
        reason,
        body.len()
    );
    let _ = client.write_all(response.as_bytes()).await;
    let _ = client.write_all(body).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PathProxyConfig {
        PathProxyConfig::new("px", false, true).unwrap()
    }

    // ─── 前缀匹配 ───

    #[test]
    fn test_match_target_basic() {
        assert_eq!(
            cfg().match_target("/px/https://www.baidu.com/"),
            Some("https://www.baidu.com/")
        );
    }

    #[test]
    fn test_match_target_with_query_and_anchor() {
        assert_eq!(
            cfg().match_target("/px/http://a.com/b?x=1&y=2#frag"),
            Some("http://a.com/b?x=1&y=2#frag")
        );
    }

    #[test]
    fn test_match_target_rejects_other_prefixes() {
        // 前缀必须精确，`/pxx/` 与 `/p/` 都不应命中
        assert!(cfg().match_target("/pxx/https://a.com/").is_none());
        assert!(cfg().match_target("/p/https://a.com/").is_none());
        assert!(cfg().match_target("/https://a.com/").is_none());
        // 前缀自身、前缀+斜杠
        assert!(cfg().match_target("/px").is_none());
        assert!(cfg().match_target("/px/").is_none());
        // 普通相对路径仍需返回 None（保持 404 反扫描）
        assert!(cfg().match_target("/").is_none());
        assert!(cfg().match_target("/index.html").is_none());
    }

    #[test]
    fn test_match_target_requires_leading_slash() {
        assert!(cfg().match_target("px/https://a.com/").is_none());
    }

    // ─── 配置校验 ───

    #[test]
    fn test_config_trims_slashes_and_space() {
        let c = PathProxyConfig::new("  /px/  ", false, true).unwrap();
        assert_eq!(c.prefix(), "px");
    }

    #[test]
    fn test_config_rejects_invalid_prefix() {
        assert!(PathProxyConfig::new("", false, true).is_err());
        assert!(PathProxyConfig::new("   ", false, true).is_err());
        assert!(PathProxyConfig::new("p/x", false, true).is_err());
        assert!(PathProxyConfig::new("p x", false, true).is_err());
        assert!(PathProxyConfig::new("p%x", false, true).is_err());
        assert!(PathProxyConfig::new("p?x", false, true).is_err());
        // 非 ASCII：客户端会 percent-encode，导致前缀永远匹配不上
        assert!(PathProxyConfig::new("代理", false, true).is_err());
        assert!(PathProxyConfig::new("pé", false, true).is_err());
    }

    #[test]
    fn test_config_accepts_common_prefixes() {
        for p in ["px", "gh-proxy", "dl_2024", "v1.2", "PX9"] {
            assert!(PathProxyConfig::new(p, false, true).is_ok(), "{} should be valid", p);
        }
    }

    // ─── 请求头构造 ───

    #[test]
    fn test_build_upstream_request_rewrites_request_line_and_host() {
        let u = url::Url::parse("https://example.com/a/b?q=1").unwrap();
        let head = "POST /px/https://example.com/a/b?q=1 HTTP/1.1\r\n\
                    Host: 1.2.3.4\r\n\
                    User-Agent: curl\r\n\
                    Content-Length: 5\r\n\r\n";
        let req = build_upstream_request("POST", &u, head, None);
        let out = &req.head;
        assert!(out.starts_with("POST /a/b?q=1 HTTP/1.1\r\n"), "got: {}", out);
        assert!(out.contains("Host: example.com\r\n"));
        assert!(!out.contains("1.2.3.4"), "proxy host must be replaced");
        assert!(out.contains("User-Agent: curl\r\n"));
        assert!(out.ends_with("Connection: close\r\n\r\n"));
        assert_eq!(req.content_length, Some(5));
        assert!(!req.chunked);
        assert!(!req.expect_continue);
    }

    #[test]
    fn test_build_upstream_request_drops_hop_by_hop_headers() {
        let u = url::Url::parse("http://example.com/").unwrap();
        let head = "GET /px/http://example.com/ HTTP/1.1\r\n\
                    Host: 1.2.3.4\r\n\
                    Proxy-Authorization: Basic xxxx\r\n\
                    Proxy-Connection: keep-alive\r\n\
                    Connection: keep-alive\r\n\
                    Upgrade: websocket\r\n\
                    Expect: 100-continue\r\n\
                    Accept: */*\r\n\r\n";
        let req = build_upstream_request("GET", &u, head, None);
        let lower = req.head.to_ascii_lowercase();
        assert!(!lower.contains("proxy-authorization"), "credentials must not leak");
        assert!(!lower.contains("proxy-connection"));
        assert!(!lower.contains("upgrade:"));
        assert!(!lower.contains("expect:"), "100-continue is answered by the proxy");
        assert_eq!(lower.matches("connection:").count(), 1, "only the synthesized Connection header");
        assert!(req.head.contains("Accept: */*"));
        assert!(req.expect_continue, "must remember to answer 100-continue");
    }

    /// 用于认证的 `Authorization` 头不得转发给目标站点（凭据泄漏）。
    #[test]
    fn test_build_upstream_request_drops_authorization_used_for_auth() {
        let u = url::Url::parse("http://example.com/").unwrap();
        let head = "GET /px/http://example.com/ HTTP/1.1\r\n\
                    Host: 1.2.3.4\r\n\
                    Authorization: Basic dTpw\r\n\r\n";
        // 认证用的是 Authorization → 必须剔除
        let req = build_upstream_request("GET", &u, head, Some("authorization"));
        assert!(
            !req.head.to_ascii_lowercase().contains("authorization"),
            "proxy credentials leaked: {}",
            req.head
        );
        // 认证走的是 Proxy-Authorization → 目标站点自己的 Authorization 应保留
        let req2 = build_upstream_request("GET", &u, head, Some("proxy-authorization"));
        assert!(req2.head.contains("Authorization: Basic dTpw\r\n"));
    }

    #[test]
    fn test_build_upstream_request_chunked_drops_content_length() {
        let u = url::Url::parse("http://example.com/up").unwrap();
        let head = "POST /px/http://example.com/up HTTP/1.1\r\n\
                    Host: 1.2.3.4\r\n\
                    Content-Length: 3\r\n\
                    Transfer-Encoding: chunked\r\n\r\n";
        let req = build_upstream_request("POST", &u, head, None);
        assert!(req.chunked);
        assert_eq!(req.content_length, None);
        assert!(req.head.contains("Transfer-Encoding: chunked\r\n"));
        assert!(!req.head.contains("Content-Length"), "must not send both framings");
        // 分帧头应出现在普通头之前，但仍是一个合法头块
        assert!(req.head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_build_upstream_request_non_chunked_te_is_dropped() {
        let u = url::Url::parse("http://example.com/up").unwrap();
        let head = "POST /px/http://example.com/up HTTP/1.1\r\n\
                    Host: 1.2.3.4\r\n\
                    Transfer-Encoding: gzip\r\n\r\n";
        let req = build_upstream_request("POST", &u, head, None);
        assert!(!req.chunked);
        assert!(!req.head.contains("Transfer-Encoding"));
        assert_eq!(req.content_length, None);
    }

    // ─── 响应头重写 ───

    fn base() -> url::Url {
        url::Url::parse("https://example.com/dir/file").unwrap()
    }

    #[test]
    fn test_parse_status_code() {
        assert_eq!(parse_status_code(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status_code(b"HTTP/1.0 404 Not Found\r\n"), Some(404));
        assert_eq!(parse_status_code(b"garbage"), None);
    }

    #[test]
    fn test_rebuild_response_head_rewrites_absolute_location() {
        let head = b"HTTP/1.1 302 Found\r\n\
                     Location: https://cdn.example.com/x.zip\r\n\
                     Content-Length: 0\r\n\r\n";
        let out = rebuild_response_head(head, Some(302), &cfg(), &base());
        assert!(
            out.contains("Location: /px/https://cdn.example.com/x.zip\r\n"),
            "got: {}",
            out
        );
        assert!(out.contains("Connection: close\r\n"));
    }

    #[test]
    fn test_rebuild_response_head_resolves_relative_location() {
        let head = b"HTTP/1.1 301 Moved\r\nLocation: /other\r\n\r\n";
        let out = rebuild_response_head(head, Some(301), &cfg(), &base());
        assert!(out.contains("Location: /px/https://example.com/other\r\n"), "got: {}", out);
    }

    #[test]
    fn test_rebuild_response_head_keeps_location_when_disabled() {
        let c = PathProxyConfig::new("px", false, false).unwrap();
        let head = b"HTTP/1.1 302 Found\r\nLocation: https://cdn.example.com/x\r\n\r\n";
        let out = rebuild_response_head(head, Some(302), &c, &base());
        assert!(out.contains("Location: https://cdn.example.com/x\r\n"));
    }

    #[test]
    fn test_rebuild_response_head_ignores_location_on_200() {
        let head = b"HTTP/1.1 200 OK\r\nLocation: https://cdn.example.com/x\r\n\r\n";
        let out = rebuild_response_head(head, Some(200), &cfg(), &base());
        assert!(out.contains("Location: https://cdn.example.com/x\r\n"));
    }

    #[test]
    fn test_rewrite_location_skips_non_http_scheme() {
        let base_url = base();
        assert!(rewrite_location("mailto:a@b.com", &cfg(), &base_url).is_none());
    }
}
