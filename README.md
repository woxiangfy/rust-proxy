# rust-proxy 使用手册

轻量级 HTTP/HTTPS 代理服务器，异步高并发，拿来即用。

## 功能特性

- HTTP/HTTPS 代理（CONNECT 隧道），支持多用户 HTTP Basic 认证
- **HTTPS 代理接入**：客户端可用 `https://` 协议连接代理服务器
- **路径前缀直连模式**：不配代理，直接请求 `/px/https://example.com/` 由服务器代取（类似 gh-proxy）
- **自签证书自动生成**：指定 `--https-port` 但证书缺失/加载失败时，自动生成 10 年自签证书
- **TLS 证书热重载**：用户证书更新后自动生效，无需重启
- **PROXY Protocol**：挂在 nginx/HAProxy 后自动识别真实客户端 IP
- 动态缓冲区池（8KB → 256KB 自适应，纯流式零拷贝）
- Windows / Linux，可安装为系统服务

## 快速开始

```bash
# 启动（自动寻找运行目录下的 config.toml）
./rust-proxy start

# 指定端口 / 配置文件
./rust-proxy start --port 3128
./rust-proxy start --config /path/to/config.toml

# 测试代理
./rust-proxy test http://127.0.0.1:8080
```

### 启用 HTTPS 代理接入

**启用规则**

- HTTPS **只有显式指定** `--https-port`（或配置 `https_port`）才启用；只给证书不给端口不生效。
- 证书缺失或加载失败 → 自动生成 10 年自签证书，并输出 warn 日志。
- `--port` 默认 8080；但若**只给 `--https-port` 而不给 `--port`**，则仅 HTTPS 模式。

```bash
# 自备证书
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
./rust-proxy start --tls-cert cert.pem --tls-key key.pem --https-port 8443

# 仅 HTTPS（自动自签，适合测试）
./rust-proxy start --https-port 8443

# HTTP + HTTPS 同时启用
./rust-proxy start --port 8080 --https-port 8443 --tls-cert cert.pem --tls-key key.pem

# 客户端接入
curl -x http://127.0.0.1:8080 https://example.com
curl -x https://127.0.0.1:8443 --proxy-insecure https://example.com
curl -x https://127.0.0.1:8443 --proxy-cacert cert.pem https://example.com
```

证书/私钥支持相对路径（相对配置文件目录解析）与绝对路径。

## 命令参数

### start

| 参数 | 说明 | 默认 |
| --- | --- | --- |
| `--port` | HTTP 监听端口（未指定且未指定 `--https-port` 时默认 8080） | 8080（条件默认） |
| `--https-port` | HTTPS 监听端口，显式指定才启用 HTTPS | 无 |
| `--tls-cert` / `--tls-key` | PEM 证书 / 私钥（PKCS#8 或 RSA） | 无（缺失则自签） |
| `--timeout` | 读写超时（秒） | 30 |
| `--log-level` | 日志级别 | info |
| `--log-file` | 日志文件（指定后不再输出到控制台） | 无 |
| `--config` | 配置文件路径 | 运行目录 config.toml |
| `--multi-thread` | 启用多线程 Tokio 运行时 | false |
| `--proxy-protocol` | 等价于 `--proxy-protocol-mode auto`（兼容保留） | false |
| `--proxy-protocol-mode` | `auto` / `disable` / `require` | auto |
| `--proxy-protocol-trusted-ips` | 可信代理 IP，逗号分隔 | 无（接受所有来源） |
| `--path-proxy-prefix` | 启用路径前缀直连模式并指定前缀（如 `px`） | 无 |
| `--path-proxy-insecure` | 路径模式跳过上游 TLS 校验 | false |

### test

```bash
./rust-proxy test https://127.0.0.1:8443                     # 目标默认 https://api.myip.la/cn
./rust-proxy test https://127.0.0.1:8443 https://example.com
```

代理地址**必须带 `http://` 或 `https://`**。`https://` 接入会自动跳过代理证书校验（支持自签）；目标 HTTPS 走 CONNECT 隧道后用系统 CA 验证。

### server（系统服务，需管理员权限）

```bash
./rust-proxy server install --port 8080 --log-file proxy.log
./rust-proxy server start | stop | restart | uninstall
sc query rust-proxy          # Windows 验证
```

`server install` 参数与 `start` 一致（`--log-file` 默认落到可执行文件同目录 `proxy.log`），安装时参数写入服务配置。停止/关机时会等待活跃连接处理完毕再退出。

## 配置文件

TOML，所有项可选，**优先级：命令行 > 配置文件 > 默认值**。

配置采用**严格解析**：出现未知键会直接报错（如把 `proxy_protocol_mode` 拼错、或把顶层键写在 `[[auth]]` 段之后——按 TOML 语义它会被算作该数组元素的字段），不再静默忽略。`--config` 指定的文件读取/解析失败时，日志会打出 `error` 并回退到"仅命令行参数"，避免"以为开了认证其实没开"。

```toml
port = 8080
timeout = 60
log_level = "info"
log_file = "proxy.log"

# HTTPS 代理（显式设置 https_port 才启用）
https_port = 8443
tls_cert = "cert.pem"
tls_key = "key.pem"

# 认证：配置后客户端必须通过 Basic 认证
# [[auth]]
# username = "admin"
# password = "secret"

# PROXY Protocol（默认 auto）
# proxy_protocol_mode = "auto"        # auto / disable / require
# http_proxy_protocol = "disable"     # 可选：按端口覆盖
# https_proxy_protocol = "auto"
# proxy_protocol_trusted_ips = ["10.0.0.1"]

# 路径前缀直连模式（省略即不启用）
# path_proxy_prefix = "px"
# path_proxy_insecure_tls = false
# path_proxy_rewrite_location = true

# 日志级别：trace / debug / info / warn / error
```

## 路径前缀直连模式

客户端不配代理，把目标完整 URL 拼在路径前缀后：

```text
http://1.2.3.4/px/https://www.baidu.com/     → 访问 https://www.baidu.com/
http://1.2.3.4/px/http://example.com/a.txt   → 访问 http://example.com/a.txt
```

```bash
./rust-proxy start --port 80 --path-proxy-prefix px --path-proxy-insecure

curl -O http://1.2.3.4/px/https://example.com/file.zip
curl "http://1.2.3.4/px/https://api.example.com/search?q=rust&page=2"
curl -X POST -d "k=v" http://1.2.3.4/px/https://postman-echo.com/post
curl -u admin:secret "http://1.2.3.4/px/https://example.com/file.zip"
```

**行为要点**

| 场景 | 行为 |
| --- | --- |
| 前缀精确命中 | 解析目标 URL，服务器直连上游后回传 |
| `/{prefix}`、`/{prefix}/`、其他相对路径 | 404（保持反扫描特性，前缀本身就是路径口令） |
| 目标非法 / 非 http(s) | 400 |
| 上游不可达 | 502 |
| 上游 3xx | `Location` 重写为 `/{prefix}/<绝对URL>`（可关） |
| 请求体 | 按 Content-Length / chunked 流式转发；两者并存以 chunked 为准（防请求走私） |
| 响应体 | 原始字节流式转发，chunked / gzip / br 原样保留 |
| 逐跳头 | `Connection`、`Keep-Alive`、`Proxy-*`、`Upgrade`、`TE`、`Trailer`、`Expect` 不转发；`Host` 重写为上游主机 |
| 认证 | 复用 `[[auth]]`，接受 `Authorization` 或 `Proxy-Authorization`，质询返回 401 |
| 凭据隔离 | 用于本代理认证的头不会转发给上游 |
| `Expect: 100-continue` | 代理直接回 100，不转发给上游 |

**安全提示**：该端口等于一个「URL 网关」，任何能访问到它的人都能借它访问服务器可达的任意地址（含内网、云元数据）。生产环境务必配置 `[[auth]]`、使用不易猜到的前缀（如 `dl-8f3c2a`），且不要裸奔在公网。未配置认证时启动会输出 warn 日志。

**前缀命名**：自动去掉首尾空白与 `/`，只允许 ASCII 字母、数字、`-`、`_`、`.`，大小写敏感。含 `/`、`?`、`#`、`%`、空白或非 ASCII 字符会在启动时报错退出。

**已知限制**

- 不支持 WebSocket 升级与非 http(s) 协议（`ftp://`、`file://`）；需要 WebSocket 请用 CONNECT 模式。
- 目标 URL 不做 percent-decoding，`%20` 原样传给上游。
- 页面内站内绝对路径链接（`href="/abs"`）会丢前缀 → 404，相对路径正常。本模式适合「按 URL 下载文件 / 调接口」，不适合通用反代。
- 上游 `Set-Cookie` 的 `Domain` 与代理域名不符，Cookie 通常不会保存。

**性能**：与经典代理共用同一纯流式拷贝链路，内存与文件大小无关。缓冲区随传输自适应扩到 256KB（5s 或累计 32MB 触发，取先到者）。实测 512MB 单连接下载 RSS 恒定约 9MB，HTTP 上游约 1.1GB/s、HTTPS 上游约 0.55GB/s（TLS record 上限所致）。`timeout` 是单次读写超时，不是总时长——持续有数据就不会被中断。

## 客户端接入

| 设置项 | 值 |
| --- | --- |
| HTTP / HTTPS 代理 | `127.0.0.1:8080` |

```bash
# curl
curl -x http://127.0.0.1:8080 http://httpbin.org/ip
curl -x http://127.0.0.1:8080 https://httpbin.org/ip
curl -x https://127.0.0.1:8443 --proxy-insecure https://httpbin.org/ip

# 环境变量
export http_proxy=http://127.0.0.1:8080; export https_proxy=http://127.0.0.1:8080   # Linux/macOS
$env:http_proxy="http://127.0.0.1:8080"; $env:https_proxy="http://127.0.0.1:8080"   # PowerShell
```

不支持 FTP 协议。日志默认输出到 stderr，格式 `YYYY-MM-DD HH:MM:SS 级别 消息`（本地时间）；指定 `--log-file` 后仅写文件，单文件超过 10MB 自动滚动为 `proxy.YYYYMMDD_HHMMSS.log`，最多保留 10 个。

## 挂在 nginx/HAProxy 后

默认 `auto` 即全自动识别，每个连接独立检测 PROXY v1/v2 签名：匹配则解析真实 IP，不匹配则前缀数据回退给应用层正常处理（不截断）。因此天然兼容「HTTP 直连 + HTTPS 经 nginx」混合场景。

- `auto`（默认，推荐）：自动识别
- `disable`：完全禁用
- `require`：强制要求带 PROXY 头，否则断开（上游全是 LB 时可用）

```nginx
stream {
    server {
        listen 443;
        proxy_pass $backend;   # 指向 rust-proxy 的 HTTPS 端口
        ssl_preread on;
        proxy_protocol on;
    }
}
```

建议同时配置 `--proxy-protocol-trusted-ips` 限制来源，防止客户端伪造 IP。`require` 模式必须两端同时开启，否则普通连接会被丢弃。

## 常见问题

| 问题 | 处理 |
| --- | --- |
| 端口被占用 | 换端口或停止占用进程：`netstat -ano \| findstr :8080`（Win）、`lsof -i :8080`（Linux） |
| 代理无法连接 | 检查防火墙、服务是否启动、端口是否正确 |
| 日志无权限 | `sudo` 运行，或改用用户可写目录 `./proxy.log` |
| HTTPS 代理接入失败 | 确认显式指定了 `--https-port`；检查证书路径、PEM 格式、证书私钥是否匹配、证书链是否完整、`--port` 与 `--https-port` 是否冲突 |
| TLS 握手超时 | 客户端 TLS 版本不支持（rustls 支持 1.2/1.3）、未信任自签证书（需 `--proxy-insecure` 或导入 CA）、中间设备拦截 |

```bash
openssl x509 -in cert.pem -text -noout    # 验证证书
openssl rsa -in key.pem -check -noout     # 验证私钥
```

自签证书不参与热重载（无外部源文件可监听）；用户证书每 1 小时检查一次 mtime，变化则原子替换 `TlsAcceptor`，已建立连接不受影响，失败则保留旧证书继续服务。更新时建议 `mv` 原子替换，避免读到半截文件。

## 架构

代码已整理为库（`src/lib.rs`）+ 薄壳二进制（`src/main.rs`，11 行），因此集成测试可以起真实代理做端到端验证。`proxy.rs` 通过 `handle_client_generic<S: AsyncRead + AsyncWrite>` 实现传输层无关（HTTP 明文 / TLS）的请求处理。

| 模块 | 职责 |
| --- | --- |
| `lib.rs` / `main.rs` | 库入口（模块导出与分层）/ 薄壳二进制 |
| `app.rs` | 进程编排：运行时装配、关停信号、子命令分派 |
| `proxy.rs` | 请求解析、分类、CONNECT 隧道、经典 HTTP 转发 |
| `auth.rs` | Basic 凭据校验（等时比较）、407 / 401 质询 |
| `client.rs` | `test-proxy` 自检客户端（CONNECT + TLS） |
| `path_proxy.rs` | 路径前缀模式：URL 解析、上游直连、头过滤、流式回传、Location 重写 |
| `server.rs` | 监听管理、连接分发（`ConnContext`）、优雅关闭 |
| `tls.rs` | TLS 证书加载、自签回退、mtime 热重载 |
| `proxy_protocol.rs` | PROXY Protocol v1/v2 解析、模式映射、真实地址解析（`PpPolicy`） |
| `config.rs` | 配置解析与合并（命令行 + TOML） |
| `net.rs` | 上游连接（DNS/IPv4/IPv6）、`host:port` 解析、错误分级 |
| `http_util.rs` | 头部结束查找、逐跳头判定、authority 构造 |
| `http_body.rs` | chunked 分帧状态机与流式转发 |
| `http_response.rs` | 错误响应构造（404 / 407 / 401 共用骨架） |
| `io.rs` | `PrefixedStream`（PROXY 前缀回填 / CONNECT 提前读） |
| `buffer_pool.rs` | 自适应缓冲区池 |
| `logging.rs` | 按大小滚动日志（10MB / 10 个文件） |
| `service.rs` | 系统服务安装与管理 |

前台 `start` 也支持优雅关停：SIGINT/SIGTERM（Linux/macOS）与 Ctrl+C（Windows）后停止接受新连接、等待活跃连接处理完再退出。
