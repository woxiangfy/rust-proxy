# rust-proxy 用户使用手册

## 简介

rust-proxy 是一个轻量级 HTTP/HTTPS 代理服务器，支持异步高并发处理。AI辅组开发。

## 功能特性

- HTTP/HTTPS 代理支持（CONNECT 隧道）
- **HTTPS 代理接入支持（Secure Web Proxy）**：客户端可通过 HTTPS 协议接入代理服务器
- 异步高并发处理
- 支持多线程运行
- 支持windows/linux平台, 可以安装为系统服务
- HTTP Basic 代理认证（支持多用户）
- 动态缓冲区池（自动扩缩容，零拷贝优化）

## 快速开始

### 基本用法

```bash
# 启动代理（自动寻找运行目录下的 config.toml）
./rust-proxy start

# 指定端口
./rust-proxy start --port 3128

# 指定配置文件
./rust-proxy start --config /path/to/config.toml

# 测试代理连接
./rust-proxy test 127.0.0.1:8080
```

### 启用 HTTPS 代理接入

启用 HTTPS 代理后，服务器会同时监听 HTTP 和 HTTPS 两个端口。客户端可通过任一协议接入代理：

```bash
# 生成自签证书（测试用，生产环境请使用 CA 签发的证书）
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

# 启动代理（HTTP=8080，HTTPS=8443）
./rust-proxy start --tls-cert cert.pem --tls-key key.pem --https-port 8443

# 通过 HTTP 接入代理（兼容模式）
curl -x http://127.0.0.1:8080 https://example.com

# 通过 HTTPS 接入代理（加密通道，防中间人篡改代理流量）
curl -x https://127.0.0.1:8443 --proxy-insecure https://example.com
# 或指定 CA 证书验证代理身份：
curl -x https://127.0.0.1:8443 --proxy-cacert cert.pem https://example.com
```

### 完整参数示例

```bash
./rust-proxy start --port 8080 --timeout 30 --log-level info --log-file proxy.log
```

## 命令说明

### start 命令

启动代理服务器，支持以下参数：

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--port` | HTTP 监听端口 | 8080 |
| `--timeout` | 请求超时时间（秒） | 30 |
| `--log-level` | 日志级别 | info |
| `--log-file` | 日志文件路径 | 无（输出到控制台） |
| `--config` | 配置文件路径 | 自动寻找运行目录下的 config.toml |
| `--https-port` | HTTPS 代理监听端口 | 8443（启用 TLS 时生效） |
| `--tls-cert` | TLS 证书文件路径（PEM 格式） | 无 |
| `--tls-key` | TLS 私钥文件路径（PEM 格式，PKCS#8 或 RSA） | 无 |

> **说明**：只有同时提供 `--tls-cert` 和 `--tls-key` 时才会启用 HTTPS 代理。证书/私钥支持相对路径（相对于配置文件目录解析）和绝对路径。

### test 命令

测试指定的代理服务器是否正常工作：

```bash
# 测试本地代理
./rust-proxy test 127.0.0.1:8080

# 指定测试 URL
./rust-proxy test 127.0.0.1:8080 https://example.com
```

### server 命令

将代理服务器安装为系统服务，支持 Windows 平台。**需要管理员权限**执行。

```bash
# 安装服务（指定参数）
./rust-proxy server install --port 8080 --log-file proxy.log

# 卸载服务
./rust-proxy server uninstall

# 启动服务
./rust-proxy server start

# 停止服务
./rust-proxy server stop

# 重启服务
./rust-proxy server restart
```

#### server install 参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--port` | HTTP 监听端口 | 8080 |
| `--timeout` | 请求超时时间（秒） | 30 |
| `--log-level` | 日志级别 | info |
| `--log-file` | 日志文件路径 | 可执行文件同目录下的 proxy.log |
| `--https-port` | HTTPS 代理监听端口 | 8443（启用 TLS 时生效） |
| `--tls-cert` | TLS 证书文件路径 | 无 |
| `--tls-key` | TLS 私钥文件路径 | 无 |

#### 使用注意事项

1. **安装服务**时，会将当前指定的参数（端口、日志文件等）保存到服务配置中，后续启动服务时会使用这些参数
2. **服务运行时**，日志默认输出到可执行文件同目录下的 `proxy.log`
3. **Windows 服务名称**为 `rust-proxy`
4. **停止服务**时，会等待当前正在处理的连接完成后再退出，确保数据不丢失
5. **系统关机**时，服务会自动优雅退出

#### 服务管理完整流程

```bash
# 1. 以管理员身份打开命令提示符或 PowerShell

# 2. 安装服务（指定端口和日志文件）
rust-proxy server install --port 8080 --log-file proxy.log

# 3. 启动服务
rust-proxy server start

# 4. 验证服务是否运行（Windows）
sc query rust-proxy

# 5. 停止服务
rust-proxy server stop

# 6. 卸载服务
rust-proxy server uninstall
```

## 配置参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--port` | HTTP 监听端口 | 8080 |
| `--https-port` | HTTPS 代理监听端口 | 8443（启用 TLS 时生效） |
| `--tls-cert` | TLS 证书文件路径（PEM 格式） | 无 |
| `--tls-key` | TLS 私钥文件路径（PEM 格式，PKCS#8 或 RSA） | 无 |
| `--timeout` | 请求超时时间（秒） | 30 |
| `--log-level` | 日志级别 | info |
| `--log-file` | 日志文件路径 | 无（输出到控制台） |
| `--config` | 配置文件路径 | 自动寻找 |
| `--multi-thread` | 启用多线程运行时 | false |

### 日志级别

| 级别 | 说明 |
|------|------|
| `trace` | 最详细日志（包含所有调试信息） |
| `debug` | 调试信息 |
| `info` | 一般信息（默认） |
| `warn` | 警告信息 |
| `error` | 错误信息 |

## 配置文件

支持 TOML 格式配置文件，所有配置项均为可选。

### 配置文件示例

创建 `config.toml`：

```toml
# HTTP 监听端口
port = 8080

# 日志文件路径（可选）
log_file = "proxy.log"

# 请求超时时间（秒）
timeout = 60

# 日志级别
log_level = "info"

# HTTPS 代理配置（可选）
# 同时提供证书和私钥后，代理会额外监听 HTTPS 端口
https_port = 8443
tls_cert = "cert.pem"
tls_key = "key.pem"

# 代理认证配置（可选）
# 配置后，客户端必须通过 HTTP Basic 认证才能使用代理
# [[auth]]
# username = "admin"
# password = "secret"
```

### 配置优先级

命令行参数 > 配置文件 > 默认值

即使配置文件中指定了端口，运行 `./rust-proxy start --port 9090` 仍会使用 9090 端口。

## 使用示例

### 方式一：仅命令行参数

```bash
# 开发测试环境
./rust-proxy start --port 8888 --log-level debug

# 生产环境
./rust-proxy start --port 80 --timeout 120 --log-level warn --log-file /var/log/proxy.log
```

### 方式二：配置文件

```bash
# 自动寻找运行目录下的 config.toml
./rust-proxy start

# 指定配置文件
./rust-proxy start --config /etc/proxy/myconfig.toml
```

### 方式三：混合使用

```bash
# 配置文件设置基础配置，命令行覆盖部分参数
./rust-proxy start --config config.toml --port 9090 --log-level debug
```

### 方式四：启用 HTTPS 代理接入

```bash
# 命令行方式
./rust-proxy start --tls-cert /etc/proxy/cert.pem --tls-key /etc/proxy/key.pem --https-port 8443

# 配置文件方式（config.toml 中已配置 https_port/tls_cert/tls_key）
./rust-proxy start --config /etc/proxy/config.toml

# 安装为系统服务（含 HTTPS）
./rust-proxy server install --port 8080 --tls-cert C:\certs\cert.pem --tls-key C:\certs\key.pem --https-port 8443
```

## 代理设置

### 浏览器代理设置

| 设置项 | 值 |
|--------|-----|
| HTTP代理 | `127.0.0.1:8080` |
| HTTPS代理 | `127.0.0.1:8080` |
| FTP代理 | `127.0.0.1:8080` |

### curl 测试

```bash
# 使用代理访问
curl -x http://127.0.0.1:8080 http://httpbin.org/ip

# HTTPS测试（通过CONNECT隧道）
curl -x http://127.0.0.1:8080 https://httpbin.org/ip

# 通过 HTTPS 代理接入（需启用 TLS 监听）
curl -x https://127.0.0.1:8443 --proxy-insecure https://httpbin.org/ip
```

### 命令行环境变量

```bash
# Linux/Mac
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

# Windows PowerShell
$env:http_proxy="http://127.0.0.1:8080"
$env:https_proxy="http://127.0.0.1:8080"
```

## 日志查看

### 控制台输出

默认情况下，日志直接输出到控制台：

```
2026-06-20T10:30:00.123456Z  INFO rust_proxy::server: Proxy server listening on 0.0.0.0:8080
2026-06-20T10:30:05.234567Z  INFO 127.0.0.1:54321 -> GET http://example.com -> 200 OK
```

### 日志文件

指定日志文件后，日志同时写入文件和控制台：

```bash
./rust-proxy --log-file proxy.log
```

日志文件格式示例：

```
2026-06-20T10:30:00.123456Z  INFO Starting HTTP proxy server on 0.0.0.0:8080
2026-06-20T10:30:05.234567Z  INFO 127.0.0.1:54321 -> GET http://example.com
2026-06-20T10:30:05.567890Z  INFO Request completed: GET http://example.com
```

## 常见问题

### 1. 端口被占用

```
Error: Failed to bind to 0.0.0.0:8080
```

解决方法：使用其他端口或停止占用端口的进程

```bash
# Windows查看端口占用
netstat -ano | findstr :8080

# Linux查看端口占用
lsof -i :8080
```

### 2. 代理无法连接

- 检查防火墙设置
- 确认代理服务器已启动
- 验证端口配置正确

### 3. 日志文件无权限

```bash
# Linux/Mac
sudo ./rust-proxy --log-file /var/log/proxy.log

# 或使用用户有权限的目录
./rust-proxy --log-file ./proxy.log
```

### 4. HTTPS网站无法访问

某些HTTPS网站可能不支持代理访问，属于正常现象。rust-proxy 通过 CONNECT 方法支持 HTTPS 隧道，但部分网站可能有访问限制。

### 5. HTTPS 代理接入失败

启用 HTTPS 代理接入（`--tls-cert` / `--tls-key`）时若启动失败，请检查：

- 证书文件路径是否正确（相对路径相对于配置文件目录解析）
- 证书文件是否为合法的 PEM 格式
- 证书和私钥是否匹配
- HTTP 端口与 HTTPS 端口是否冲突（`--port` 和 `--https-port` 不能相同）
- 证书链是否完整（应包含中间证书，可使用 fullchain.pem）

```bash
# 验证证书文件格式
openssl x509 -in cert.pem -text -noout

# 验证私钥文件格式
openssl rsa -in key.pem -check -noout
```

### 6. TLS 握手超时

代理日志中出现 `TLS handshake timed out` 时，通常是客户端发起连接后未完成 TLS 握手。可能原因：

- 客户端不支持服务器的 TLS 版本（rustls 默认支持 TLS 1.2 和 1.3）
- 客户端未配置信任的服务器证书（自签证书需使用 `--proxy-insecure` 或导入 CA）
- 网络中间设备拦截了 TLS 流量

## 架构说明

### 传输层抽象

代理服务器支持两种传输模式，共用同一套请求处理逻辑：

- **HTTP 模式**（默认）：监听明文 TCP，客户端通过 `http://host:port` 接入
- **HTTPS 模式**（启用 TLS 后）：额外监听 TLS 加密端口，客户端通过 `https://host:port` 接入

`proxy.rs` 中通过泛型 `handle_client_generic<S: AsyncRead + AsyncWrite>` 实现传输层无关的请求处理，`server.rs` 负责 TCP/TLS 监听和 TLS 握手，握手成功后将 `TlsStream` 交给泛型处理函数。

### 关键组件

| 模块 | 职责 |
|------|------|
| `proxy.rs` | HTTP 请求解析、认证校验、CONNECT 隧道、HTTP 转发（泛型，支持 TCP/TLS 流） |
| `server.rs` | 监听管理、TLS acceptor 构建、连接分发、优雅关闭 |
| `config.rs` | 配置解析与合并（命令行 + TOML） |
| `buffer_pool.rs` | 动态扩缩容的缓冲区池（零拷贝优化） |
| `logging.rs` | 按天滚动的日志系统 |
| `service.rs` | 系统服务安装与管理 |

## 日志级别选择建议

| 场景 | 推荐级别 | 说明 |
|------|----------|------|
| 日常使用 | `info` | 记录基本请求信息 |
| 开发调试 | `debug` | 显示详细调试信息 |
| 生产环境 | `warn` | 仅显示警告和错误 |
| 排查问题 | `trace` | 最详细的日志记录 |

## 性能提示

- 默认超时时间 30 秒适合大多数场景
- 高并发场景下，日志级别建议使用 `info` 或更高
- 日志文件会占用磁盘空间，定期清理或轮转日志