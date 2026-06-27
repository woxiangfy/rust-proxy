# rust-proxy 用户使用手册

## 简介

rust-proxy 是一个轻量级 HTTP 代理服务器，支持异步高并发处理，可用于网络访问代理、日志记录等场景。

## 功能特性

- HTTP/HTTPS 代理支持
- 异步高并发处理
- 单进程运行
- 详细的日志记录功能
- 灵活的配置方式
- 自动寻找默认配置文件

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

### 完整参数示例

```bash
./rust-proxy start --port 8080 --timeout 30 --log-level info --log-file proxy.log
```

## 命令说明

### start 命令

启动代理服务器，支持以下参数：

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--port` | 监听端口 | 8080 |
| `--timeout` | 请求超时时间（秒） | 30 |
| `--log-level` | 日志级别 | info |
| `--log-file` | 日志文件路径 | 无（输出到控制台） |
| `--config` | 配置文件路径 | 自动寻找运行目录下的 config.toml |

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
| `--port` | 监听端口 | 8080 |
| `--timeout` | 请求超时时间（秒） | 30 |
| `--log-level` | 日志级别 | info |
| `--log-file` | 日志文件路径 | 可执行文件同目录下的 proxy.log |

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
| `--port` | 监听端口 | 8080 |
| `--timeout` | 请求超时时间（秒） | 30 |
| `--log-level` | 日志级别 | info |
| `--log-file` | 日志文件路径 | 无（输出到控制台） |
| `--config` | 配置文件路径 | 自动寻找 |

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
# 监听端口
port = 8080

# 日志文件路径（可选）
log_file = "proxy.log"

# 请求超时时间（秒）
timeout = 60

# 日志级别
log_level = "info"
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