//! rust-proxy 库入口
//!
//! 二进制（`src/main.rs`）只是本库的一层壳，因此所有能力都在这里以 `pub mod`
//! 暴露。这样做的收益：
//! - `tests/` 下的集成测试可以 `use rust_proxy::server::run_server_with_listener`
//!   起真实代理做端到端验证，不必复制一份启动逻辑；
//! - 模块可见性显式化（原先全部是 bin 私有的 `mod`，无法被任何外部测试引用）；
//! - `main.rs` 收敛到个位数行，入口与编排（[`app`]）分离。
//!
//! 目录分层（自底向上，箭头方向即依赖方向，无反向引用）：
//!
//! ```text
//! 支撑层 support：buffer_pool  logging  net
//!
//! 传输层 transport：tls（服务端证书）tls_client（客户端握手）proxy_protocol  stream
//!   → config（tls 取 `TlsConfig`，proxy_protocol 取 `ProxyProtocolMode`）, support
//!
//! 协议层 protocol：request（读客户端请求头）dispatch（分类与编排）connect（CONNECT 隧道）
//!                 classic（经典转发流水线）forward（上游目标与请求头构造）
//!                 relay（请求体转发与响应回传）path_proxy（路径前缀直连）
//!                 auth  http_util  http_body  http_response
//!   → config, support, transport::stream, transport::tls_client
//!
//! 配置层 config：mod（模型与运行时派生）schema（声明层唯一真源）
//!   → support::logging
//!
//! 装配与外围：
//!   server   → protocol, transport, support, config（监听、分派、优雅关闭）
//!   service  → config, support::logging, server（系统服务安装与管理）
//!   client   → support::net, transport::tls_client（`test-proxy` 自检客户端）
//!   app      → 以上全部 + clap 分派
//! ```
//!
//! 旧路径别名只保留确实有公开入口的模块（`protocol::{path_proxy, proxy}` 与
//! support / transport 的平铺导出）；`protocol` 内部的 `auth` / `http_body` /
//! `http_response` / `http_util` 条目均为 `pub(super)`，不再做无意义的别名。
//! 新代码请使用分层路径（`rust_proxy::protocol::...`）。

pub mod app;
pub mod client;
pub mod config;
pub mod protocol;
pub mod server;
pub mod service;
pub mod support;
pub mod transport;

// 兼容旧路径：只保留有公开入口的模块别名。
pub use protocol::{path_proxy, proxy};
pub use support::{buffer_pool, logging, net};
pub use transport::{proxy_protocol, stream, tls, tls_client};
