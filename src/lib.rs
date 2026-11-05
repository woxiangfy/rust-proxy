//! rust-proxy 库入口
//!
//! 二进制（`src/main.rs`）只是本库的一层壳，因此所有能力都在这里以 `pub mod`
//! 暴露。这样做的收益：
//! - `tests/` 下的集成测试可以 `use rust_proxy::server::run_server_with_listener`
//!   起真实代理做端到端验证，不必复制一份启动逻辑；
//! - 模块可见性显式化（原先全部是 bin 私有的 `mod`，无法被任何外部测试引用）；
//! - `main.rs` 收敛到个位数行，入口与编排（[`app`]）分离。
//!
//! 模块分层（自底向上，箭头方向即依赖方向，无反向引用）：
//!
//! ```text
//! 叶子层（无内部依赖）：
//!   buffer_pool  stream  net  http_util  http_body  http_response  logging
//!
//! 中层：
//!   config   → logging
//!   auth     → config, http_response
//!   tls      → buffer_pool
//!   tls_client            （客户端 TLS：自检客户端 / 路径模式上游共用）
//!   client   → net, tls_client        （`test-proxy` 自检客户端）
//!
//! 处理层：
//!   proxy        → auth, path_proxy, http_body, http_util, http_response, net, stream, buffer_pool
//!   path_proxy   → net, http_body, http_util, http_response, buffer_pool, tls_client
//!   proxy_protocol → stream
//!
//! 装配层：
//!   server → tls, proxy_protocol, proxy, path_proxy, config, buffer_pool, stream
//!   service → config, logging, server
//!   app    → 以上全部 + clap 分派
//! ```

pub mod app;
pub mod auth;
pub mod buffer_pool;
pub mod client;
pub mod config;
pub mod http_body;
pub mod http_response;
pub mod http_util;
pub mod logging;
pub mod net;
pub mod path_proxy;
pub mod proxy;
pub mod proxy_protocol;
pub mod server;
pub mod service;
pub mod stream;
pub mod tls;
pub mod tls_client;
