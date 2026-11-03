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
//! buffer_pool  io  net  http_util  http_body  logging
//!        \       |    |      |          |        /
//!         tls  proxy_protocol  config  service
//!                    \          |        /
//!                     proxy  path_proxy
//!                          \    /
//!                          server
//!                            |
//!                           app
//! ```

pub mod app;
pub mod buffer_pool;
pub mod config;
pub mod http_body;
pub mod http_response;
pub mod http_util;
pub mod io;
pub mod logging;
pub mod net;
pub mod path_proxy;
pub mod proxy;
pub mod proxy_protocol;
pub mod server;
pub mod service;
pub mod tls;
