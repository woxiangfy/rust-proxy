//! rust-proxy —— 轻量级 HTTP/HTTPS 代理服务器
//!
//! 本文件只保留二进制入口：所有模块与编排逻辑都在库 crate（[`rust_proxy`]）中，
//! 详见 [`rust_proxy::app::run`]。这样 `tests/` 下的集成测试可以复用同一份实现，
//! 而不是各自重新搭一套启动流程。

use anyhow::Result;

fn main() -> Result<()> {
    rust_proxy::app::run()
}
