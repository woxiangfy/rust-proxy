//! 经典代理的兼容门面：仅保留对外入口的 re-export
//!
//! 实现已按职责拆分：
//! - [`crate::protocol::request`]：请求头读取与完整性判定
//! - [`crate::protocol::connect`]：CONNECT 隧道
//! - [`crate::protocol::dispatch`]：请求编排、分类与 404/431 响应
//! - [`crate::protocol::relay`]：经典转发流水线与响应回传
//!
//! 保留本模块是为了让 `server.rs` 与 `lib.rs` 的既有引用保持可用。

pub use crate::protocol::dispatch::{handle_client, handle_client_with_addr};
