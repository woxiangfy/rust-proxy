//! 协议/转发层：请求读头与分类、认证、CONNECT / 经典转发、路径前缀直连、HTTP 分帧与响应构造
//!
//! 本层只处理"如何理解并转发一个代理请求"，不监听端口、不做 TLS 握手；
//! 接入与装配由 `crate::server` 负责。

pub mod auth;
pub(crate) mod connect;
pub(crate) mod forward;
pub mod http_body;
pub mod http_response;
pub mod http_util;
pub mod path_proxy;
pub mod proxy;
pub(crate) mod request;
