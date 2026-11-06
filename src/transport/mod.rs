//! 传输/接入原语：TLS 服务端证书体系、客户端 TLS、PROXY Protocol、前缀流适配
//!
//! 监听、连接分发与优雅关停留在 `crate::server`（装配入口），本层只提供可复用的传输件。

pub mod proxy_protocol;
pub mod stream;
pub mod tls;
pub mod tls_client;
