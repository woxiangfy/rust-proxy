//! HTTP 代理服务器生命周期管理模块
//!
//! 负责服务器启动、TCP 监听、连接接受和优雅关闭。

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use log::{error, info};

use crate::buffer_pool::BufferPool;
use crate::config::Args;
use crate::proxy::handle_client;

/// 启动代理服务器，绑定端口并进入连接接受循环
///
/// `shutdown_rx` 用于接收外部关闭信号，实现优雅关闭。传入 `None` 则服务器无限运行。
pub async fn run_server(args: &Args, shutdown_rx: Option<oneshot::Receiver<()>>) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{}", args.port);

    info!("Binding address: {}", bind_addr);

    // 初始化缓冲区池，用于零拷贝数据传输
    let buffer_pool = Arc::new(BufferPool::new());

    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind to {}", bind_addr))?;

    info!("rust_proxy is running");

    accept_connections(listener, args.timeout, buffer_pool, shutdown_rx).await;

    Ok(())
}

/// 主循环：接受 TCP 连接并为每个客户端分配异步任务
///
/// 同时监听 `shutdown_rx` 关闭信号，收到信号后等待所有活跃连接完成再退出。
async fn accept_connections(
    listener: TcpListener,
    timeout: u64,
    buffer_pool: Arc<BufferPool>,
    mut shutdown_rx: Option<oneshot::Receiver<()>>,
) {
    let mut join_set = JoinSet::new();

    loop {
        let accept_future = listener.accept();

        let result = if let Some(shutdown) = shutdown_rx.as_mut() {
            tokio::select! {
                res = accept_future => Some(res),
                _ = shutdown => {
                    info!("Received shutdown signal, stopping server...");
                    info!("Waiting for {} active connections to complete...", join_set.len());
                    while join_set.join_next().await.is_some() {}
                    info!("All active connections completed, server stopped");
                    return;
                }
                _ = join_set.join_next(), if !join_set.is_empty() => None,
            }
        } else {
            tokio::select! {
                res = accept_future => Some(res),
                _ = join_set.join_next(), if !join_set.is_empty() => None,
            }
        };

        match result {
            Some(Ok((client, _addr))) => {
                let buffer_pool = Arc::clone(&buffer_pool);
                join_set.spawn(async move {
                    handle_client(client, timeout, buffer_pool).await;
                });
            }
            Some(Err(e)) => {
                error!("Failed to accept connection: {}", e);
            }
            None => {}
        }
    }
}
