//! HTTP 代理服务器生命周期管理模块
//!
//! 负责服务器启动、TCP 监听、连接接受和优雅关闭。

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::{error, info};

use crate::buffer_pool::BufferPool;
use crate::config::Args;
use crate::proxy::handle_client;

/// 启动代理服务器，绑定端口并进入连接接受循环
///
/// `shutdown_rx` 用于接收外部关闭信号，实现优雅关闭。传入 `None` 则服务器无限运行。
pub async fn run_server(args: &Args, shutdown_rx: Option<oneshot::Receiver<()>>) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{}", args.port);

    info!("正在启动 HTTP 代理服务器，绑定地址: {}", bind_addr);
    info!("超时时间: {} 秒", args.timeout);
    info!("日志级别: {}", args.log_level);

    // 初始化缓冲区池，用于零拷贝数据传输
    let buffer_pool = Arc::new(BufferPool::new());
    info!("缓冲区池已初始化（零拷贝模式）");

    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("无法绑定到 {}", bind_addr))?;

    info!("代理服务器已开始监听 {}", bind_addr);

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

        // 如果有 shutdown 接收器，则同时监听接受连接和关闭信号
        let result = if let Some(shutdown) = shutdown_rx.as_mut() {
            tokio::select! {
                res = accept_future => res,
                _ = shutdown => {
                    info!("收到关闭信号，正在停止服务器...");
                    info!("等待 {} 个活跃连接完成...", join_set.len());
                    // 等待所有正在处理的连接完成
                    while join_set.join_next().await.is_some() {}
                    info!("所有连接已完成，服务器已停止");
                    return;
                }
            }
        } else {
            accept_future.await
        };

        match result {
            Ok((client, _addr)) => {
                let buffer_pool = Arc::clone(&buffer_pool);
                join_set.spawn(async move {
                    handle_client(client, timeout, buffer_pool).await;
                });
            }
            Err(e) => {
                error!("接受连接失败: {}", e);
            }
        }
    }
}
