//! Server module for HTTP proxy server lifecycle management

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::{error, info};

use crate::buffer_pool::BufferPool;
use crate::config::Args;
use crate::proxy::handle_client;

/// Start the proxy server with the given configuration
pub async fn run_server(args: &Args, shutdown_rx: Option<oneshot::Receiver<()>>) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{}", args.port);
    
    info!("Starting HTTP proxy server on {}", bind_addr);
    info!("Timeout: {} seconds", args.timeout);
    info!("Log level: {}", args.log_level);

    let buffer_pool = Arc::new(BufferPool::new());
    info!("Buffer pool initialized for zero-copy operations");

    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind to {}", bind_addr))?;

    info!("Proxy server listening on {}", bind_addr);

    accept_connections(listener, args.timeout, buffer_pool, shutdown_rx).await;
    
    Ok(())
}

/// Main server loop accepting and spawning client connections
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
                res = accept_future => res,
                _ = shutdown => {
                    info!("Received shutdown signal, stopping server...");
                    info!("Waiting for {} active connections to complete...", join_set.len());
                    while join_set.join_next().await.is_some() {}
                    info!("All connections completed, server stopped");
                    return;
                }
            }
        } else {
            accept_future.await
        };

        match result {
            Ok((client, _addr)) => {
                let timeout = timeout;
                let buffer_pool = Arc::clone(&buffer_pool);
                join_set.spawn(async move {
                    handle_client(client, timeout, buffer_pool).await;
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}
