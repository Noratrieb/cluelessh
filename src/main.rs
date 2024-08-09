use std::net::SocketAddr;

use eyre::{Context, Result};
use fakessh::{ServerConnection, SshError};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{error, info};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt().init();

    let listener = TcpListener::bind("0.0.0.0:2222")
        .await
        .wrap_err("binding listener")?;

    loop {
        let next = listener.accept().await?;

        tokio::spawn(async {
            if let Err(err) = handle_connection(next).await {
                error!(?err, "error handling connection");
            }
        });
    }
}

async fn handle_connection(next: (TcpStream, SocketAddr)) -> Result<()> {
    let (mut conn, addr) = next;

    info!(?addr, "Received a new connection");

    let mut state = ServerConnection::default();

    loop {
        let mut buf = [0; 1024];
        let read = conn
            .read(&mut buf)
            .await
            .wrap_err("reading from connection")?;
        if read == 0 {
            return Ok(());
        }

        if let Err(err) = state.recv_bytes(&buf[..read]) {
            match err {
                SshError::ClientError(err) => {
                    info!(?err, "disconnecting client after invalid operation");
                    return Ok(());
                }
                SshError::ServerError(err) => {
                    return Err(err);
                }
            }
        }

        while let Some(msg) = state.next_message_to_send() {
            conn.write_all(&msg.to_bytes_inefficient())
                .await
                .wrap_err("writing response")?;
        }
    }
}
