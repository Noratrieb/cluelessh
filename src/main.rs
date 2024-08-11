use std::net::SocketAddr;

use eyre::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{error, info};

use ssh_transport::{ServerConnection, SshStatus, ThreadRngRand};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let addr = "0.0.0.0:2222".parse::<SocketAddr>().unwrap();

    info!(?addr, "Starting server");

    let listener = TcpListener::bind(addr).await.wrap_err("binding listener")?;

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

    //let rng = vec![
    //    0x14, 0xa2, 0x04, 0xa5, 0x4b, 0x2f, 0x5f, 0xa7, 0xff, 0x53, 0x13, 0x67, 0x57, 0x67, 0xbc,
    //    0x55, 0x3f, 0xc0, 0x6c, 0x0d, 0x07, 0x8f, 0xe2, 0x75, 0x95, 0x18, 0x4b, 0xd2, 0xcb, 0xd0,
    //    0x64, 0x06,
    //];
    //struct HardcodedRng(Vec<u8>);
    //impl ssh_transport::SshRng for HardcodedRng {
    //    fn fill_bytes(&mut self, dest: &mut [u8]) {
    //        dest.copy_from_slice(&self.0[..dest.len()]);
    //        self.0.splice(0..dest.len(), []);
    //    }
    //}

    let mut state = ServerConnection::new(ThreadRngRand);

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
                SshStatus::ClientError(err) => {
                    info!(?err, "disconnecting client after invalid operation");
                    return Ok(());
                }
                SshStatus::ServerError(err) => {
                    return Err(err);
                }
                SshStatus::Disconnect => {
                    return Ok(());
                }
            }
        }

        while let Some(msg) = state.next_msg_to_send() {
            conn.write_all(&msg.to_bytes())
                .await
                .wrap_err("writing response")?;
        }
    }
}
