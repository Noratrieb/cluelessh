use std::{collections::HashMap, net::SocketAddr};

use eyre::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info, info_span, Instrument};

use ssh_protocol::{
    connection::{ChannelOpen, ChannelOperationKind, ChannelRequestKind},
    transport::{self, ThreadRngRand},
    ChannelUpdateKind, ServerConnection, SshStatus,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let addr = std::env::var("FAKESSH_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:2222".to_owned());

    let addr = addr
        .parse::<SocketAddr>()
        .wrap_err_with(|| format!("failed to parse listen addr '{addr}'"))?;

    info!(?addr, "Starting server");

    let listener = TcpListener::bind(addr).await.wrap_err("binding listener")?;

    loop {
        let next = listener.accept().await?;
        let span = info_span!("connection", addr = ?next.1);
        tokio::spawn(
            async {
                let mut total_sent_data = Vec::new();

                if let Err(err) = handle_connection(next, &mut total_sent_data).await {
                    error!(?err, "error handling connection");
                }

                info!(data = ?String::from_utf8_lossy(&total_sent_data), "Finished connection");
            }
            .instrument(span),
        );
    }
}

async fn handle_connection(
    next: (TcpStream, SocketAddr),
    total_sent_data: &mut Vec<u8>,
) -> Result<()> {
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

    let mut state = ServerConnection::new(transport::ServerConnection::new(ThreadRngRand));

    let mut session_channels = HashMap::new();

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

        while let Some(update) = state.next_channel_update() {
            match update.kind {
                ChannelUpdateKind::Open(kind) => match kind {
                    ChannelOpen::Session => {
                        session_channels.insert(update.number, ());
                    }
                },
                ChannelUpdateKind::Request(req) => {
                    match req.kind {
                        ChannelRequestKind::PtyReq { .. } => {}
                        ChannelRequestKind::Shell => {}
                        ChannelRequestKind::Exec { .. } => {}
                    };
                    if req.want_reply {
                        state.do_operation(
                            update.number.construct_op(ChannelOperationKind::Success),
                        );
                    }
                }
                ChannelUpdateKind::Data { data } => {
                    let is_eof = data.contains(&0x03 /*EOF, Ctrl-C*/);

                    // echo :3
                    // state
                    //    .do_operation(update.number.construct_op(ChannelOperationKind::Data(data)));

                    // arbitrary limit
                    if total_sent_data.len() < 500_000 {
                        total_sent_data.extend_from_slice(&data);
                    }

                    if is_eof {
                        debug!(channel = ?update.number, "Received EOF, closing channel");

                        state.do_operation(update.number.construct_op(ChannelOperationKind::Close));
                    }
                }
                ChannelUpdateKind::ExtendedData { .. } | ChannelUpdateKind::Eof => { /* ignore */ }
                ChannelUpdateKind::Closed => {
                    session_channels.remove(&update.number);
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
