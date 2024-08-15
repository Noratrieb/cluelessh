use std::{collections::HashMap, net::SocketAddr};

use eyre::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info, info_span, Instrument};

use ssh_protocol::{
    connection::{ChannelOpen, ChannelOperationKind, ChannelRequest},
    transport::{self, ThreadRngRand},
    ChannelUpdateKind, ServerConnection, SshStatus,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if std::env::var("FAKESSH_JSON_LOGS").is_ok_and(|v| v != "0") {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    let addr = std::env::var("FAKESSH_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:2222".to_owned());

    let addr = addr
        .parse::<SocketAddr>()
        .wrap_err_with(|| format!("failed to parse listen addr '{addr}'"))?;

    info!(%addr, "Starting server");

    let listener = TcpListener::bind(addr).await.wrap_err("binding listener")?;

    loop {
        let next = listener.accept().await?;
        let span = info_span!("connection", addr = %next.1);
        tokio::spawn(
            async {
                let mut total_sent_data = Vec::new();

                if let Err(err) = handle_connection(next, &mut total_sent_data).await {
                    if let Some(err) = err.downcast_ref::<std::io::Error>() {
                        if err.kind() == std::io::ErrorKind::ConnectionReset {
                            return;
                        }
                    }

                    error!(?err, "error handling connection");
                }

                // Limit stdin to 500 characters.
                let stdin = String::from_utf8_lossy(&total_sent_data);
                let stdin = if let Some((idx, _)) = stdin.char_indices().nth(500) {
                    &stdin[..idx]
                } else {
                    &stdin
                };

                info!(?stdin, "Finished connection");
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

    info!(%addr, "Received a new connection");

    /*let rng = vec![
        0x14, 0xa2, 0x04, 0xa5, 0x4b, 0x2f, 0x5f, 0xa7, 0xff, 0x53, 0x13, 0x67, 0x57, 0x67, 0xbc,
        0x55, 0x3f, 0xc0, 0x6c, 0x0d, 0x07, 0x8f, 0xe2, 0x75, 0x95, 0x18, 0x4b, 0xd2, 0xcb, 0xd0,
        0x64, 0x06, 0x14, 0xa2, 0x04, 0xa5, 0x4b, 0x2f, 0x5f, 0xa7, 0xff, 0x53, 0x13, 0x67, 0x57,
        0x67, 0xbc, 0x55, 0x3f, 0xc0, 0x6c, 0x0d, 0x07, 0x8f, 0xe2, 0x75, 0x95, 0x18, 0x4b, 0xd2,
        0xcb, 0xd0, 0x64, 0x06, 0x67, 0xbc, 0x55, 0x3f, 0xc0, 0x6c, 0x0d, 0x07, 0x8f, 0xe2, 0x75,
        0x95, 0x18, 0x4b, 0xd2, 0xcb, 0xd0, 0x64, 0x06,
    ];
    struct HardcodedRng(Vec<u8>);
    impl ssh_protocol::transport::SshRng for HardcodedRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.copy_from_slice(&self.0[..dest.len()]);
            self.0.splice(0..dest.len(), []);
        }
    }*/

    let mut state = ServerConnection::new(transport::ServerConnection::new(ThreadRngRand));

    let mut session_channels = HashMap::new();

    loop {
        let mut buf = [0; 1024];
        let read = conn
            .read(&mut buf)
            .await
            .wrap_err("reading from connection")?;
        if read == 0 {
            info!("Did not read any bytes from TCP stream, EOF");
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
                    info!("Received disconnect from client");
                    return Ok(());
                }
            }
        }

        while let Some(update) = state.next_channel_update() {
            //eprintln!("{:?}", update);
            match update.kind {
                ChannelUpdateKind::Open(kind) => match kind {
                    ChannelOpen::Session => {
                        session_channels.insert(update.number, ());
                    }
                },
                ChannelUpdateKind::Request(req) => {
                    let success = update.number.construct_op(ChannelOperationKind::Success);
                    match req {
                        ChannelRequest::PtyReq { want_reply, .. } => {
                            if want_reply {
                                state.do_operation(success);
                            }
                        }
                        ChannelRequest::Shell { want_reply } => {
                            if want_reply {
                                state.do_operation(success);
                            }
                        }
                        ChannelRequest::Exec {
                            want_reply,
                            command,
                        } => {
                            if want_reply {
                                state.do_operation(success);
                            }

                            let result = execute_command(&command);
                            state.do_operation(
                                update
                                    .number
                                    .construct_op(ChannelOperationKind::Data(result.stdout)),
                            );
                            state.do_operation(update.number.construct_op(
                                ChannelOperationKind::Request(ChannelRequest::ExitStatus {
                                    status: result.status,
                                }),
                            ));
                            state.do_operation(
                                update.number.construct_op(ChannelOperationKind::Eof),
                            );
                            state.do_operation(
                                update.number.construct_op(ChannelOperationKind::Close),
                            );
                        }
                        ChannelRequest::ExitStatus { .. } => {}
                        ChannelRequest::Env { .. } => {}
                    };
                }
                ChannelUpdateKind::Data { data } => {
                    let is_eof = data.contains(&0x04 /*EOF, Ctrl-D*/);

                    // echo :3
                    state.do_operation(
                        update
                            .number
                            .construct_op(ChannelOperationKind::Data(data.clone())),
                    );

                    // arbitrary limit
                    if total_sent_data.len() < 50_000 {
                        total_sent_data.extend_from_slice(&data);
                    } else {
                        info!(channel = %update.number, "Reached stdin limit");
                        state.do_operation(
                            update.number.construct_op(ChannelOperationKind::Data(
                                b"Thanks Hayley!\n".to_vec(),
                            )),
                        );
                        state.do_operation(update.number.construct_op(ChannelOperationKind::Close));
                    }

                    if is_eof {
                        debug!(channel = %update.number, "Received Ctrl-D, closing channel");

                        state.do_operation(update.number.construct_op(ChannelOperationKind::Eof));
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

struct ProcessOutput {
    status: u32,
    stdout: Vec<u8>,
}

const UNAME_SVNRM: &[u8] =
    b"Linux ubuntu 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64\r\n";
const UNAME_A: &[u8] =
    b"Linux ubuntu 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\r\n";
const CPUINFO_UNAME_A: &[u8] = b"      4  AMD EPYC 7282 16-Core Processor\r\n\
Linux vps2 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\r\n";

fn execute_command(command: &[u8]) -> ProcessOutput {
    let Ok(command) = std::str::from_utf8(command) else {
        return ProcessOutput {
            status: 1,
            stdout: b"what the hell".to_vec(),
        };
    };
    match command {
        "uname -s -v -n -r -m" => ProcessOutput {
            status: 0,
            stdout: UNAME_SVNRM.to_vec(),
        },
        "uname -a" => ProcessOutput {
            status: 0,
            stdout: UNAME_A.to_vec(),
        },
        "cat /proc/cpuinfo|grep name|cut -f2 -d':'|uniq -c ; uname -a" => ProcessOutput {
            status: 0,
            stdout: CPUINFO_UNAME_A.to_vec(),
        },
        "true" => ProcessOutput {
            status: 0,
            stdout: b"".to_vec(),
        },
        _ => {
            let argv0 = command.split_ascii_whitespace().next().unwrap_or("");

            ProcessOutput {
                status: 127,
                stdout: format!("bash: line 1: {argv0}: command not found\r\n").into_bytes(),
            }
        }
    }
}
