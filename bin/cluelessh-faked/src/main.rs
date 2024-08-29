mod readline;

use std::{net::SocketAddr, sync::Arc};

use cluelessh_keys::private::EncryptedPrivateKeys;
use cluelessh_tokio::{server::ServerAuth, Channel};
use eyre::{eyre, Context, OptionExt, Result};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tracing::{debug, error, info, info_span, warn, Instrument};

use cluelessh_protocol::{
    connection::{ChannelKind, ChannelOperationKind, ChannelRequest},
    ChannelUpdateKind, SshStatus,
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

    let host_keys = vec![
        EncryptedPrivateKeys::parse(ED25519_PRIVKEY.as_bytes())
            .unwrap()
            .decrypt(None)
            .unwrap()
            .remove(0),
        EncryptedPrivateKeys::parse(ECDSA_PRIVKEY.as_bytes())
            .unwrap()
            .decrypt(None)
            .unwrap()
            .remove(0),
    ];

    let pub_host_keys = host_keys
        .iter()
        .map(|key| key.private_key.public_key())
        .collect::<Vec<_>>();

    let auth_verify = ServerAuth {
        verify_password: Some(Arc::new(|auth| {
            Box::pin(async move {
                info!(password = %auth.password, "Got password");

                // Don't worry queen, your password is correct!
                Ok(true)
            })
        })),
        check_pubkey: None,
        verify_signature: None,
        auth_banner: Some(
            "\
            !! this system ONLY allows catgirls to enter !!\r\n\
            !! all other attempts WILL be prosecuted to the full extent of the rawr !!\r\n\
            !! THIS SYTEM WILL LOG AND STORE YOUR CLEARTEXT PASSWORD !!\r\n\
            !! DO NOT ENTER PASSWORDS YOU DON'T WANT STOLEN !!\r\n"
                .to_owned(),
        ),
        do_key_exchange: Arc::new(move |msg| {
            let host_keys = host_keys.clone();
            Box::pin(async move {
                let private = host_keys
                    .iter()
                    .find(|privkey| {
                        privkey.private_key.public_key()
                            == msg.server_host_key_algorithm.public_key()
                    })
                    .ok_or_eyre("missing private key")?;

                // TODO: non-shitty error handling here

                cluelessh_protocol::transport::server::do_key_exchange(
                    msg,
                    private,
                    &mut cluelessh_protocol::OsRng,
                )
                .map_err(|_| eyre!("error during key exchange"))
            })
        }),
    };

    let transport_config = cluelessh_protocol::transport::server::ServerConfig {
        host_keys: pub_host_keys,
        // This is definitely who we are.
        server_identification: b"SSH-2.0-OpenSSH_9.7\r\n".to_vec(),
    };

    let mut listener =
        cluelessh_tokio::server::ServerListener::new(listener, auth_verify, transport_config);

    loop {
        let next = listener.accept().await?;
        let span = info_span!("connection", addr = %next.peer_addr());
        tokio::spawn(
            async move {
                let total_sent_data = Arc::new(Mutex::new(Vec::new()));

                if let Err(err) = handle_connection(next, total_sent_data.clone()).await {
                    if let Some(err) = err.downcast_ref::<std::io::Error>() {
                        if err.kind() == std::io::ErrorKind::ConnectionReset {
                            return;
                        }
                    }

                    error!(?err, "error handling connection");
                }

                // Limit stdin to 500 characters.
                let total_sent_data = total_sent_data.lock().await;
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
    mut conn: cluelessh_tokio::server::ServerConnection<TcpStream>,
    total_sent_data: Arc<Mutex<Vec<u8>>>,
) -> Result<()> {
    info!(addr = %conn.peer_addr(), "Received a new connection");

    loop {
        match conn.progress().await {
            Ok(()) => {}
            Err(cluelessh_tokio::server::Error::ServerError(err)) => {
                return Err(err);
            }
            Err(cluelessh_tokio::server::Error::SshStatus(status)) => match status {
                SshStatus::PeerError(err) => {
                    info!(?err, "disconnecting client after invalid operation");
                    return Ok(());
                }
                SshStatus::Disconnect => {
                    info!("Received disconnect from client");
                    return Ok(());
                }
            },
        }

        while let Some(channel) = conn.next_new_channel() {
            if *channel.kind() == ChannelKind::Session {
                let total_sent_data = total_sent_data.clone();
                tokio::spawn(async {
                    let _ = handle_session_channel(channel, total_sent_data).await;
                });
            } else {
                warn!("Trying to open non-session channel");
            }
        }
    }
}

async fn handle_session_channel(
    mut channel: Channel,
    total_sent_data: Arc<Mutex<Vec<u8>>>,
) -> Result<()> {
    let mut readline = None;

    loop {
        match channel.next_update().await {
            Ok(update) => match update {
                ChannelUpdateKind::Request(req) => {
                    let success = ChannelOperationKind::Success;
                    match req {
                        ChannelRequest::PtyReq { want_reply, .. } => {
                            let mut new_readline = readline::InteractiveShell::new();
                            let to_write = new_readline.bytes_to_write();
                            if !to_write.is_empty() {
                                channel.send(ChannelOperationKind::Data(to_write)).await?;
                            }
                            readline = Some(new_readline);

                            if want_reply {
                                channel.send(success).await?;
                            }
                        }
                        ChannelRequest::Shell { want_reply } => {
                            if want_reply {
                                channel.send(success).await?;
                            }
                        }
                        ChannelRequest::Exec {
                            want_reply,
                            command,
                        } => {
                            if want_reply {
                                channel.send(success).await?;
                            }

                            let result = execute_command(&command);
                            if !result.stdout.is_empty() {
                                channel
                                    .send(ChannelOperationKind::Data(result.stdout))
                                    .await?;
                            }
                            channel
                                .send(ChannelOperationKind::Request(ChannelRequest::ExitStatus {
                                    status: result.status,
                                }))
                                .await?;
                            channel.send(ChannelOperationKind::Eof).await?;
                            channel.send(ChannelOperationKind::Close).await?;
                        }
                        ChannelRequest::ExitStatus { .. } => {}
                        ChannelRequest::Env { .. } => {}
                    };
                }
                ChannelUpdateKind::OpenFailed { .. } => todo!(),
                ChannelUpdateKind::Data { data } => {
                    // Store sent data
                    let mut total_sent_data = total_sent_data.lock().await;
                    // arbitrary limit
                    if total_sent_data.len() < 50_000 {
                        total_sent_data.extend_from_slice(&data);
                    } else {
                        info!("Reached stdin limit");
                        channel
                            .send(ChannelOperationKind::Data(b"Thanks Hayley!\n".to_vec()))
                            .await?;
                        channel.send(ChannelOperationKind::Close).await?;
                    }

                    if let Some(readline) = &mut readline {
                        readline.recv_bytes(&data);
                        let to_write = readline.bytes_to_write();
                        if !to_write.is_empty() {
                            // TODO: introduce helper to Channel that allows writing 0 data
                            channel.send(ChannelOperationKind::Data(to_write)).await?;
                        }

                        if readline.should_exit() {
                            debug!("Received Ctrl-D, closing channel");

                            channel.send(ChannelOperationKind::Eof).await?;
                            channel.send(ChannelOperationKind::Close).await?;
                        }
                    } else {
                        // bad fallback behavior
                        let is_eof = data.contains(&0x04 /*EOF, Ctrl-D*/);

                        // echo :3
                        channel
                            .send(ChannelOperationKind::Data(data.clone()))
                            .await?;

                        if is_eof {
                            debug!("Received Ctrl-D, closing channel");

                            channel.send(ChannelOperationKind::Eof).await?;
                            channel.send(ChannelOperationKind::Close).await?;
                        }
                    }
                }
                ChannelUpdateKind::Open(_)
                | ChannelUpdateKind::Closed
                | ChannelUpdateKind::ExtendedData { .. }
                | ChannelUpdateKind::Eof
                | ChannelUpdateKind::Success
                | ChannelUpdateKind::Failure => { /* ignore */ }
            },
            Err(err) => return Err(err),
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

    // Some hardcoded commands
    match command.trim() {
        "uname -s -v -n -r -m" => {
            return ProcessOutput {
                status: 0,
                stdout: UNAME_SVNRM.to_vec(),
            }
        }
        "uname -a" => {
            return ProcessOutput {
                status: 0,
                stdout: UNAME_A.to_vec(),
            }
        }
        "cat /proc/cpuinfo|grep name|cut -f2 -d':'|uniq -c ; uname -a" => {
            return ProcessOutput {
                status: 0,
                stdout: CPUINFO_UNAME_A.to_vec(),
            }
        }
        _ => {}
    }

    // Now, lex the string and do this nicely
    let Some(parts) = shlex::split(command) else {
        return ProcessOutput {
            status: 1,
            stdout: b"bash: invalid input\r\n".to_vec(),
        };
    };

    let Some(argv0) = parts.first() else {
        return ProcessOutput {
            status: 1,
            stdout: b"bash: invalid input\r\n".to_vec(),
        };
    };

    match argv0.as_str().trim() {
        "true" => ProcessOutput {
            status: 0,
            stdout: b"".to_vec(),
        },
        "cd" => ProcessOutput {
            status: 0,
            stdout: b"".to_vec(),
        },
        "ls" => ProcessOutput {
            status: 0,
            stdout: b"hpasswd index.php secrets.php\r\n".to_vec(),
        },
        "whoami" => ProcessOutput {
            status: 0,
            stdout: b"root\r\n".to_vec(),
        },
        "id" => ProcessOutput {
            status: 0,
            stdout: b"uid=0(root) gid=0(root) groups=0(root)\r\n".to_vec(),
        },
        _ => ProcessOutput {
            status: 127,
            stdout: format!("bash: line 1: {argv0}: command not found\r\n").into_bytes(),
        },
    }
}

const ED25519_PRIVKEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDpOc36b8DXNzM7U06RPdMyyNUXn+AMMEVXUhciSxm49gAAAJDpgLSk6YC0
pAAAAAtzc2gtZWQyNTUxOQAAACDpOc36b8DXNzM7U06RPdMyyNUXn+AMMEVXUhciSxm49g
AAAECSeskxuEtJrr9L7ZkbpogXC5pKRNVHx1ueMX2h1XUnmek5zfpvwNc3MztTTpE90zLI
1Ref4AwwRVdSFyJLGbj2AAAAB3Rlc3RrZXkBAgMEBQY=
-----END OPENSSH PRIVATE KEY-----
";

const ECDSA_PRIVKEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTAzIMf0R8+7KPHyaad2AYc5PivpuiV
Agf2THXdwHOXWoZz3pG/QBRGx+9n+ucIVT0lkWiMMwV86lSg/6w/DWNuAAAAqP8RaNj/EW
jYAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMDMgx/RHz7so8fJ
pp3YBhzk+K+m6JUCB/ZMdd3Ac5dahnPekb9AFEbH72f65whVPSWRaIwzBXzqVKD/rD8NY2
4AAAAhANOCLkd997DYpaix3I0BYDXDccdnRQ3SIMevrXTO2r+fAAAACm5vcmFAbml4b3MB
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----
";
