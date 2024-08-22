use std::io::Write;

use clap::Parser;

use eyre::Context;
use rand::RngCore;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, error, info};

use ssh_protocol::{
    transport::{self},
    SshStatus,
};
use tracing_subscriber::EnvFilter;

struct ThreadRngRand;
impl ssh_protocol::transport::SshRng for ThreadRngRand {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand::thread_rng().fill_bytes(dest);
    }
}

#[derive(clap::Parser, Debug)]
struct Args {
    #[arg(short = 'p', long, default_value_t = 22)]
    port: u16,
    destination: String,
    command: Vec<String>,
}

enum Operation {
    PasswordEntered(std::io::Result<String>),
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let mut conn = TcpStream::connect(&format!("{}:{}", args.destination, args.port))
        .await
        .wrap_err("connecting")?;

    let username = "hans-peter";

    let mut state = ssh_protocol::ClientConnection::new(
        transport::client::ClientConnection::new(ThreadRngRand),
        ssh_protocol::auth::ClientAuth::new(username.as_bytes().to_vec()),
    );

    let (send_op, mut recv_op) = tokio::sync::mpsc::channel::<Operation>(10);

    let mut buf = [0; 1024];

    loop {
        while let Some(msg) = state.next_msg_to_send() {
            conn.write_all(&msg.to_bytes())
                .await
                .wrap_err("writing response")?;
        }

        if let Some(auth) = state.auth() {
            for req in auth.user_requests() {
                match req {
                    ssh_protocol::auth::ClientUserRequest::Password => {
                        let username = username.to_owned();
                        let destination = args.destination.clone();
                        let send_op = send_op.clone();
                        std::thread::spawn(move || {
                            let password = rpassword::prompt_password(format!(
                                "{}@{}'s password: ",
                                username, destination
                            ));
                            let _ = send_op.blocking_send(Operation::PasswordEntered(password));
                        });
                    }
                    ssh_protocol::auth::ClientUserRequest::PrivateKeySign {
                        session_identifier: _,
                    } => {
                        // TODO: move
                        let mut agent = ssh_agent_client::SocketAgentConnection::from_env()
                            .await
                            .wrap_err("failed to connect to SSH agent")?;
                        let identities = agent.list_identities().await?;
                        for identity in identities {
                            debug!(comment = ?identity.comment, "Found identity");
                        }
                    }
                    ssh_protocol::auth::ClientUserRequest::Banner(banner) => {
                        let banner = String::from_utf8_lossy(&banner);
                        std::io::stdout().write(&banner.as_bytes())?;
                    }
                }
            }
        }

        tokio::select! {
            read = conn.read(&mut buf) => {
                let read = read.wrap_err("reading from connection")?;
                if read == 0 {
                    info!("Did not read any bytes from TCP stream, EOF");
                    return Ok(());
                }
                if let Err(err) = state.recv_bytes(&buf[..read]) {
                    match err {
                        SshStatus::PeerError(err) => {
                            error!(?err, "disconnecting client after invalid operation");
                            return Ok(());
                        }
                        SshStatus::Disconnect => {
                            error!("Received disconnect from server");
                            return Ok(());
                        }
                    }
                }
            }
            op = recv_op.recv() => {
                match op {
                    Some(Operation::PasswordEntered(password)) => {
                        if let Some(auth) = state.auth() {
                            auth.send_password(&password?);
                        } else {
                            debug!("Ignoring entered password as the state has moved on");
                        }
                    }
                    None => {}
                }
                state.progress();
            }
        }
    }
}
