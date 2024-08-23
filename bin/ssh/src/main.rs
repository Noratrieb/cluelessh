use std::{collections::HashSet, io::Write};

use clap::Parser;

use eyre::{bail, Context, ContextCompat, OptionExt};
use rand::RngCore;
use ssh_transport::{key::PublicKey, parse::Writer};
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
    #[arg(short, long)]
    user: Option<String>,
    destination: String,
    command: Vec<String>,
}

enum Operation {
    PasswordEntered(std::io::Result<String>),
    Signature {
        key_alg_name: &'static str,
        public_key: Vec<u8>,
        signature: Vec<u8>,
    },
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let username = match args.user {
        None => {
            tokio::task::spawn_blocking(|| {
                users::get_current_username()
                    .wrap_err("getting username")
                    .and_then(|username| {
                        username
                            .to_str()
                            .ok_or_eyre("your username is invalid UTF-8???")
                            .map(ToOwned::to_owned)
                    })
            })
            .await??
        }
        Some(user) => user,
    };

    let mut attempted_public_keys = HashSet::new();

    let mut conn = TcpStream::connect(&format!("{}:{}", args.destination, args.port))
        .await
        .wrap_err("connecting")?;

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
                        let username = username.clone();
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
                        session_identifier,
                    } => {
                        // TODO: support agentless manual key opening
                        // TODO: move
                        let mut agent = ssh_agent_client::SocketAgentConnection::from_env()
                            .await
                            .wrap_err("failed to connect to SSH agent")?;
                        let identities = agent.list_identities().await?;
                        for identity in &identities {
                            let pubkey = PublicKey::from_wire_encoding(&identity.key_blob)
                                .wrap_err("received invalid public key from SSH agent")?;
                            debug!(comment = ?identity.comment, %pubkey, "Found identity");
                        }
                        if identities.len() > 1 {
                            todo!("try identities");
                        }
                        let identity = &identities[0];
                        if attempted_public_keys.insert(identity.key_blob.clone()) {
                            bail!("authentication denied (publickey)");
                        }
                        let pubkey = PublicKey::from_wire_encoding(&identity.key_blob)?;

                        let mut sig = Writer::new();
                        sig.string(session_identifier);
                        sig.string(&username);
                        sig.string("ssh-connection");
                        sig.string("publickey");
                        sig.bool(true);
                        sig.string(pubkey.algorithm_name());
                        sig.string(&identity.key_blob);

                        let data = sig.finish();
                        let signature = agent
                            .sign(&identity.key_blob, &data, 0)
                            .await
                            .wrap_err("signing for authentication")?;

                        send_op
                            .send(Operation::Signature {
                                key_alg_name: pubkey.algorithm_name(),
                                public_key: identity.key_blob.clone(),
                                signature,
                            })
                            .await?;
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
                    Some(Operation::Signature{
                        key_alg_name, public_key, signature,
                    }) => {
                        if let Some(auth) = state.auth() {
                            auth.send_signature(key_alg_name, &public_key, &signature);
                        } else {
                            debug!("Ignoring signature as the state has moved on");
                        }
                    }
                    None => {}
                }
                state.progress();
            }
        }
    }
}
