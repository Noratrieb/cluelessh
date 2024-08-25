use std::{collections::HashSet, sync::Arc};

use clap::Parser;

use eyre::{bail, Context, ContextCompat, OptionExt, Result};
use cluelessh_tokio::client::{PendingChannel, SignatureResult};
use cluelessh_transport::{key::PublicKey, numbers, parse::Writer};
use tokio::net::TcpStream;
use tracing::{debug, error};

use cluelessh_protocol::connection::{ChannelKind, ChannelOperationKind, ChannelRequest};
use tracing_subscriber::EnvFilter;

#[derive(clap::Parser, Debug)]
struct Args {
    #[arg(short = 'p', long, default_value_t = 22)]
    port: u16,
    #[arg(short, long)]
    user: Option<String>,
    destination: String,
    command: Vec<String>,
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

    let conn = TcpStream::connect(&format!("{}:{}", args.destination, args.port))
        .await
        .wrap_err("connecting")?;

    let username1 = username.clone();
    let mut tokio_conn = cluelessh_tokio::client::ClientConnection::connect(
        conn,
        cluelessh_tokio::client::ClientAuth {
            username: username.clone(),
            prompt_password: Arc::new(move || {
                let username = username1.clone();
                let destination = args.destination.clone();
                Box::pin(async {
                    let result = tokio::task::spawn_blocking(move || {
                        rpassword::prompt_password(format!(
                            "{}@{}'s password: ",
                            username, destination
                        ))
                    })
                    .await?;
                    result.wrap_err("failed to prompt password")
                })
            }),
            sign_pubkey: Arc::new(move |session_identifier| {
                let session_identifier = session_identifier.to_vec();
                let mut attempted_public_keys = HashSet::new();
                let username = username.clone();
                Box::pin(async move {
                    // TODO: support agentless manual key opening
                    // TODO: move
                    let mut agent = cluelessh_agent_client::SocketAgentConnection::from_env()
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
                    if !attempted_public_keys.insert(identity.key_blob.clone()) {
                        bail!("authentication denied (publickey)");
                    }
                    let pubkey = PublicKey::from_wire_encoding(&identity.key_blob)?;

                    let mut sign_data = Writer::new();
                    sign_data.string(session_identifier);
                    sign_data.u8(numbers::SSH_MSG_USERAUTH_REQUEST);
                    sign_data.string(&username);
                    sign_data.string("ssh-connection");
                    sign_data.string("publickey");
                    sign_data.bool(true);
                    sign_data.string(pubkey.algorithm_name());
                    sign_data.string(&identity.key_blob);

                    let data = sign_data.finish();
                    let signature = agent
                        .sign(&identity.key_blob, &data, 0)
                        .await
                        .wrap_err("signing for authentication")?;

                    Ok(SignatureResult {
                        key_alg_name: pubkey.algorithm_name(),
                        public_key: identity.key_blob.clone(),
                        signature,
                    })
                })
            }),
        },
    )
    .await?;

    let session = tokio_conn.open_channel(ChannelKind::Session);

    tokio::spawn(async {
        let result = main_channel(session).await;
        if let Err(err) = result {
            error!(?err);
        }
    });

    loop {
        tokio_conn.progress().await?;
    }
}

async fn main_channel(channel: PendingChannel) -> Result<()> {
    let Ok(mut channel) = channel.wait_ready().await else {
        bail!("failed to create channel");
    };

    channel
        .send_operation(ChannelOperationKind::Request(ChannelRequest::PtyReq {
            want_reply: true,
            term: "xterm-256color".to_owned(),
            width_chars: 70,
            height_rows: 10,
            width_px: 0,
            height_px: 0,
            term_modes: vec![],
        }))
        .await?;

    Ok(())
}
