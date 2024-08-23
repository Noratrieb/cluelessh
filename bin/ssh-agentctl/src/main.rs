use std::{io::Write, path::PathBuf};

use clap::Parser;
use eyre::{bail, Context};
use sha2::Digest;
use ssh_agent_client::{IdentityAnswer, SocketAgentConnection};
use ssh_transport::{key::PublicKey, parse::Writer};

#[derive(clap::Parser, Debug)]
struct Args {
    #[command(subcommand)]
    command: Subcommand,
}

#[derive(clap::Subcommand, Debug)]
enum Subcommand {
    /// Add a new identity to the agent, SSH_AGENTC_ADD_IDENTITY
    AddIdentity {
        /// The path to the private key file
        identity: PathBuf,
    },
    /// Remove all identities from the agent, SSH_AGENTC_REMOVE_ALL_IDENTITIES
    RemoveAllIdentities,
    /// List all identities in the agent, SSH_AGENTC_REQUEST_IDENTITIES
    ListIdentities {
        #[arg(short, long = "key-id")]
        key_id: bool,
    },
    /// Sign a blob, SSH_AGENTC_SIGN_REQUEST
    Sign {
        /// The key-id of the key, obtained with list-identities --key-id
        #[arg(short, long)]
        key: Option<String>,
        /// The domain of the signature, for example 'file'
        #[arg(short, long)]
        namespace: String,
        file: PathBuf,
    },
    /// Temporarily lock the agent with a passphrase, SSH_AGENTC_LOCK
    Lock,
    /// Temporarily unlock a temporarily locked agent with a passphrase, SSH_AGENTC_UNLOCK
    Unlock,
    /// Query all available extension types SSH_AGENTC_EXTENSION/query
    ExtensionQuery,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let mut agent = ssh_agent_client::SocketAgentConnection::from_env().await?;

    match args.command {
        Subcommand::AddIdentity { identity } => {
            let file = std::fs::read(&identity)
                .wrap_err_with(|| format!("reading file {}", identity.display()))?;
            let _ = file;
            todo!("we need to parse and decrypt the key...")
        }
        Subcommand::RemoveAllIdentities => {
            agent.remove_all_identities().await?;
            println!("Removed all identities from the agent");
        }
        Subcommand::ListIdentities { key_id } => {
            list_ids(&mut agent, key_id).await?;
        }
        Subcommand::Sign {
            file,
            key,
            namespace,
        } => {
            if namespace.is_empty() {
                bail!("namespace must not be empty");
            }

            let file = std::fs::read(&file)
                .wrap_err_with(|| format!("reading file {}", file.display()))?;

            let ids = agent
                .list_identities()
                .await
                .wrap_err("listing identities")?;

            let key = match ids.len() {
                0 => {
                    bail!("no keys found");
                }
                1 => {
                    let id = &ids[0];
                    if let Some(key) = key {
                        if key_id(id) != key {
                            eprintln!("error: key {key} not found. pass a key-id found below:");
                            list_ids(&mut agent, true).await?;
                            eprintln!(
                                "note: there is only one key, passing the key-id is not required"
                            );
                            std::process::exit(1);
                        }
                    }
                    id
                }
                _ => {
                    let Some(key) = key else {
                        eprintln!("error: missing argument --key. pass the key-id found below:");
                        list_ids(&mut agent, true).await?;
                        std::process::exit(1);
                    };

                    let Some(id) = ids.iter().find(|item| key_id(item) == key) else {
                        eprintln!("error: key {key} not found. pass a key-id from below");
                        list_ids(&mut agent, true).await?;
                        std::process::exit(1);
                    };
                    id
                }
            };

            // <https://github.com/openssh/openssh-portable/blob/a76a6b85108e3032c8175611ecc5746e7131f876/PROTOCOL.sshsig>

            let mut sign_data = Writer::new();
            sign_data.raw(b"SSHSIG");
            sign_data.string(&namespace);
            sign_data.string([]);
            sign_data.string(b"sha512");
            sign_data.string(sha2::Sha512::digest(file));

            let signature = agent.sign(&key.key_blob, &sign_data.finish(), 0).await?;

            let mut sig = Writer::new();
            sig.raw(b"SSHSIG");
            sig.u32(1); // version
            sig.string(&key.key_blob); // publickey
            sig.string(namespace.as_bytes());
            sig.string(b""); // reserved
            sig.string(b"sha512"); // hash algorithm
            sig.string(&signature);

            let signature = pem::encode(&pem::Pem::new("SSH SIGNATURE", sig.finish()));
            std::io::stdout().write_all(signature.as_bytes())?;
        }
        Subcommand::Lock => {
            let passphrase =
                tokio::task::spawn_blocking(|| rpassword::prompt_password("passphrase: "))
                    .await?
                    .wrap_err("failed to prompt passphrase")?;
            agent.lock(&passphrase).await?;
            println!("Locked SSH agent");
        }
        Subcommand::Unlock => {
            let passphrase =
                tokio::task::spawn_blocking(|| rpassword::prompt_password("passphrase: "))
                    .await?
                    .wrap_err("failed to prompt passphrase")?;
            agent.unlock(&passphrase).await?;
            println!("Unlocked SSH agent");
        }
        Subcommand::ExtensionQuery => {
            let extensions = agent.extension_query().await?;
            for ext in extensions {
                println!("{ext}");
            }
        }
    }

    Ok(())
}

async fn list_ids(agent: &mut SocketAgentConnection, print_key_id: bool) -> eyre::Result<()> {
    let ids = agent.list_identities().await?;
    for id in ids {
        print_key(id, print_key_id);
    }
    Ok(())
}

fn print_key(id: IdentityAnswer, show_key_id: bool) {
    let key = PublicKey::from_wire_encoding(&id.key_blob);
    match key {
        Ok(key) => {
            if show_key_id {
                print!("{} ", key_id(&id));
            }
            println!("{key} {}", id.comment);
        }
        Err(key) => {
            eprintln!("{key}");
            println!("<unknown> {}", id.comment);
        }
    }
}

fn key_id(key: &IdentityAnswer) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(&key.key_blob);
    hex::encode(&digest[..4])
}
