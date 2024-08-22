use std::path::PathBuf;

use base64::Engine;
use clap::Parser;
use eyre::{bail, Context};
use ssh_keys::PrivateKeyType;

#[derive(clap::Parser)]
struct Args {
    #[command(subcommand)]
    command: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    Info {
        /// Decrypt the key to get more information. Will not display private information unless --show-private is used
        #[arg(short, long)]
        decrypt: bool,
        /// Show the private key. WARNING: This will display the private key
        #[arg(long)]
        show_private: bool,
        id_file: PathBuf,
    },
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();

    match args.command {
        Subcommand::Info {
            id_file,
            decrypt,
            show_private,
        } => {
            if show_private && !decrypt {
                bail!("cannot --show-private without --decrypt");
            }

            let file = std::fs::read(&id_file)
                .wrap_err_with(|| format!("reading file {}", id_file.display()))?;

            let keys = ssh_keys::EncryptedPrivateKeys::parse_unencrypted(&file)?;

            if decrypt {
                let passphrase = if keys.requires_passphrase() {
                    let phrase = rpassword::prompt_password("passphrase: ")?;
                    Some(phrase)
                } else {
                    None
                };

                let keys = keys.parse_private(passphrase.as_deref())?;
                for key in keys {
                    println!("{} {}", key.private_key.public_key(), key.comment);
                    if show_private {
                        match key.private_key {
                            PrivateKeyType::Ed25519 { private_key, .. } => {
                                println!(
                                    "  private key: {}",
                                    base64::prelude::BASE64_STANDARD_NO_PAD.encode(private_key)
                                )
                            }
                        }
                    }
                }
            } else {
                for key in keys.public_keys {
                    println!("{key}");
                }
            }
        }
    }

    Ok(())
}
