use std::{
    io::Write,
    path::{Path, PathBuf},
};

use base64::Engine;
use clap::Parser;
use eyre::{bail, Context};
use ssh_keys::{KeyEncryptionParams, PrivateKeyType};

#[derive(clap::Parser)]
struct Args {
    #[command(subcommand)]
    command: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    /// Strips PEM armor
    Unpem { id_file: PathBuf },
    /// Extract the encrypted part of the private key
    ExtractEncrypted { id_file: PathBuf },
    Info {
        /// Decrypt the key to get more information. Will not display private information unless --show-private is used
        #[arg(short, long)]
        decrypt: bool,
        /// Show the private key. WARNING: This will display the private key
        #[arg(long)]
        show_private: bool,
        id_file: PathBuf,
    },
    Generate {
        #[arg(short, long = "type")]
        type_: KeyType,
        #[arg(short, long)]
        comment: String,
        #[arg(short, long)]
        path: PathBuf,
    },
}

#[derive(clap::ValueEnum, Clone)]
enum KeyType {
    Ed25519,
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();

    match args.command {
        Subcommand::Unpem { id_file } => {
            let file = std::fs::read(&id_file)
                .wrap_err_with(|| format!("reading file {}", id_file.display()))?;
            let raw = pem::parse(&file)?;
            std::io::stdout().lock().write_all(raw.contents())?;
            Ok(())
        }
        Subcommand::ExtractEncrypted { id_file } => {
            let file = std::fs::read(&id_file)
                .wrap_err_with(|| format!("reading file {}", id_file.display()))?;
            let keys = ssh_keys::EncryptedPrivateKeys::parse(&file)?;
            let passphrase = if keys.requires_passphrase() {
                let phrase = rpassword::prompt_password("passphrase: ")?;
                Some(phrase)
            } else {
                None
            };

            let data = keys.decrypt_encrypted_part(passphrase.as_deref())?;
            std::io::stdout().lock().write_all(&data)?;
            Ok(())
        }
        Subcommand::Info {
            id_file,
            decrypt,
            show_private,
        } => info(&id_file, decrypt, show_private),
        Subcommand::Generate {
            type_,
            comment,
            path,
        } => generate(type_, comment, &path),
    }
}

fn info(id_file: &Path, decrypt: bool, show_private: bool) -> eyre::Result<()> {
    if show_private && !decrypt {
        bail!("cannot --show-private without --decrypt");
    }

    let file =
        std::fs::read(&id_file).wrap_err_with(|| format!("reading file {}", id_file.display()))?;

    let keys = ssh_keys::EncryptedPrivateKeys::parse(&file)?;

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
    Ok(())
}

fn generate(type_: KeyType, comment: String, path: &Path) -> eyre::Result<()> {
    let type_ = match type_ {
        KeyType::Ed25519 => ssh_keys::KeyType::Ed25519,
    };

    let passphrase = rpassword::prompt_password("Enter passphrase (empty for no passphrase): ")?;

    let key = ssh_keys::PlaintextPrivateKey::generate(
        comment,
        ssh_keys::KeyGenerationParams { key_type: type_ },
    );

    println!("{} {}", key.private_key.public_key(), key.comment);

    let keys = key.encrypt(KeyEncryptionParams::secure_or_none(passphrase))?;

    let mut pubkey_path = path.to_path_buf().into_os_string();
    pubkey_path.push(".pub");
    std::fs::write(
        &pubkey_path,
        format!("{} {}\n", key.private_key.public_key(), key.comment),
    )
    .wrap_err_with(|| format!("writing to {:?}", pubkey_path))?;

    let privkey = keys.to_bytes_armored();

    std::fs::write(path, privkey).wrap_err_with(|| format!("writing to {}", path.display()))?;

    Ok(())
}