use std::{
    fmt::Display,
    io::Write,
    path::{Path, PathBuf},
};

use base64::Engine;
use clap::Parser;
use cluelessh_keys::{
    private::{EncryptedPrivateKeys, KeyEncryptionParams, PlaintextPrivateKey, PrivateKey},
    public::{PublicKey, PublicKeyWithComment},
};
use eyre::{bail, Context};

#[derive(clap::Parser)]
struct Args {
    #[command(subcommand)]
    cmd: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    /// Get information about an SSH key
    Info {
        /// Decrypt the key to get more information. Will not display private information unless --show-private is used
        #[arg(short, long)]
        decrypt: bool,
        /// Show the private key. WARNING: This will display the private key
        #[arg(long)]
        show_private: bool,
        id_file: PathBuf,
    },
    /// Generate a new SSH key
    Generate {
        #[arg(short, long = "type", default_value_t = KeyType::Ed25519)]
        type_: KeyType,
        #[arg(short, long, default_value_t = String::default())]
        comment: String,
        #[arg(short, long)]
        path: PathBuf,
    },
    /// Commands for debugging SSH keys
    Debug {
        #[command(subcommand)]
        cmd: DebugCommand,
    },
}

#[derive(clap::Subcommand)]
enum DebugCommand {
    /// Strips PEM armor
    Unpem { id_file: PathBuf },
    /// Extract the encrypted part of the private key
    ExtractEncrypted { id_file: PathBuf },
    /// Create a fake private key that contains random private key bytes and the actual public key bytes.
    CreateFakePrivkey { public_key: PathBuf },
}

#[derive(clap::ValueEnum, Clone)]
enum KeyType {
    Ed25519,
    Ecdsa,
}

impl Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 => f.write_str("ed25519"),
            Self::Ecdsa => f.write_str("ecdsa"),
        }
    }
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();

    match args.cmd {
        Subcommand::Debug {
            cmd: DebugCommand::Unpem { id_file },
        } => {
            let file = std::fs::read(&id_file)
                .wrap_err_with(|| format!("reading file {}", id_file.display()))?;
            let raw = pem::parse(&file)?;
            std::io::stdout().lock().write_all(raw.contents())?;
            Ok(())
        }
        Subcommand::Debug {
            cmd: DebugCommand::ExtractEncrypted { id_file },
        } => {
            let file = std::fs::read(&id_file)
                .wrap_err_with(|| format!("reading file {}", id_file.display()))?;
            let keys = EncryptedPrivateKeys::parse(&file)?;
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
        Subcommand::Debug {
            cmd: DebugCommand::CreateFakePrivkey { public_key },
        } => {
            let file = std::fs::read_to_string(&public_key)
                .wrap_err_with(|| format!("reading file {}", public_key.display()))?;
            let public_key = file
                .parse::<PublicKeyWithComment>()
                .wrap_err("failed to parse public key")?;

            let mut fake_private_key = PlaintextPrivateKey::generate(
                "".into(),
                cluelessh_keys::KeyGenerationParams {
                    key_type: match public_key.key {
                        PublicKey::Ed25519 { .. } => cluelessh_keys::KeyType::Ed25519,
                        PublicKey::EcdsaSha2NistP256 { .. } => cluelessh_keys::KeyType::Ecdsa,
                    },
                },
            );

            match public_key.key {
                PublicKey::Ed25519 { public_key } => {
                    let PrivateKey::Ed25519 {
                        public_key: fake_public_key,
                        ..
                    } = &mut fake_private_key.private_key
                    else {
                        panic!()
                    };
                    *fake_public_key = public_key;
                }
                PublicKey::EcdsaSha2NistP256 { public_key } => {
                    let PrivateKey::EcdsaSha2NistP256 {
                        public_key: fake_public_key,
                        ..
                    } = &mut fake_private_key.private_key
                    else {
                        panic!()
                    };
                    *fake_public_key = public_key;
                }
            }

            let fake_private_key = fake_private_key.encrypt(KeyEncryptionParams::plaintext())?;

            println!("{}", fake_private_key.to_bytes_armored());
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
        std::fs::read(id_file).wrap_err_with(|| format!("reading file {}", id_file.display()))?;

    let keys = EncryptedPrivateKeys::parse(&file)?;

    if decrypt {
        let passphrase = if keys.requires_passphrase() {
            let phrase = rpassword::prompt_password("passphrase: ")?;
            Some(phrase)
        } else {
            None
        };

        let keys = keys.decrypt(passphrase.as_deref())?;
        for key in keys {
            println!("{} {}", key.private_key.public_key(), key.comment);
            if show_private {
                match key.private_key {
                    PrivateKey::Ed25519 { private_key, .. } => {
                        println!(
                            "  private key: {}",
                            base64::prelude::BASE64_STANDARD.encode(private_key.as_bytes())
                        )
                    }
                    PrivateKey::EcdsaSha2NistP256 { private_key, .. } => {
                        println!(
                            "  private key: {}",
                            base64::prelude::BASE64_STANDARD.encode(private_key.to_bytes())
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
        KeyType::Ed25519 => cluelessh_keys::KeyType::Ed25519,
        KeyType::Ecdsa => cluelessh_keys::KeyType::Ecdsa,
    };

    let passphrase = rpassword::prompt_password("Enter passphrase (empty for no passphrase): ")?;

    let key = PlaintextPrivateKey::generate(
        comment,
        cluelessh_keys::KeyGenerationParams { key_type: type_ },
    );

    println!("{} {}", key.private_key.public_key(), key.comment);

    let params = if passphrase.is_empty() {
        KeyEncryptionParams::plaintext()
    } else {
        KeyEncryptionParams::secure_encrypted(passphrase)
    };
    let keys = key.encrypt(params)?;

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
