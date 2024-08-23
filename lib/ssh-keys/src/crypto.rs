use std::str::FromStr;

use aes::cipher::{KeySizeUser, StreamCipher};
use ssh_transport::parse::{self, Parser, Writer};

use crate::PrivateKeyType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cipher {
    None,
    Aes256Ctr,
}

impl FromStr for Cipher {
    type Err = parse::ParseError;

    fn from_str(ciphername: &str) -> Result<Self, Self::Err> {
        let cipher = match ciphername {
            "none" => Cipher::None,
            "aes256-ctr" => Cipher::Aes256Ctr,
            _ => {
                return Err(parse::ParseError(format!(
                    "unsupported cipher: {ciphername}"
                )));
            }
        };
        Ok(cipher)
    }
}

impl Cipher {
    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Aes256Ctr => "aes256-ctr",
        }
    }

    pub(crate) fn key_iv_size(&self) -> (usize, usize) {
        match self {
            Cipher::None => (0, 0),
            Cipher::Aes256Ctr => (aes::Aes256::key_size(), 16),
        }
    }

    /// Decrypt or encrypt a buffer in place (the same operation due to stream ciphers).
    pub(crate) fn crypt_in_place(&self, data: &mut [u8], key: &[u8], iv: &[u8]) {
        match self {
            Cipher::None => unreachable!("cannot decrypt none cipher"),
            Cipher::Aes256Ctr => {
                type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
                let mut cipher =
                    <Aes256Ctr as aes::cipher::KeyIvInit>::new_from_slices(key, iv).unwrap();
                cipher.apply_keystream(data);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kdf {
    None,
    BCrypt { salt: [u8; 16], rounds: u32 },
}
impl Kdf {
    pub(crate) fn from_str_and_options(
        kdfname: &str,
        kdfoptions: &[u8],
    ) -> Result<Self, parse::ParseError> {
        let kdf = match kdfname {
            "none" => {
                if !kdfoptions.is_empty() {
                    return Err(parse::ParseError(format!(
                        "KDF options must be empty for none KDF"
                    )));
                }
                Kdf::None
            }
            "bcrypt" => {
                let mut opts = Parser::new(kdfoptions);
                let salt = opts.string()?;
                let rounds = opts.u32()?;
                Kdf::BCrypt {
                    salt: salt
                        .try_into()
                        .map_err(|_| parse::ParseError(format!("incorrect bcrypt salt len")))?,
                    rounds,
                }
            }
            _ => {
                return Err(parse::ParseError(format!("unsupported KDF: {kdfname}")));
            }
        };
        Ok(kdf)
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BCrypt { .. } => "bcrypt",
        }
    }

    pub fn options(&self) -> Vec<u8> {
        match self {
            Self::None => Vec::new(),
            Self::BCrypt { salt, rounds } => {
                let mut opts = Writer::new();
                opts.string(salt);
                opts.u32(*rounds);
                opts.finish()
            }
        }
    }

    pub(crate) fn derive(&self, passphrase: &str, output: &mut [u8]) -> parse::Result<()> {
        match self {
            Self::None => unreachable!("should not attempt to derive passphrase from none"),
            Self::BCrypt { salt, rounds } => {
                bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, *rounds, output).map_err(|err| {
                    parse::ParseError(format!("error when performing key derivation: {err}"))
                })
            }
        }
    }
}

pub enum KeyType {
    Ed25519,
}

pub struct KeyGenerationParams {
    pub key_type: KeyType,
}

pub(crate) fn generate_private_key(params: KeyGenerationParams) -> PrivateKeyType {
    match params.key_type {
        KeyType::Ed25519 => {
            let private_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

            PrivateKeyType::Ed25519 {
                public_key: private_key.verifying_key().to_bytes(),
                private_key: private_key.to_bytes(),
            }
        }
    }
}