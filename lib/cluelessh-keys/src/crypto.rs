use std::str::FromStr;

use aes::cipher::{KeySizeUser, StreamCipher};
use cluelessh_format::{Reader, Writer};

use crate::private::PrivateKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cipher {
    None,
    Aes256Ctr,
}

impl FromStr for Cipher {
    type Err = cluelessh_format::ParseError;

    fn from_str(ciphername: &str) -> Result<Self, Self::Err> {
        let cipher = match ciphername {
            "none" => Cipher::None,
            "aes256-ctr" => Cipher::Aes256Ctr,
            _ => {
                return Err(cluelessh_format::ParseError(format!(
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

    pub(crate) fn block_size(&self) -> usize {
        // this is the "minimum" block size in core SSH, so I assume it's here as well?
        match self {
            Self::None => 8,
            Self::Aes256Ctr => 16, // looks like it takes the AES block size, even if AES-CTR isn't really a block cipher..
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
    ) -> Result<Self, cluelessh_format::ParseError> {
        let kdf = match kdfname {
            "none" => {
                if !kdfoptions.is_empty() {
                    return Err(cluelessh_format::ParseError(format!(
                        "KDF options must be empty for none KDF"
                    )));
                }
                Kdf::None
            }
            "bcrypt" => {
                let mut opts = Reader::new(kdfoptions);
                let salt = opts.string()?;
                let rounds = opts.u32()?;
                Kdf::BCrypt {
                    salt: salt.try_into().map_err(|_| {
                        cluelessh_format::ParseError(format!("incorrect bcrypt salt len"))
                    })?,
                    rounds,
                }
            }
            _ => {
                return Err(cluelessh_format::ParseError(format!(
                    "unsupported KDF: {kdfname}"
                )));
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

    pub(crate) fn derive(
        &self,
        passphrase: &str,
        output: &mut [u8],
    ) -> cluelessh_format::Result<()> {
        match self {
            Self::None => unreachable!("should not attempt to derive passphrase from none"),
            Self::BCrypt { salt, rounds } => {
                bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, *rounds, output).map_err(|err| {
                    cluelessh_format::ParseError(format!(
                        "error when performing key derivation: {err}"
                    ))
                })
            }
        }
    }
}

pub enum KeyType {
    Ed25519,
    Ecdsa,
}

pub struct KeyGenerationParams {
    pub key_type: KeyType,
}

pub(crate) fn generate_private_key(params: KeyGenerationParams) -> PrivateKey {
    match params.key_type {
        KeyType::Ed25519 => {
            let private_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

            PrivateKey::Ed25519 {
                public_key: private_key.verifying_key(),
                private_key,
            }
        }
        KeyType::Ecdsa => {
            let private_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);

            PrivateKey::EcdsaSha2NistP256 {
                public_key: *private_key.verifying_key(),
                private_key,
            }
        }
    }
}
