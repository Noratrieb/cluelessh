use std::str::FromStr;

use aes::cipher::{KeySizeUser, StreamCipher};
use ssh_transport::parse::{self, Parser};

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
    pub(crate) fn key_iv_size(&self) -> (usize, usize) {
        match self {
            Cipher::None => (0, 0),
            Cipher::Aes256Ctr => (aes::Aes256::key_size(), 16),
        }
    }

    pub(crate) fn decrypt_in_place(&self, data: &mut [u8], key: &[u8], iv: &[u8]) {
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
