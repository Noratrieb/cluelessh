//! Operations on SSH keys.

// <https://datatracker.ietf.org/doc/html/rfc4716> exists but is kinda weird

use std::fmt::Display;

use base64::Engine;
use tracing::debug;

use crate::parse::{self, ParseError, Parser, Writer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519 { public_key: [u8; 32] },
}

impl PublicKey {
    /// Parses an SSH public key from its wire encoding as specified in
    /// RFC4253, RFC5656, and RFC8709.
    pub fn from_wire_encoding(bytes: &[u8]) -> parse::Result<Self> {
        let mut p = Parser::new(bytes);
        let alg = p.utf8_string()?;

        let k = match alg {
            "ssh-ed25519" => {
                let len = p.u32()?;
                if len != 32 {
                    return Err(ParseError(format!("incorrect ed25519 len: {len}")));
                }
                let public_key = p.array::<32>()?;
                Self::Ed25519 { public_key }
            }
            _ => return Err(ParseError(format!("unsupported key type: {alg}"))),
        };
        Ok(k)
    }

    pub fn to_wire_encoding(&self) -> Vec<u8> {
        let mut p = Writer::new();
        match self {
            Self::Ed25519 { public_key } => {
                p.string(b"ssh-ed25519");
                p.string(public_key);
            }
        }
        p.finish()
    }

    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Ed25519 { .. } => "ssh-ed25519",
        }
    }

    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        match self {
            PublicKey::Ed25519 { public_key } => {
                let mut s = Parser::new(signature);
                let Ok(alg) = s.utf8_string() else {
                    return false;
                };
                if alg != "ssh-ed25519" {
                    return false;
                }
                let Ok(signature) = s.string() else {
                    return false;
                };

                let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
                    debug!("Invalid signature length");
                    return false;
                };
                let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
                    debug!("Invalid public key");
                    return false;
                };

                verifying_key.verify_strict(data, &signature).is_ok()
            }
        }
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 { .. } => {
                let encoded_pubkey = b64encode(&self.to_wire_encoding());
                write!(f, "ssh-ed25519 {encoded_pubkey}")
            }
        }
    }
}

fn b64encode(bytes: &[u8]) -> String {
    base64::prelude::BASE64_STANDARD_NO_PAD.encode(bytes)
}
