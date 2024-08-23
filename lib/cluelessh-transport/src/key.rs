//! Operations on SSH keys.

// <https://datatracker.ietf.org/doc/html/rfc4716> exists but is kinda weird

use std::fmt::Display;

use base64::Engine;

use crate::parse::{self, ParseError, Parser, Writer};

#[derive(Debug, Clone)]
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
