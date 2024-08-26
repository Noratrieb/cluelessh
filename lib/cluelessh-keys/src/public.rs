//! Operations on SSH keys.

// <https://datatracker.ietf.org/doc/html/rfc4716> exists but is kinda weird

use std::fmt::Display;

use base64::Engine;
use ed25519_dalek::VerifyingKey;
use tracing::debug;

use cluelessh_format::{ParseError, Reader, Writer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519 {
        public_key: ed25519_dalek::VerifyingKey,
    },
    EcdsaSha2NistP256 {
        public_key: p256::ecdsa::VerifyingKey,
    },
}

impl PublicKey {
    /// Parses an SSH public key from its wire encoding as specified in
    /// RFC4253, RFC5656, and RFC8709.
    pub fn from_wire_encoding(bytes: &[u8]) -> cluelessh_format::Result<Self> {
        let mut p = Reader::new(bytes);
        let alg = p.utf8_string()?;

        let k = match alg {
            "ssh-ed25519" => {
                let len = p.u32()?;
                if len != 32 {
                    return Err(ParseError(format!("incorrect ed25519 len: {len}")));
                }
                let public_key = p.array::<32>()?;
                let public_key = VerifyingKey::from_bytes(&public_key)
                    .map_err(|_| ParseError(format!("invalid ed25519 public key")))?;
                Self::Ed25519 { public_key }
            }
            "ecdsa-sha2-nistp256" => {
                todo!()
            }
            _ => return Err(ParseError(format!("unsupported key type: {alg}"))),
        };
        Ok(k)
    }

    pub fn to_wire_encoding(&self) -> Vec<u8> {
        let mut p = Writer::new();
        p.string(self.algorithm_name());
        match self {
            Self::Ed25519 { public_key } => {
                p.string(public_key.as_bytes());
            }
            Self::EcdsaSha2NistP256 { public_key } => {
                // <https://datatracker.ietf.org/doc/html/rfc5656#section-3.1>
                p.string(b"nistp256");
                // > point compression MAY be used.
                // But OpenSSH does not appear to support that, so let's NOT use it.
                p.string(public_key.to_encoded_point(false).as_bytes());
            }
        }
        p.finish()
    }

    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Ed25519 { .. } => "ssh-ed25519",
            Self::EcdsaSha2NistP256 { .. } => "ecdsa-sha2-nistp256",
        }
    }

    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        match self {
            PublicKey::Ed25519 { public_key } => {
                let mut s = Reader::new(signature);
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

                public_key.verify_strict(data, &signature).is_ok()
            }
            PublicKey::EcdsaSha2NistP256 { .. } => {
                todo!("ecdsa-sha2-nistp256 signature verification")
            }
        }
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 { .. } => {
                let encoded_pubkey = b64encode(&self.to_wire_encoding());
                write!(f, "{} {encoded_pubkey}", self.algorithm_name())
            }
            Self::EcdsaSha2NistP256 { .. } => {
                let encoded_pubkey = b64encode(&self.to_wire_encoding());
                write!(f, "{} {encoded_pubkey}", self.algorithm_name())
            },
        }
    }
}

fn b64encode(bytes: &[u8]) -> String {
    base64::prelude::BASE64_STANDARD_NO_PAD.encode(bytes)
}
