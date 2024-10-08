//! Operations on SSH keys.

// <https://datatracker.ietf.org/doc/html/rfc4716> exists but is kinda weird

use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

use base64::Engine;

use cluelessh_format::{ParseError, Reader, Writer};

use crate::signature::Signature;

#[derive(Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519 {
        public_key: ed25519_dalek::VerifyingKey,
    },
    EcdsaSha2NistP256 {
        public_key: p256::ecdsa::VerifyingKey,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct PublicKeyWithComment {
    pub key: PublicKey,
    pub comment: String,
}

impl FromStr for PublicKeyWithComment {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split_ascii_whitespace();
        let alg = parts
            .next()
            .ok_or_else(|| ParseError("missing algorithm on line".to_owned()))?;
        let key_blob = parts
            .next()
            .ok_or_else(|| ParseError("missing key on line".to_owned()))?;
        let key_blob = base64::prelude::BASE64_STANDARD
            .decode(key_blob)
            .map_err(|err| ParseError(format!("invalid base64 encoding for key: {err}")))?;
        let comment = parts.next().unwrap_or_default();

        let public_key = PublicKey::from_wire_encoding(&key_blob)
            .map_err(|err| ParseError(format!("unsupported key: {err}")))?;

        if public_key.algorithm_name() != alg {
            return Err(ParseError(format!(
                "algorithm name mismatch: {} != {}",
                public_key.algorithm_name(),
                alg
            )));
        }

        Ok(Self {
            key: public_key,
            comment: comment.to_owned(),
        })
    }
}

impl PublicKey {
    /// Parses an SSH public key from its wire encoding as specified in
    /// RFC4253, RFC5656, and RFC8709.
    pub fn from_wire_encoding(bytes: &[u8]) -> cluelessh_format::Result<Self> {
        let mut p = Reader::new(bytes);
        let alg = p.utf8_string()?;

        let k = match alg {
            "ssh-ed25519" => {
                // <https://datatracker.ietf.org/doc/html/rfc8709#name-public-key-format>
                let len = p.u32()?;
                if len != 32 {
                    return Err(ParseError(format!("incorrect ed25519 len: {len}")));
                }
                let public_key = p.array::<32>()?;
                let public_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
                    .map_err(|_| ParseError(format!("invalid ed25519 public key")))?;
                Self::Ed25519 { public_key }
            }
            "ecdsa-sha2-nistp256" => {
                // <https://datatracker.ietf.org/doc/html/rfc5656#section-3.1>
                let params = p.utf8_string()?;
                if params != "nistp256" {
                    return Err(ParseError(format!("curve parameter mismatch: {params}")));
                }
                let q = p.string()?;
                let public_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(q)
                    .map_err(|_| ParseError("invalid public key format".to_owned()))?;

                Self::EcdsaSha2NistP256 { public_key }
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
                // <https://datatracker.ietf.org/doc/html/rfc8709#name-public-key-format>
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

    pub fn verify_signature(&self, data: &[u8], signature: &Signature) -> bool {
        match self {
            PublicKey::Ed25519 { public_key } => match signature {
                Signature::Ed25519 { signature } => {
                    public_key.verify_strict(data, &signature).is_ok()
                }
                _ => false,
            },
            PublicKey::EcdsaSha2NistP256 { .. } => {
                todo!("ecdsa-sha2-nistp256 signature verification")
            }
        }
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self, f)
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
            }
        }
    }
}

fn b64encode(bytes: &[u8]) -> String {
    base64::prelude::BASE64_STANDARD.encode(bytes)
}

impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_wire_encoding())
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = PublicKey;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "bytes encoded as an SSH public key")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                PublicKey::from_wire_encoding(bytes).map_err(|err| {
                    serde::de::Error::custom(format_args!(
                        "invalid value: {}: {err}",
                        de::Unexpected::Bytes(bytes),
                    ))
                })
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::PublicKey;

    #[track_caller]
    fn test_roundtrip(keys: &[&str]) {
        for key_bytes in keys {
            eprintln!("{key_bytes}");
            let key_bytes: Vec<u8> = base64::prelude::BASE64_STANDARD.decode(key_bytes).unwrap();

            let key = PublicKey::from_wire_encoding(&key_bytes).unwrap();

            assert_eq!(key.to_wire_encoding(), key_bytes);
        }
    }

    #[test]
    fn ed25519() {
        test_roundtrip(&[
            "AAAAC3NzaC1lZDI1NTE5AAAAIJJKT1n+xPwS4ECXXPVB5U5gWwMpqa+FMvVuyFwbfvEg",
            "AAAAC3NzaC1lZDI1NTE5AAAAINZ1yLdDhI2Vou/9qrPIUP8RU8Sg0WxLI2njtP5hkdL7",
            "AAAAC3NzaC1lZDI1NTE5AAAAIAIIWlDvWkMEX8XIu6lxvd4cFOxeFUpH4ZReKuyS3h9l",
        ]);
    }

    #[test]
    fn ecdsa_sha2_nistp256() {
        test_roundtrip(&[
            "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHZTdlJoLNb701EWnahywBv032Aby+Piza7TzKW1H6Z//Hni/rBcUgnMmG+Kc4XWp6zgny3FMFpviuL01eJbpY8=",
            "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCv8bAwK5tZBEpOgFe6tmnog6GHKzeXnOK/qewbH4yiGb9fq4LkSY8oK3WhVZdIwtc1n8j9dNc4aGMURNlVBNKc=",
        ]);
    }
}
