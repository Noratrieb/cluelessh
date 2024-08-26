use base64::Engine;

use crate::public::{PublicKey, PublicKeyWithComment};

pub struct AuthorizedKeys {
    pub keys: Vec<PublicKeyWithComment>,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid authorized_keys: {0}")]
pub struct Error(String);

impl AuthorizedKeys {
    pub fn parse(authorized_keys: &str) -> Result<Self, Error> {
        let lines = authorized_keys.lines();
        let mut keys: Vec<PublicKeyWithComment> = Vec::new();

        for line in lines {
            let mut parts = line.split_whitespace();
            let alg = parts
                .next()
                .ok_or_else(|| Error("missing algorithm on line".to_owned()))?;
            let key_blob = parts
                .next()
                .ok_or_else(|| Error("missing key on line".to_owned()))?;
            let key_blob = base64::prelude::BASE64_STANDARD
                .decode(key_blob)
                .map_err(|err| Error(format!("invalid base64 encoding for key: {err}")))?;
            let comment = parts.next().unwrap_or_default();

            let public_key = PublicKey::from_wire_encoding(&key_blob)
                .map_err(|err| Error(format!("unsupported key: {err}")))?;

            if public_key.algorithm_name() != alg {
                return Err(Error(format!(
                    "algorithm name mismatch: {} != {}",
                    public_key.algorithm_name(),
                    alg
                )));
            }

            keys.push(PublicKeyWithComment {
                key: public_key,
                comment: comment.to_owned(),
            });
        }

        Ok(Self { keys })
    }

    pub fn contains(&self, provided_key: &PublicKey) -> Option<&PublicKeyWithComment> {
        self.keys.iter().find(|key| key.key == *provided_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::public::{PublicKey, PublicKeyWithComment};

    use super::AuthorizedKeys;

    #[test]
    fn parse_single() {
        let keys = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG0n1ikUG9rYqobh7WpAyXrqZqxQoQ2zNJrFPj12gTpP nora\n";
        let keys = AuthorizedKeys::parse(keys).unwrap();
        assert_eq!(
            keys.keys.as_slice(),
            [PublicKeyWithComment {
                key: PublicKey::Ed25519 {
                    public_key: ed25519_dalek::VerifyingKey::from_bytes(
                        &[
                            109, 39, 214, 41, 20, 27, 218, 216, 170, 134, 225, 237, 106, 64, 201,
                            122, 234, 102, 172, 80, 161, 13, 179, 52, 154, 197, 62, 61, 118, 129,
                            58, 79,
                        ]
                        .try_into()
                        .unwrap()
                    )
                    .unwrap(),
                },
                comment: "nora".into(),
            }]
        );
    }

    #[test]
    fn contains() {
        let keys = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG0n1ikUG9rYqobh7WpAyXrqZqxQoQ2zNJrFPj12gTpP nora\n";
        let keys = AuthorizedKeys::parse(keys).unwrap();

        let provided = PublicKey::Ed25519 {
            public_key: ed25519_dalek::VerifyingKey::from_bytes(
                &[
                    109, 39, 214, 41, 20, 27, 218, 216, 170, 134, 225, 237, 106, 64, 201, 122, 234,
                    102, 172, 80, 161, 13, 179, 52, 154, 197, 62, 61, 118, 129, 58, 79,
                ]
                .try_into()
                .unwrap(),
            )
            .unwrap(),
        };

        let flipped = PublicKey::Ed25519 {
            public_key: ed25519_dalek::VerifyingKey::from_bytes(
                &[
                    1, 39, 214, 41, 20, 27, 218, 216, 170, 134, 225, 237, 106, 64, 201, 122, 234,
                    102, 172, 80, 161, 13, 179, 52, 154, 197, 62, 61, 118, 129, 58, 79,
                ]
                .try_into()
                .unwrap(),
            )
            .unwrap(),
        };

        assert!(keys.contains(&provided).is_some());
        assert!(keys.contains(&flipped).is_none());
    }

    #[test]
    fn empty() {
        let keys = "";
        let keys = AuthorizedKeys::parse(keys).unwrap();
        assert_eq!(keys.keys, []);
    }

    #[test]
    fn no_comment() {
        let keys =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG0n1ikUG9rYqobh7WpAyXrqZqxQoQ2zNJrFPj12gTpP\n";
        let keys = AuthorizedKeys::parse(keys).unwrap();
        assert_eq!(
            keys.keys.as_slice(),
            [PublicKeyWithComment {
                key: PublicKey::Ed25519 {
                    public_key: ed25519_dalek::VerifyingKey::from_bytes(
                        &[
                            109, 39, 214, 41, 20, 27, 218, 216, 170, 134, 225, 237, 106, 64, 201,
                            122, 234, 102, 172, 80, 161, 13, 179, 52, 154, 197, 62, 61, 118, 129,
                            58, 79,
                        ]
                        .try_into()
                        .unwrap()
                    )
                    .unwrap(),
                },
                comment: "".into(),
            }]
        );
    }

    #[test]
    fn multiple() {
        let keys =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG0n1ikUG9rYqobh7WpAyXrqZqxQoQ2zNJrFPj12gTpP nora\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG0n1ikUG9rYqobh7WpAyXrqZqxQoQ2zNJrFPj12gTpP peter\n";
        let keys = AuthorizedKeys::parse(keys).unwrap();
        assert_eq!(keys.keys.len(), 2);
    }

    #[test]
    fn corrupt() {
        let keys = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG0n1ikUG";
        let keys = AuthorizedKeys::parse(keys);
        assert!(keys.is_err());
    }

    #[test]
    fn algorithm_mismatch() {
        let keys =
            "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIG0n1ikUG9rYqobh7WpAyXrqZqxQoQ2zNJrFPj12gTpP nora\n";
        let keys = AuthorizedKeys::parse(keys);
        assert!(keys.is_err());
    }
}
