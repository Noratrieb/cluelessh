use cluelessh_format::Writer;

use crate::{private::PrivateKey, public::PublicKey};

// TODO SessionId newtype
pub fn signature_data(session_id: [u8; 32], username: &str, pubkey: &PublicKey) -> Vec<u8> {
    let mut s = Writer::new();

    s.string(session_id);
    s.u8(cluelessh_format::numbers::SSH_MSG_USERAUTH_REQUEST);
    s.string(username);
    s.string("ssh-connection");
    s.string("publickey");
    s.bool(true);
    s.string(pubkey.algorithm_name());
    s.string(pubkey.to_wire_encoding());

    s.finish()
}

pub enum Signature {
    Ed25519 { signature: ed25519_dalek::Signature },
    EcdsaSha2NistP256 { signature: p256::ecdsa::Signature },
}

impl Signature {
    pub fn to_wire_encoding(&self) -> Vec<u8> {
        let mut data = Writer::new();
        data.string(self.algorithm_name());
        match self {
            Self::Ed25519 { signature } => {
                // <https://datatracker.ietf.org/doc/html/rfc8709#name-signature-format>
                data.string(signature.to_bytes());
            }
            Self::EcdsaSha2NistP256 { signature } => {
                // <https://datatracker.ietf.org/doc/html/rfc5656#section-3.1.2>

                let (r, s) = signature.split_scalars();

                let mut signature_blob = Writer::new();
                signature_blob.mpint(p256::U256::from(r.as_ref()));
                signature_blob.mpint(p256::U256::from(s.as_ref()));
                data.string(signature_blob.finish());
            }
        }
        data.finish()
    }

    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Ed25519 { .. } => "ssh-ed25519",
            Self::EcdsaSha2NistP256 { .. } => "ecdsa-sha2-nistp256",
        }
    }
}

impl PrivateKey {
    pub fn sign(&self, data: &[u8]) -> Signature {
        match self {
            Self::Ed25519 { private_key, .. } => {
                use ed25519_dalek::Signer;

                let sig = private_key.sign(data);
                Signature::Ed25519 { signature: sig }
            }
            Self::EcdsaSha2NistP256 { private_key, .. } => {
                use p256::ecdsa::signature::Signer;

                let sig = private_key.sign(data);
                Signature::EcdsaSha2NistP256 { signature: sig }
            }
        }
    }
}
