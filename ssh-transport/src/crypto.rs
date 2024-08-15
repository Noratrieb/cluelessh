pub mod encrypt;

use p256::ecdsa::signature::Signer;
use sha2::Digest;

use crate::{
    client_error,
    packet::{EncryptedPacket, MsgKind, Packet, RawPacket},
    parse::{self, Writer},
    Msg, Result, SshRng,
};

pub trait AlgorithmName {
    fn name(&self) -> &'static str;
}

#[derive(Clone, Copy)]
pub struct KexAlgorithm {
    name: &'static str,
    pub exchange: fn(
        client_public_key: &[u8],
        random: &mut (dyn SshRng + Send + Sync),
    ) -> Result<KexAlgorithmOutput>,
}
impl AlgorithmName for KexAlgorithm {
    fn name(&self) -> &'static str {
        self.name
    }
}
pub struct KexAlgorithmOutput {
    /// K
    pub shared_secret: Vec<u8>,
    /// Q_S
    pub server_public_key: Vec<u8>,
}

/// <https://datatracker.ietf.org/doc/html/rfc8731>
pub const KEX_CURVE_25519_SHA256: KexAlgorithm = KexAlgorithm {
    name: "curve25519-sha256",
    exchange: |client_public_key, rng| {
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(crate::SshRngRandAdapter(rng));
        let server_public_key = x25519_dalek::PublicKey::from(&secret); // Q_S

        let Ok(arr) = <[u8; 32]>::try_from(client_public_key) else {
            return Err(crate::client_error!(
                "invalid x25519 public key length, should be 32, was: {}",
                client_public_key.len()
            ));
        };
        let client_public_key = x25519_dalek::PublicKey::from(arr);
        let shared_secret = secret.diffie_hellman(&client_public_key); // K

        Ok(KexAlgorithmOutput {
            server_public_key: server_public_key.as_bytes().to_vec(),
            shared_secret: shared_secret.as_bytes().to_vec(),
        })
    },
};
/// <https://datatracker.ietf.org/doc/html/rfc5656>
pub const KEX_ECDH_SHA2_NISTP256: KexAlgorithm = KexAlgorithm {
    name: "ecdh-sha2-nistp256",
    exchange: |client_public_key, rng| {
        let secret = p256::ecdh::EphemeralSecret::random(&mut crate::SshRngRandAdapter(rng));
        let server_public_key = p256::EncodedPoint::from(secret.public_key()); // Q_S

        let client_public_key =
            p256::PublicKey::from_sec1_bytes(client_public_key).map_err(|_| {
                crate::client_error!(
                    "invalid p256 public key length: {}",
                    client_public_key.len()
                )
            })?; // Q_C

        let shared_secret = secret.diffie_hellman(&client_public_key); // K

        Ok(KexAlgorithmOutput {
            server_public_key: server_public_key.as_bytes().to_vec(),
            shared_secret: shared_secret.raw_secret_bytes().to_vec(),
        })
    },
};

#[derive(Clone, Copy)]
pub struct EncryptionAlgorithm {
    name: &'static str,
    iv_size: usize,
    key_size: usize,
    decrypt_len: fn(state: &mut [u8], bytes: &mut [u8], packet_number: u64),
    decrypt_packet: fn(state: &mut [u8], bytes: RawPacket, packet_number: u64) -> Result<Packet>,
    encrypt_packet: fn(state: &mut [u8], packet: Packet, packet_number: u64) -> EncryptedPacket,
}
impl AlgorithmName for EncryptionAlgorithm {
    fn name(&self) -> &'static str {
        self.name
    }
}

pub struct EncodedSshPublicHostKey(pub Vec<u8>);
pub struct EncodedSshSignature(pub Vec<u8>);

pub struct HostKeySigningAlgorithm {
    name: &'static str,
    hostkey_private: Vec<u8>,
    public_key: fn(private_key: &[u8]) -> EncodedSshPublicHostKey,
    sign: fn(private_key: &[u8], data: &[u8]) -> EncodedSshSignature,
}

impl AlgorithmName for HostKeySigningAlgorithm {
    fn name(&self) -> &'static str {
        self.name
    }
}

impl HostKeySigningAlgorithm {
    pub fn sign(&self, data: &[u8]) -> EncodedSshSignature {
        (self.sign)(&self.hostkey_private, data)
    }
    pub fn public_key(&self) -> EncodedSshPublicHostKey {
        (self.public_key)(&self.hostkey_private)
    }
}

pub fn hostkey_ed25519(hostkey_private: Vec<u8>) -> HostKeySigningAlgorithm {
    HostKeySigningAlgorithm {
        name: "ssh-ed25519",
        hostkey_private,
        public_key: |key| {
            let key = ed25519_dalek::SigningKey::from_bytes(key.try_into().unwrap());
            let public_key = key.verifying_key();

            // <https://datatracker.ietf.org/doc/html/rfc8709#section-4>
            let mut data = Writer::new();
            data.string(b"ssh-ed25519");
            data.string(public_key.as_bytes());
            EncodedSshPublicHostKey(data.finish())
        },
        sign: |key, data| {
            let key = ed25519_dalek::SigningKey::from_bytes(key.try_into().unwrap());
            let signature = key.sign(data);

            // <https://datatracker.ietf.org/doc/html/rfc8709#section-6>
            let mut data = Writer::new();
            data.string(b"ssh-ed25519");
            data.string(&signature.to_bytes());
            EncodedSshSignature(data.finish())
        },
    }
}
pub fn hostkey_ecdsa_sha2_p256(hostkey_private: Vec<u8>) -> HostKeySigningAlgorithm {
    HostKeySigningAlgorithm {
        name: "ecdsa-sha2-nistp256",
        hostkey_private,
        public_key: |key| {
            let key = p256::ecdsa::SigningKey::from_slice(key).unwrap();
            let public_key = key.verifying_key();
            let mut data = Writer::new();

            // <https://datatracker.ietf.org/doc/html/rfc5656#section-3.1>
            data.string(b"ecdsa-sha2-nistp256");
            data.string(b"nistp256");
            // > point compression MAY be used.
            // But OpenSSH does not appear to support that, so let's NOT use it.
            data.string(public_key.to_encoded_point(false).as_bytes());
            EncodedSshPublicHostKey(data.finish())
        },
        sign: |key, data| {
            let key = p256::ecdsa::SigningKey::from_slice(key).unwrap();
            let signature: p256::ecdsa::Signature = key.sign(data);
            let (r, s) = signature.split_scalars();

            // <https://datatracker.ietf.org/doc/html/rfc5656#section-3.1.2>
            let mut data = Writer::new();
            data.string(b"ecdsa-sha2-nistp256");
            let mut signature_blob = Writer::new();
            signature_blob.mpint(p256::U256::from(r.as_ref()));
            signature_blob.mpint(p256::U256::from(s.as_ref()));
            data.string(&signature_blob.finish());
            EncodedSshSignature(data.finish())
        },
    }
}

pub struct AlgorithmNegotiation<T> {
    pub supported: Vec<T>,
}

impl<T: AlgorithmName> AlgorithmNegotiation<T> {
    pub fn find<'a>(mut self, client_supports: &str) -> Result<T> {
        for client_alg in client_supports.split(',') {
            if let Some(alg) = self
                .supported
                .iter()
                .position(|alg| alg.name() == client_alg)
            {
                return Ok(self.supported.remove(alg));
            }
        }

        Err(client_error!(
            "client does not support any matching algorithm: supported: {client_supports:?}"
        ))
    }
}

pub(crate) struct Session {
    session_id: [u8; 32],
    client_to_server: Tunnel,
    server_to_client: Tunnel,
}

struct Tunnel {
    /// `key || IV`
    state: Vec<u8>,
    algorithm: EncryptionAlgorithm,
}

pub(crate) trait Keys: Send + Sync + 'static {
    fn decrypt_len(&mut self, bytes: &mut [u8; 4], packet_number: u64);
    fn decrypt_packet(&mut self, raw_packet: RawPacket, packet_number: u64) -> Result<Packet>;

    fn encrypt_packet_to_msg(&mut self, packet: Packet, packet_number: u64) -> Msg;

    fn additional_mac_len(&self) -> usize;
    fn rekey(
        &mut self,
        h: [u8; 32],
        k: &[u8],
        encryption_client_to_server: EncryptionAlgorithm,
        encryption_server_to_client: EncryptionAlgorithm,
    ) -> Result<(), ()>;
}

pub(crate) struct Plaintext;
impl Keys for Plaintext {
    fn decrypt_len(&mut self, _: &mut [u8; 4], _: u64) {}
    fn decrypt_packet(&mut self, raw: RawPacket, _: u64) -> Result<Packet> {
        Packet::from_full(raw.rest())
    }
    fn encrypt_packet_to_msg(&mut self, packet: Packet, _: u64) -> Msg {
        Msg(MsgKind::PlaintextPacket(packet))
    }
    fn additional_mac_len(&self) -> usize {
        0
    }
    fn rekey(
        &mut self,
        _: [u8; 32],
        _: &[u8],
        _: EncryptionAlgorithm,
        _: EncryptionAlgorithm,
    ) -> Result<(), ()> {
        Err(())
    }
}

impl Session {
    pub(crate) fn new(
        h: [u8; 32],
        k: &[u8],
        encryption_client_to_server: EncryptionAlgorithm,
        encryption_server_to_client: EncryptionAlgorithm,
    ) -> Self {
        Self::from_keys(
            h,
            h,
            k,
            encryption_client_to_server,
            encryption_server_to_client,
        )
    }

    /// <https://datatracker.ietf.org/doc/html/rfc4253#section-7.2>
    fn from_keys(
        session_id: [u8; 32],
        h: [u8; 32],
        k: &[u8],
        alg_c2s: EncryptionAlgorithm,
        alg_s2c: EncryptionAlgorithm,
    ) -> Self {
        Self {
            session_id,
            client_to_server: Tunnel {
                algorithm: alg_c2s,
                state: {
                    let mut state = derive_key(k, h, "C", session_id, alg_c2s.key_size);
                    let iv = derive_key(k, h, "A", session_id, alg_c2s.iv_size);
                    state.extend_from_slice(&iv);
                    state
                },
            },
            server_to_client: Tunnel {
                algorithm: alg_s2c,
                state: {
                    let mut state = derive_key(k, h, "D", session_id, alg_s2c.key_size);
                    state.extend_from_slice(&derive_key(k, h, "B", session_id, alg_s2c.iv_size));
                    state
                },
            },
            // integrity_key_client_to_server: derive("E").into(),
            // integrity_key_server_to_client: derive("F").into(),
        }
    }
}

impl Keys for Session {
    fn decrypt_len(&mut self, bytes: &mut [u8; 4], packet_number: u64) {
        (self.client_to_server.algorithm.decrypt_len)(
            &mut self.client_to_server.state,
            bytes,
            packet_number,
        );
    }

    fn decrypt_packet(&mut self, bytes: RawPacket, packet_number: u64) -> Result<Packet> {
        (self.client_to_server.algorithm.decrypt_packet)(
            &mut self.client_to_server.state,
            bytes,
            packet_number,
        )
    }

    fn encrypt_packet_to_msg(&mut self, packet: Packet, packet_number: u64) -> Msg {
        let packet = (self.server_to_client.algorithm.encrypt_packet)(
            &mut self.server_to_client.state,
            packet,
            packet_number,
        );
        Msg(MsgKind::EncryptedPacket(packet))
    }

    fn additional_mac_len(&self) -> usize {
        poly1305::BLOCK_SIZE
    }

    fn rekey(
        &mut self,
        h: [u8; 32],
        k: &[u8],
        encryption_client_to_server: EncryptionAlgorithm,
        encryption_server_to_client: EncryptionAlgorithm,
    ) -> Result<(), ()> {
        *self = Self::from_keys(
            self.session_id,
            h,
            k,
            encryption_client_to_server,
            encryption_server_to_client,
        );
        Ok(())
    }
}

/// Derive a key from the shared secret K and exchange hash H.
/// <https://datatracker.ietf.org/doc/html/rfc4253#section-7.2>
fn derive_key(
    k: &[u8],
    h: [u8; 32],
    letter: &str,
    session_id: [u8; 32],
    key_size: usize,
) -> Vec<u8> {
    let sha2len = sha2::Sha256::output_size();
    let padded_key_size = key_size.next_multiple_of(sha2len);
    let mut output = vec![0; padded_key_size];

    for i in 0..(padded_key_size / sha2len) {
        let mut hash = <sha2::Sha256 as sha2::Digest>::new();
        encode_mpint_for_hash(&k, |data| hash.update(data));
        hash.update(h);

        if i == 0 {
            hash.update(letter.as_bytes());
            hash.update(session_id);
        } else {
            hash.update(&output[..(i * sha2len)]);
        }

        output[(i * sha2len)..][..sha2len].copy_from_slice(&hash.finalize())
    }

    output.truncate(key_size);
    output
}

pub(crate) fn encode_mpint_for_hash(key: &[u8], mut add_to_hash: impl FnMut(&[u8])) {
    let (key, pad_zero) = parse::fixup_mpint(key);
    add_to_hash(&u32::to_be_bytes((key.len() + (pad_zero as usize)) as u32));
    if pad_zero {
        add_to_hash(&[0]);
    }
    add_to_hash(key);
}
