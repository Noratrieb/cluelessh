use aes_gcm::aead::{Aead, AeadMutInPlace};
use chacha20::cipher::{KeyInit, StreamCipher, StreamCipherSeek};
use sha2::Digest;
use subtle::ConstantTimeEq;

use crate::{
    client_error,
    packet::{EncryptedPacket, MsgKind, Packet, RawPacket},
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
pub const ENC_CHACHA20POLY1305: EncryptionAlgorithm = EncryptionAlgorithm {
    name: "chacha20-poly1305@openssh.com",
    iv_size: 0,
    key_size: 64, // 32 for header, 32 for main
    decrypt_len: |state, bytes, packet_number| {
        let alg = ChaCha20Poly1305OpenSsh::from_state(state);
        alg.decrypt_len(bytes, packet_number)
    },
    decrypt_packet: |state, bytes, packet_number| {
        let alg = ChaCha20Poly1305OpenSsh::from_state(state);
        alg.decrypt_packet(bytes, packet_number)
    },
    encrypt_packet: |state, packet, packet_number| {
        let alg = ChaCha20Poly1305OpenSsh::from_state(state);
        alg.encrypt_packet(packet, packet_number)
    },
};
pub const ENC_AES256_GCM: EncryptionAlgorithm = EncryptionAlgorithm {
    name: "aes256-gcm@openssh.com",
    iv_size: 12,
    key_size: 32,
    decrypt_len: |state, bytes, packet_number| {
        let mut alg = Aes256GcmOpenSsh::from_state(state);
        alg.decrypt_len(bytes, packet_number)
    },
    decrypt_packet: |state, bytes, packet_number| {
        let mut alg = Aes256GcmOpenSsh::from_state(state);
        alg.decrypt_packet(bytes, packet_number)
    },
    encrypt_packet: |state, packet, packet_number| {
        let mut alg = Aes256GcmOpenSsh::from_state(state);
        alg.encrypt_packet(packet, packet_number)
    },
};

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
                    state.extend_from_slice(&derive_key(k, h, "A", session_id, alg_c2s.iv_size));
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
    let mut output = vec![0; key_size];

    //let mut hash = sha2::Sha256::new();
    //encode_mpint_for_hash(&k, |data| hash.update(data));
    //hash.update(h);
    //hash.update(letter.as_bytes());
    //hash.update(session_id);
    //output[..sha2len].copy_from_slice(&hash.finalize());

    for i in 0..(key_size / sha2len) {
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

    output
}

pub(crate) fn encode_mpint_for_hash(mut key: &[u8], mut add_to_hash: impl FnMut(&[u8])) {
    while key[0] == 0 {
        key = &key[1..];
    }
    // If the first high bit is set, pad it with a zero.
    let pad_zero = (key[0] & 0b10000000) > 1;
    add_to_hash(&u32::to_be_bytes((key.len() + (pad_zero as usize)) as u32));
    if pad_zero {
        add_to_hash(&[0]);
    }
    add_to_hash(key);
}

/// `chacha20-poly1305@openssh.com` uses a 64-bit nonce, not the 96-bit one in the IETF version.
type SshChaCha20 = chacha20::ChaCha20Legacy;

/// <https://github.com/openssh/openssh-portable/blob/1ec0a64c5dc57b8a2053a93b5ef0d02ff8598e5c/PROTOCOL.chacha20poly1305>
struct ChaCha20Poly1305OpenSsh {
    header_key: chacha20::Key,
    main_key: chacha20::Key,
}

impl ChaCha20Poly1305OpenSsh {
    fn from_state(keys: &[u8]) -> Self {
        assert_eq!(keys.len(), 64);
        Self {
            main_key: <[u8; 32]>::try_from(&keys[..32]).unwrap().into(),
            header_key: <[u8; 32]>::try_from(&keys[32..]).unwrap().into(),
        }
    }

    fn decrypt_len(&self, bytes: &mut [u8], packet_number: u64) {
        // <https://github.com/openssh/openssh-portable/blob/1ec0a64c5dc57b8a2053a93b5ef0d02ff8598e5c/PROTOCOL.chacha20poly1305>
        let mut cipher = <SshChaCha20 as chacha20::cipher::KeyIvInit>::new(
            &self.header_key,
            &packet_number.to_be_bytes().into(),
        );
        cipher.apply_keystream(bytes);
    }

    fn decrypt_packet(&self, mut bytes: RawPacket, packet_number: u64) -> Result<Packet> {
        // <https://github.com/openssh/openssh-portable/blob/1ec0a64c5dc57b8a2053a93b5ef0d02ff8598e5c/PROTOCOL.chacha20poly1305>

        let mut cipher = <SshChaCha20 as chacha20::cipher::KeyIvInit>::new(
            &self.main_key,
            &packet_number.to_be_bytes().into(),
        );

        let tag_offset = bytes.full_packet().len() - 16;
        let authenticated = &bytes.full_packet()[..tag_offset];

        let mac = {
            let mut poly1305_key = [0; poly1305::KEY_SIZE];
            cipher.apply_keystream(&mut poly1305_key);
            poly1305::Poly1305::new(&poly1305_key.into()).compute_unpadded(authenticated)
        };

        let read_tag = poly1305::Tag::from_slice(&bytes.full_packet()[tag_offset..]);

        if !bool::from(mac.ct_eq(read_tag)) {
            return Err(crate::client_error!(
                "failed to decrypt: invalid poly1305 MAC"
            ));
        }

        // Advance ChaCha's block counter to 1
        cipher
            .seek(<chacha20::ChaCha20LegacyCore as chacha20::cipher::BlockSizeUser>::block_size());

        let encrypted_packet_content = bytes.content_mut();
        cipher.apply_keystream(encrypted_packet_content);

        Packet::from_full(encrypted_packet_content)
    }

    fn encrypt_packet(&self, packet: Packet, packet_number: u64) -> EncryptedPacket {
        let mut bytes = packet.to_bytes(false, Packet::DEFAULT_BLOCK_SIZE);

        // Prepare the main cipher.
        let mut main_cipher = <SshChaCha20 as chacha20::cipher::KeyIvInit>::new(
            &self.main_key,
            &packet_number.to_be_bytes().into(),
        );

        // Get the poly1305 key first, but don't use it yet!
        // We encrypt-then-mac.
        let mut poly1305_key = [0; poly1305::KEY_SIZE];
        main_cipher.apply_keystream(&mut poly1305_key);

        // As the first act of encryption, encrypt the length.
        let mut len_cipher = <SshChaCha20 as chacha20::cipher::KeyIvInit>::new(
            &self.header_key,
            &packet_number.to_be_bytes().into(),
        );
        len_cipher.apply_keystream(&mut bytes[..4]);

        // Advance ChaCha's block counter to 1
        main_cipher
            .seek(<chacha20::ChaCha20LegacyCore as chacha20::cipher::BlockSizeUser>::block_size());
        // Encrypt the content of the packet, excluding the length and the MAC, which is not pushed yet.
        main_cipher.apply_keystream(&mut bytes[4..]);

        // Now, MAC the length || content, and push that to the end.
        let mac = poly1305::Poly1305::new(&poly1305_key.into()).compute_unpadded(&bytes);

        bytes.extend_from_slice(mac.as_slice());

        EncryptedPacket::from_encrypted_full_bytes(bytes)
    }
}

/// <https://datatracker.ietf.org/doc/html/rfc5647>
/// <https://github.com/openssh/openssh-portable/blob/1ec0a64c5dc57b8a2053a93b5ef0d02ff8598e5c/PROTOCOL#L188C49-L188C64>
struct Aes256GcmOpenSsh<'a> {
    key: aes_gcm::Key<aes_gcm::Aes256Gcm>,
    nonce: &'a mut [u8; 12],
}

impl<'a> Aes256GcmOpenSsh<'a> {
    fn from_state(keys: &'a mut [u8]) -> Self {
        assert_eq!(keys.len(), 44);
        Self {
            key: <[u8; 32]>::try_from(&keys[..32]).unwrap().into(),
            nonce: <&mut [u8; 12]>::try_from(&mut keys[32..]).unwrap(),
        }
    }

    fn decrypt_len(&mut self, _: &mut [u8], _: u64) {
        // AES-GCM does not encrypt the length.
        // <https://datatracker.ietf.org/doc/html/rfc5647#section-7.3>
    }

    fn decrypt_packet(&mut self, mut bytes: RawPacket, _packet_number: u64) -> Result<Packet> {
        let mut cipher = aes_gcm::Aes256Gcm::new(&self.key);

        let mut len = [0; 4];
        len.copy_from_slice(&bytes.full_packet()[..4]);

        let tag_offset = bytes.full_packet().len() - 16;
        let mut tag = [0; 16];
        tag.copy_from_slice(&bytes.full_packet()[tag_offset..]);

        let encrypted_packet_content = bytes.content_mut();

        cipher
            .decrypt_in_place_detached(
                (&*self.nonce).into(),
                &len,
                encrypted_packet_content,
                (&tag).into(),
            )
            .map_err(|_| crate::client_error!("failed to decrypt: invalid GCM MAC"))?;
        self.inc_nonce();

        Packet::from_full(encrypted_packet_content)
    }

    fn encrypt_packet(&mut self, packet: Packet, _packet_number: u64) -> EncryptedPacket {
        let bytes = packet.to_bytes(
            false,
            <aes_gcm::aes::Aes256 as aes_gcm::aes::cipher::BlockSizeUser>::block_size() as u8,
        );

        let cipher = aes_gcm::Aes256Gcm::new(&self.key);

        let bytes = cipher
            .encrypt(
                (&*self.nonce).into(),
                aes_gcm::aead::Payload {
                    aad: &bytes[..4],
                    msg: &bytes[4..],
                },
            )
            .unwrap();
        self.inc_nonce();

        EncryptedPacket::from_encrypted_full_bytes(bytes)
    }

    fn inc_nonce(&mut self) {
        let mut carry = 1;
        for i in (0..self.nonce.len()).rev() {
            let n = self.nonce[i] as u16 + carry;
            self.nonce[i] = n as u8;
            carry = n >> 8;
        }
    }
}
