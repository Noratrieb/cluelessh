use chacha20::cipher::{KeyInit, StreamCipher, StreamCipherSeek};
use sha2::Digest;
use subtle::ConstantTimeEq;

use crate::{
    packet::{EncryptedPacket, MsgKind, Packet, RawPacket},
    Msg, Result,
};

pub(crate) struct Session {
    session_id: [u8; 32],
    encryption_key_client_to_server: SshChaCha20Poly1305,
    encryption_key_server_to_client: SshChaCha20Poly1305,
}

pub(crate) trait Keys: Send + Sync + 'static {
    fn decrypt_len(&mut self, bytes: &mut [u8; 4], packet_number: u64);
    fn decrypt_packet(&mut self, raw_packet: RawPacket, packet_number: u64) -> Result<Packet>;

    fn encrypt_packet_to_msg(&mut self, packet: Packet, packet_number: u64) -> Msg;

    fn additional_mac_len(&self) -> usize;
    fn rekey(&mut self, h: [u8; 32], k: [u8; 32]) -> Result<(), ()>;
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
    fn rekey(&mut self, _: [u8; 32], _: [u8; 32]) -> Result<(), ()> {
        Err(())
    }
}

impl Session {
    pub(crate) fn new(h: [u8; 32], k: [u8; 32]) -> Self {
        Self::from_keys(h, h, k)
    }

    /// <https://datatracker.ietf.org/doc/html/rfc4253#section-7.2>
    fn from_keys(session_id: [u8; 32], h: [u8; 32], k: [u8; 32]) -> Self {
        let encryption_key_client_to_server =
            SshChaCha20Poly1305::new(derive_key(k, h, "C", session_id));
        let encryption_key_server_to_client =
            SshChaCha20Poly1305::new(derive_key(k, h, "D", session_id));

        Self {
            session_id,
            // client_to_server_iv: derive("A").into(),
            // server_to_client_iv: derive("B").into(),
            encryption_key_client_to_server,
            encryption_key_server_to_client,
            // integrity_key_client_to_server: derive("E").into(),
            // integrity_key_server_to_client: derive("F").into(),
        }
    }
}

impl Keys for Session {
    fn decrypt_len(&mut self, bytes: &mut [u8; 4], packet_number: u64) {
        self.encryption_key_client_to_server
            .decrypt_len(bytes, packet_number);
    }

    fn decrypt_packet(&mut self, bytes: RawPacket, packet_number: u64) -> Result<Packet> {
        self.encryption_key_client_to_server
            .decrypt_packet(bytes, packet_number)
    }

    fn encrypt_packet_to_msg(&mut self, packet: Packet, packet_number: u64) -> Msg {
        let packet = self
            .encryption_key_server_to_client
            .encrypt_packet(packet, packet_number);
        Msg(MsgKind::EncryptedPacket(packet))
    }

    fn additional_mac_len(&self) -> usize {
        poly1305::BLOCK_SIZE
    }

    fn rekey(&mut self, h: [u8; 32], k: [u8; 32]) -> Result<(), ()> {
        *self = Self::from_keys(self.session_id, h, k);
        Ok(())
    }
}

/// Derive a key from the shared secret K and exchange hash H.
/// <https://datatracker.ietf.org/doc/html/rfc4253#section-7.2>
fn derive_key(k: [u8; 32], h: [u8; 32], letter: &str, session_id: [u8; 32]) -> [u8; 64] {
    let sha2len = sha2::Sha256::output_size();
    let mut output = [0; 64];

    //let mut hash = sha2::Sha256::new();
    //encode_mpint_for_hash(&k, |data| hash.update(data));
    //hash.update(h);
    //hash.update(letter.as_bytes());
    //hash.update(session_id);
    //output[..sha2len].copy_from_slice(&hash.finalize());

    for i in 0..(64 / sha2len) {
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

struct SshChaCha20Poly1305 {
    header_key: chacha20::Key,
    main_key: chacha20::Key,
}

impl SshChaCha20Poly1305 {
    fn new(key: [u8; 64]) -> Self {
        Self {
            main_key: <[u8; 32]>::try_from(&key[..32]).unwrap().into(),
            header_key: <[u8; 32]>::try_from(&key[32..]).unwrap().into(),
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

    fn decrypt_packet(&mut self, mut bytes: RawPacket, packet_number: u64) -> Result<Packet> {
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

    fn encrypt_packet(&mut self, packet: Packet, packet_number: u64) -> EncryptedPacket {
        let mut bytes = packet.to_bytes(false);

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

        bytes.extend_from_slice(&mac);

        EncryptedPacket::from_encrypted_full_bytes(bytes)
    }
}
