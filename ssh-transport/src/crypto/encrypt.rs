use crate::Result;
use aes_gcm::{aead::AeadMutInPlace, KeyInit};
use chacha20::cipher::{StreamCipher, StreamCipherSeek};
use subtle::ConstantTimeEq;

use crate::packet::{EncryptedPacket, Packet, RawPacket};

use super::EncryptionAlgorithm;

pub const CHACHA20POLY1305: EncryptionAlgorithm = EncryptionAlgorithm {
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
pub const AES256_GCM: EncryptionAlgorithm = EncryptionAlgorithm {
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
/// RFC 4344 AES128 in counter mode.
/// <https://datatracker.ietf.org/doc/html/rfc4344#section-4>
pub const ENC_AES128_CTR: EncryptionAlgorithm = EncryptionAlgorithm {
    name: "aes128-ctr",
    iv_size: 12,
    key_size: 32,
    decrypt_len: |state, bytes, packet_number| {
        let mut alg = Aes128Ctr::from_state(state);
        alg.decrypt_len(bytes, packet_number)
    },
    decrypt_packet: |state, bytes, packet_number| {
        let mut state = Aes128Ctr::from_state(state);
        state.decrypt_packet(bytes, packet_number)
    },
    encrypt_packet: |state, packet, packet_number| {
        let mut state = Aes128Ctr::from_state(state);
        state.encrypt_packet(packet, packet_number)
    },
};

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
            return Err(crate::peer_error!(
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
            .map_err(|_| crate::peer_error!("failed to decrypt: invalid GCM MAC"))?;
        self.inc_nonce();

        Packet::from_full(encrypted_packet_content)
    }

    fn encrypt_packet(&mut self, packet: Packet, _packet_number: u64) -> EncryptedPacket {
        let mut bytes = packet.to_bytes(
            false,
            <aes_gcm::aes::Aes256 as aes_gcm::aes::cipher::BlockSizeUser>::block_size() as u8,
        );

        let mut cipher = aes_gcm::Aes256Gcm::new(&self.key);

        let (aad, plaintext) = bytes.split_at_mut(4);

        let tag = cipher
            .encrypt_in_place_detached((&*self.nonce).into(), aad, plaintext)
            .unwrap();
        bytes.extend_from_slice(&tag);
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

struct Aes128Ctr {
    _key: ctr::Ctr128BE<aes::Aes128>,
}
impl Aes128Ctr {
    fn from_state(_keys: &mut [u8]) -> Self {
        todo!()
    }

    fn decrypt_len(&mut self, _: &mut [u8], _: u64) {}

    fn decrypt_packet(&mut self, _bytes: RawPacket, _packet_number: u64) -> Result<Packet> {
        todo!()
    }
    fn encrypt_packet(&mut self, _packet: Packet, _packet_number: u64) -> EncryptedPacket {
        todo!()
    }
}
