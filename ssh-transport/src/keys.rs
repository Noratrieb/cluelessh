use chacha20poly1305::{
    aead::{Aead, AeadCore},
    ChaCha20Poly1305, KeyInit,
};
use sha2::Digest;

use crate::Result;

pub(crate) struct Session {
    session_id: [u8; 32],
    client_to_server_iv: [u8; 32],
    server_to_client_iv: [u8; 32],
    encryption_key_client_to_server: ChaCha20Poly1305,
    encryption_key_server_to_client: ChaCha20Poly1305,
    integrity_key_server_to_client: [u8; 32],
    integrity_key_client_to_server: [u8; 32],
}

impl Session {
    pub(crate) fn new(h: [u8; 32], k: [u8; 32]) -> Self {
        Self::from_keys(h, h, k)
    }

    pub(crate) fn rekey(&mut self, h: [u8; 32], k: [u8; 32]) {
        *self = Self::from_keys(self.session_id, h, k);
    }

    /// <https://datatracker.ietf.org/doc/html/rfc4253#section-7.2>
    fn from_keys(session_id: [u8; 32], h: [u8; 32], k: [u8; 32]) -> Self {
        let derive = |letter: &str| {
            let mut hash = sha2::Sha256::new();
            encode_mpint_for_hash(&k, |data| hash.update(data));
            hash.update(h);
            hash.update(letter.as_bytes());
            hash.update(session_id);
            hash.finalize()
        };

        let encryption_key_client_to_server = ChaCha20Poly1305::new(&derive("C"));
        let encryption_key_server_to_client = ChaCha20Poly1305::new(&derive("D"));

        Self {
            session_id,
            client_to_server_iv: derive("A").into(),
            server_to_client_iv: derive("B").into(),
            encryption_key_client_to_server,
            encryption_key_server_to_client,
            integrity_key_client_to_server: derive("E").into(),
            integrity_key_server_to_client: derive("F").into(),
        }
    }

    pub(crate) fn decrypt_bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.encryption_key_client_to_server
            .decrypt(&[0; 12].into(), bytes)
            .map_err(|_| crate::client_error!("failed to decrypt, invalid message"))
    }
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
