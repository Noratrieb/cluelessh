use std::fmt::Debug;

use crate::crypto::{self, Cipher, Kdf};
use cluelessh_format::{Reader, Writer};

use crate::public::PublicKey;
use crate::KeyGenerationParams;

pub struct EncryptedPrivateKeys {
    pub public_keys: Vec<PublicKey>,
    pub cipher: Cipher,
    pub kdf: Kdf,
    pub encrypted_private_keys: Vec<u8>,
}

#[derive(Clone)]
pub struct PlaintextPrivateKey {
    pub private_key: PrivateKey,
    pub comment: String,
    checkint: u32,
}

impl Debug for PlaintextPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaintextPrivateKey")
            .field(
                "public_key",
                &format_args!("{}", self.private_key.public_key()),
            )
            .field("comment", &self.comment)
            .finish()
    }
}

#[derive(Clone)]
pub enum PrivateKey {
    Ed25519 {
        public_key: ed25519_dalek::VerifyingKey,
        private_key: ed25519_dalek::SigningKey,
    },
    EcdsaSha2NistP256 {
        public_key: p256::ecdsa::VerifyingKey,
        private_key: p256::ecdsa::SigningKey,
    },
}

const MAGIC: &[u8; 15] = b"openssh-key-v1\0";

impl EncryptedPrivateKeys {
    /// Parse OpenSSH private keys, either armored or not.
    pub fn parse(content: &[u8]) -> cluelessh_format::Result<Self> {
        // https://github.com/openssh/openssh-portable/blob/a76a6b85108e3032c8175611ecc5746e7131f876/PROTOCOL.key
        let pem: pem::Pem; // lifetime extension
        let content = if content.starts_with(b"openssh-key-v1") {
            content
        } else if content.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----") {
            pem = pem::parse(content).map_err(|err| {
                cluelessh_format::ParseError(format!("invalid PEM format: {err}"))
            })?;
            pem.contents()
        } else {
            return Err(cluelessh_format::ParseError("invalid SSH key".to_owned()));
        };

        let mut p = Reader::new(content);

        let magic = p.array::<{ MAGIC.len() }>()?;
        if magic != *MAGIC {
            return Err(cluelessh_format::ParseError(
                "invalid magic, not an SSH key?".to_owned(),
            ));
        }

        let ciphername = p.utf8_string()?;
        let cipher = ciphername.parse::<Cipher>()?;
        let kdfname = p.utf8_string()?;
        let kdfoptions = p.string()?;
        let kdf = Kdf::from_str_and_options(kdfname, kdfoptions)?;
        let keynum = p.u32()?;

        let mut public_keys = Vec::new();

        for _ in 0..keynum {
            let pubkey = p.string()?;
            let pubkey = PublicKey::from_wire_encoding(pubkey)?;
            public_keys.push(pubkey);
        }

        let priv_keys = p.string()?;

        Ok(EncryptedPrivateKeys {
            public_keys,
            cipher,
            kdf,
            encrypted_private_keys: priv_keys.to_owned(),
        })
    }

    pub fn to_bytes_armored(&self) -> String {
        let content = self.to_bytes();
        let pem = pem::Pem::new("OPENSSH PRIVATE KEY", content);
        pem::encode(&pem)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut p = Writer::new();
        p.array(*MAGIC);
        p.string(self.cipher.name().as_bytes());
        p.string(self.kdf.name().as_bytes());
        dbg!(self.kdf.options());
        p.string(self.kdf.options());

        p.u32(self.public_keys.len() as u32);

        for pubkey in &self.public_keys {
            p.string(pubkey.to_wire_encoding());
        }

        p.string(&self.encrypted_private_keys);

        p.finish()
    }

    pub fn requires_passphrase(&self) -> bool {
        (!matches!(self.kdf, Kdf::None)) && (!matches!(self.cipher, Cipher::None))
    }

    pub fn decrypt_encrypted_part(
        &self,
        passphrase: Option<&str>,
    ) -> cluelessh_format::Result<Vec<u8>> {
        let mut data = self.encrypted_private_keys.clone();
        if self.requires_passphrase() {
            let Some(passphrase) = passphrase else {
                panic!("missing passphrase for encrypted key");
            };
            if passphrase.is_empty() {
                return Err(cluelessh_format::ParseError(format!("empty passphrase")));
            }

            let (key_size, iv_size) = self.cipher.key_iv_size();

            let mut output = vec![0; key_size + iv_size];
            self.kdf.derive(passphrase, &mut output)?;
            let (key, iv) = output.split_at(key_size);
            self.cipher.crypt_in_place(&mut data, key, iv);
        }
        Ok(data)
    }

    pub fn decrypt(
        &self,
        passphrase: Option<&str>,
    ) -> cluelessh_format::Result<Vec<PlaintextPrivateKey>> {
        let data = self.decrypt_encrypted_part(passphrase)?;

        let mut p = Reader::new(&data);
        let checkint1 = p.u32()?;
        let checkint2 = p.u32()?;
        if checkint1 != checkint2 {
            return Err(cluelessh_format::ParseError(format!(
                "invalid key or password"
            )));
        }

        let mut result_keys = Vec::new();

        for pubkey in &self.public_keys {
            let keytype = match *pubkey {
                PublicKey::Ed25519 { public_key } => {
                    // <https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-eddsa-keys>
                    let alg = p.utf8_string()?;
                    if alg != pubkey.algorithm_name() {
                        return Err(cluelessh_format::ParseError(format!(
                            "algorithm mismatch. pubkey: {}, privkey: {alg}",
                            pubkey.algorithm_name()
                        )));
                    }

                    let enc_a = p.string()?; // ENC(A)
                    if enc_a != public_key.as_bytes() {
                        return Err(cluelessh_format::ParseError(format!("public key mismatch")));
                    }
                    let k_enc_a = p.string()?; // k || ENC(A)
                    if k_enc_a.len() != 64 {
                        return Err(cluelessh_format::ParseError(format!(
                            "invalid len for ed25519 keypair: {}, expected 64",
                            k_enc_a.len()
                        )));
                    }
                    let (k, enc_a) = k_enc_a.split_at(32);
                    if enc_a != public_key.as_bytes() {
                        // Yes, ed25519 SSH keys seriously store the public key THREE TIMES.
                        return Err(cluelessh_format::ParseError(format!("public key mismatch")));
                    }
                    let private_key = k.try_into().unwrap();
                    PrivateKey::Ed25519 {
                        public_key,
                        private_key,
                    }
                }
                PublicKey::EcdsaSha2NistP256 { public_key } => {
                    // <https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-ecdsa-keys>
                    let alg = p.utf8_string()?;
                    if alg != pubkey.algorithm_name() {
                        return Err(cluelessh_format::ParseError(format!(
                            "algorithm mismatch. pubkey: {}, privkey: {alg}",
                            pubkey.algorithm_name()
                        )));
                    }

                    let curve_name = p.utf8_string()?;
                    if curve_name != "nistp256" {
                        return Err(cluelessh_format::ParseError(format!(
                            "curve name mismatch. expected: nistp256, found: {curve_name}",
                        )));
                    }

                    let q = p.string()?;
                    if q != public_key.to_encoded_point(false).as_bytes() {
                        return Err(cluelessh_format::ParseError(format!("public key mismatch")));
                    }

                    let d = p.mpint()?;

                    let private_key = p256::ecdsa::SigningKey::from_slice(d).map_err(|_| {
                        cluelessh_format::ParseError(format!("invalid private key bytes"))
                    })?;

                    PrivateKey::EcdsaSha2NistP256 {
                        public_key,
                        private_key,
                    }
                }
            };

            let comment = p.utf8_string()?;

            result_keys.push(PlaintextPrivateKey {
                private_key: keytype,
                comment: comment.to_owned(),
                checkint: checkint1,
            });
        }

        // verify padding
        for i in 1_u8..=255 {
            if p.has_data() {
                let b = p.u8()?;
                if b != i {
                    return Err(cluelessh_format::ParseError(format!(
                        "private key padding is incorrect: {b} != {i}"
                    )));
                }
            }
        }

        Ok(result_keys)
    }
}

pub struct KeyEncryptionParams {
    pub cipher: Cipher,
    pub kdf: Kdf,
    pub passphrase: Option<String>,
}

impl KeyEncryptionParams {
    pub fn plaintext() -> Self {
        Self {
            cipher: Cipher::None,
            kdf: Kdf::None,
            passphrase: None,
        }
    }
    pub fn secure_encrypted(passphrase: String) -> Self {
        assert!(!passphrase.is_empty());
        Self {
            cipher: Cipher::Aes256Ctr,
            kdf: Kdf::BCrypt {
                salt: rand::random(),
                rounds: 24,
            },
            passphrase: Some(passphrase),
        }
    }

    pub fn same_as_existing(key: &EncryptedPrivateKeys, passphrase: Option<String>) -> Self {
        if passphrase.is_none() {
            assert_eq!(key.cipher, Cipher::None);
            assert_eq!(key.kdf, Kdf::None);
        }
        Self {
            cipher: key.cipher.clone(),
            kdf: key.kdf.clone(),
            passphrase,
        }
    }
}

impl PlaintextPrivateKey {
    pub fn generate(comment: String, params: KeyGenerationParams) -> Self {
        let keytype = crypto::generate_private_key(params);
        Self {
            comment,
            private_key: keytype,
            checkint: rand::random(),
        }
    }

    pub fn encrypt(
        &self,
        params: KeyEncryptionParams,
    ) -> cluelessh_format::Result<EncryptedPrivateKeys> {
        let public_keys = vec![self.private_key.public_key()];

        let mut enc = Writer::new();
        enc.u32(self.checkint);
        enc.u32(self.checkint);

        match &self.private_key {
            PrivateKey::Ed25519 {
                public_key,
                private_key,
            } => {
                // <https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-eddsa-keys>
                enc.string(b"ssh-ed25519");
                enc.string(public_key);
                let combined = private_key.as_bytes().len() + public_key.as_bytes().len();
                enc.u32(combined as u32);
                enc.raw(private_key.as_bytes());
                enc.raw(public_key.as_bytes());
            }
            PrivateKey::EcdsaSha2NistP256 {
                public_key,
                private_key,
            } => {
                // <https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-ecdsa-keys>
                enc.string(self.private_key.algorithm_name());
                enc.string("nistp256");
                enc.string(public_key.to_encoded_point(false));
                enc.mpint(p256::U256::from(private_key.as_nonzero_scalar().as_ref()));
            }
        }

        enc.string(self.comment.as_bytes());

        let current_len = enc.current_length();
        let block_size = params.cipher.block_size();
        let pad_len = current_len.next_multiple_of(block_size) - current_len;

        for i in 1..=(pad_len as u8) {
            enc.u8(i);
        }

        let mut encrypted_private_keys = enc.finish();

        match params.cipher {
            Cipher::None => {}
            Cipher::Aes256Ctr => {
                let (key_size, iv_size) = params.cipher.key_iv_size();

                let mut output = vec![0; key_size + iv_size];
                params
                    .kdf
                    .derive(&params.passphrase.unwrap(), &mut output)?;
                let (key, iv) = output.split_at(key_size);
                params
                    .cipher
                    .crypt_in_place(&mut encrypted_private_keys, key, iv);
            }
        }

        Ok(EncryptedPrivateKeys {
            public_keys,
            cipher: params.cipher,
            kdf: params.kdf,
            encrypted_private_keys,
        })
    }
}

impl PrivateKey {
    pub fn public_key(&self) -> PublicKey {
        match *self {
            Self::Ed25519 { public_key, .. } => PublicKey::Ed25519 { public_key },
            Self::EcdsaSha2NistP256 { public_key, .. } => {
                PublicKey::EcdsaSha2NistP256 { public_key }
            }
        }
    }

    pub fn algorithm_name(&self) -> &'static str {
        self.public_key().algorithm_name()
    }
}

#[cfg(test)]
mod tests {
    use crate::private::{EncryptedPrivateKeys, KeyEncryptionParams, PrivateKey};

    // ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP60Q8iOyatiPeJbpQ8JVoZazukcSwhnKrg+wzw7/JZQ uwu
    // no password
    const TEST_ED25519_NONE: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD+tEPIjsmrYj3iW6UPCVaGWs7pHEsIZyq4PsM8O/yWUAAAAIj6bZmH+m2Z
hwAAAAtzc2gtZWQyNTUxOQAAACD+tEPIjsmrYj3iW6UPCVaGWs7pHEsIZyq4PsM8O/yWUA
AAAEAdSh0yeEtOyIa0mzMH36U77BNkiuQkERT8TVTrOOgPyP60Q8iOyatiPeJbpQ8JVoZa
zukcSwhnKrg+wzw7/JZQAAAAA3V3dQEC
-----END OPENSSH PRIVATE KEY-----
";

    // ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPaiIO6MePXM/QCJWVge1k4dsiefPr4taP9VJbCtXdx uwu
    // Password: 'test'
    const TEST_ED25519_AES256_CTR: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA5S8LoGs
SYFE1uIAlgK4I/AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIHPaiIO6MePXM/QC
JWVge1k4dsiefPr4taP9VJbCtXdxAAAAkB9StlI/JgwhtvDGx7v08RAa76W6aXSgbDJTU/
KNPzv0yXhCRleYltud2W2R3G6lElGKBgLfC6U944U8ZFHQQevQIHeSGPkbLGklTXrrrLl7
ZdWF8er/J/gA0H1T0QE/NYiHxY4NdBzYc4GKCBItOmIT8K/4bsMmh7VXtO0WmkmhoumnLX
rsOKyxcDiMs2J8cg==
-----END OPENSSH PRIVATE KEY-----
";

    // ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHZTdlJoLNb701EWnahywBv032Aby+Piza7TzKW1H6Z//Hni/rBcUgnMmG+Kc4XWp6zgny3FMFpviuL01eJbpY8= uwu
    // no password
    const TEST_ECDSA_SHA2_NISTP256_NONE: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQR2U3ZSaCzW+9NRFp2ocsAb9N9gG8vj
4s2u08yltR+mf/x54v6wXFIJzJhvinOF1qes4J8txTBab4ri9NXiW6WPAAAAoKQV4mmkFe
JpAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHZTdlJoLNb701EW
nahywBv032Aby+Piza7TzKW1H6Z//Hni/rBcUgnMmG+Kc4XWp6zgny3FMFpviuL01eJbpY
8AAAAgVF0Z9J3CtkKpNt2IGTJZtBLK+QQKu/bUkp12gstIonUAAAADdXd1AQIDBAU=
-----END OPENSSH PRIVATE KEY-----";

    // ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEusldR/7TICHafRbJX+30e5st+UbgUP1rBIh/AcnBn9dScaOXWgm8vmUYmth5GpZtLo39kBBKZV8QJe7FXmC8c= uwu
    // password: 'test'
    const TEST_ECDSA_SHA2_NISTP256_AES256_CTR: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCWX6qaxj
miQgsaPGi1IyvYAAAAGAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBEusldR/7TICHafRbJX+30e5st+UbgUP1rBIh/AcnBn9dScaOXWgm8vmUY
mth5GpZtLo39kBBKZV8QJe7FXmC8cAAACgRu/TvP/8rpKdP8krcK4fcCusqyxKsnGa8Auv
Pq9bO01HN5LcaXvDUteDZ9JBMuhVZJkW+8x1y3oNo4dLxcQk2Lor0v9xTB+8Ak0GPZUKPq
f8eMUtjTcN9zoUi67Ho+RIxqN8mYxLy7YDlM54vJ45VhNtcBdoIrQFdrT3QngvZ26Hk6M1
NZ1XxE87G/z54ftU4Nhj9SCIDPNXB5/1xu/6mA==
-----END OPENSSH PRIVATE KEY-----";

    #[track_caller]
    fn roundtrip(keys: &[&[u8]], passphrase: Option<&str>) {
        for key_bytes in keys {
            let key_bytes = pem::parse(key_bytes).unwrap();
            let key_bytes = key_bytes.contents();
            let keys = EncryptedPrivateKeys::parse(&key_bytes).unwrap();
            let decrypted = keys.decrypt(passphrase).unwrap();

            let encrypted = decrypted[0]
                .encrypt(KeyEncryptionParams::same_as_existing(
                    &keys,
                    passphrase.map(ToOwned::to_owned),
                ))
                .unwrap();

            let bytes = encrypted.to_bytes();
            if key_bytes != bytes {
                let _ = std::fs::write("_expected", key_bytes);
                let _ = std::fs::write("_found", &bytes);
            }
            assert_eq!(key_bytes, bytes);
        }
    }

    #[track_caller]
    fn parse_private_key(key: &[u8], password: Option<&str>) -> PrivateKey {
        let keys = EncryptedPrivateKeys::parse(key).unwrap();
        assert_eq!(keys.public_keys.len(), 1);
        let mut decrypted = keys.decrypt(password).unwrap();
        assert_eq!(decrypted.len(), 1);
        let key = decrypted.remove(0);
        key.private_key
    }

    #[test]
    fn ed25519_none() {
        assert!(matches!(
            parse_private_key(TEST_ED25519_NONE, None),
            PrivateKey::Ed25519 { .. }
        ));
    }

    #[test]
    fn ecdsa_sha2_nistp256_none() {
        assert!(matches!(
            parse_private_key(TEST_ECDSA_SHA2_NISTP256_NONE, None),
            PrivateKey::EcdsaSha2NistP256 { .. }
        ));
    }

    #[test]
    fn ed25519_aes256ctr() {
        assert!(matches!(
            parse_private_key(TEST_ED25519_AES256_CTR, Some("test")),
            PrivateKey::Ed25519 { .. }
        ));
    }

    #[test]
    fn roundtrip_ed25519_none() {
        roundtrip(&[TEST_ED25519_NONE], None);
    }

    #[test]
    fn roundtrip_ed25519_aes256_ctr() {
        roundtrip(&[TEST_ED25519_AES256_CTR], Some("test"));
    }

    #[test]
    fn roundtrip_ecdsa_sha2_nistp256_none() {
        roundtrip(&[TEST_ECDSA_SHA2_NISTP256_NONE], None);
    }

    #[test]
    fn roundtrip_ecdsa_sha2_nistp256_aes256_ctr() {
        roundtrip(&[TEST_ECDSA_SHA2_NISTP256_AES256_CTR], Some("test"));
    }
}
