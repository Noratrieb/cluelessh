mod crypto;

use crypto::{Cipher, Kdf};
use ssh_transport::{
    key::PublicKey,
    parse::{self, Parser},
};

pub struct EncryptedPrivateKeys {
    pub public_keys: Vec<PublicKey>,
    pub cipher: Cipher,
    pub kdf: Kdf,
    pub encrypted_private_keys: Vec<u8>,
}

pub struct PlaintextPrivateKey {
    pub private_key: PrivateKeyType,
    pub comment: String,
}

pub enum PrivateKeyType {
    Ed25519 {
        public_key: [u8; 32],
        private_key: [u8; 32],
    },
}

const MAGIC: &[u8; 15] = b"openssh-key-v1\0";

impl EncryptedPrivateKeys {
    /// Parse OpenSSH private keys, either armored or not.
    pub fn parse_unencrypted(content: &[u8]) -> parse::Result<Self> {
        // https://github.com/openssh/openssh-portable/blob/a76a6b85108e3032c8175611ecc5746e7131f876/PROTOCOL.key
        let pem: pem::Pem; // lifetime extension
        let content = if content.starts_with(b"openssh-key-v1") {
            content
        } else if content.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----") {
            pem = pem::parse(content)
                .map_err(|err| parse::ParseError(format!("invalid PEM format: {err}")))?;
            pem.contents()
        } else {
            return Err(parse::ParseError("invalid SSH key".to_owned()));
        };

        let mut p = Parser::new(content);

        let magic = p.array::<{ MAGIC.len() }>()?;
        if magic != *MAGIC {
            return Err(parse::ParseError(
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

    pub fn requires_passphrase(&self) -> bool {
        (!matches!(self.kdf, Kdf::None)) && (!matches!(self.cipher, Cipher::None))
    }

    pub fn parse_private(
        &self,
        passphrase: Option<&str>,
    ) -> parse::Result<Vec<PlaintextPrivateKey>> {
        let mut data = self.encrypted_private_keys.clone();
        if self.requires_passphrase() {
            let Some(passphrase) = passphrase else {
                panic!("missing passphrase for encrypted key");
            };
            if passphrase.is_empty() {
                return Err(parse::ParseError(format!("empty passphrase")));
            }

            let (key_size, iv_size) = self.cipher.key_iv_size();

            let mut output = vec![0; key_size + iv_size];
            self.kdf.derive(passphrase, &mut output)?;
            let (key, iv) = output.split_at(key_size);
            self.cipher.decrypt_in_place(&mut data, &key, &iv);
        }

        let mut p = Parser::new(&data);
        let checkint1 = p.u32()?;
        let checkint2 = p.u32()?;
        if checkint1 != checkint2 {
            return Err(parse::ParseError(format!(
                "failed sanity check, invalid key or password ({checkint1}!={checkint2})"
            )));
        }

        let mut result_keys = Vec::new();

        for pubkey in &self.public_keys {
            let keytype = match pubkey {
                PublicKey::Ed25519 { public_key } => {
                    let alg = p.utf8_string()?;
                    if alg != "ssh-ed25519" {
                        return Err(parse::ParseError(format!(
                            "algorithm mismatch. pubkey: ssh-ed25519, privkey: {alg}"
                        )));
                    }
                    let enc_a = p.string()?; // ENC(A)
                    if enc_a != public_key {
                        return Err(parse::ParseError(format!("public key mismatch")));
                    }
                    let k_enc_a = p.string()?; // k || ENC(A)
                    if k_enc_a.len() != 64 {
                        return Err(parse::ParseError(format!(
                            "invalid len for ed25519 keypair: {}, expected 64",
                            k_enc_a.len()
                        )));
                    }
                    let (k, enc_a) = k_enc_a.split_at(32);
                    if enc_a != public_key {
                        // Yes, ed25519 SSH keys seriously store the public key THREE TIMES.
                        return Err(parse::ParseError(format!("public key mismatch")));
                    }
                    let private_key = k.try_into().unwrap();
                    PrivateKeyType::Ed25519 {
                        public_key: *public_key,
                        private_key,
                    }
                }
            };

            let comment = p.utf8_string()?;

            result_keys.push(PlaintextPrivateKey {
                private_key: keytype,
                comment: comment.to_owned(),
            });
        }

        // verify padding
        for i in 1_u8..=255 {
            if p.has_data() {
                let b = p.u8()?;
                if b != i {
                    return Err(parse::ParseError(format!(
                        "private key padding is incorrect: {b} != {i}"
                    )));
                }
            }
        }

        Ok(result_keys)
    }
}

impl PrivateKeyType {
    pub fn public_key(&self) -> PublicKey {
        match *self {
            Self::Ed25519 { public_key, .. } => PublicKey::Ed25519 { public_key },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Cipher, EncryptedPrivateKeys, Kdf, PrivateKeyType};

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

    #[test]
    fn ed25519_none() {
        let keys = EncryptedPrivateKeys::parse_unencrypted(TEST_ED25519_NONE).unwrap();
        assert_eq!(keys.public_keys.len(), 1);
        assert_eq!(keys.cipher, Cipher::None);
        assert_eq!(keys.kdf, Kdf::None);

        let decrypted = keys.parse_private(None).unwrap();
        assert_eq!(decrypted.len(), 1);
        let key = decrypted.first().unwrap();
        assert_eq!(key.comment, "uwu");
        assert!(matches!(key.private_key, PrivateKeyType::Ed25519 { .. }));
    }

    #[test]
    fn ed25519_aes256ctr() {
        let keys = EncryptedPrivateKeys::parse_unencrypted(TEST_ED25519_AES256_CTR).unwrap();
        assert_eq!(keys.public_keys.len(), 1);
        assert_eq!(keys.cipher, Cipher::Aes256Ctr);
        assert!(matches!(keys.kdf, Kdf::BCrypt { .. }));

        let decrypted = keys.parse_private(Some("test")).unwrap();
        assert_eq!(decrypted.len(), 1);
        let key = decrypted.first().unwrap();
        assert_eq!(key.comment, "uwu");
        assert!(matches!(key.private_key, PrivateKeyType::Ed25519 { .. }));
    }
}
