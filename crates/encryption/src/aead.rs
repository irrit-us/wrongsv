use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use generic_array::GenericArray;
use typenum::U12;

/// AEAD wrapper supporting AES-256-GCM and ChaCha20-Poly1305.
pub enum Cipher {
    AesGcm(Box<Aes256Gcm>),
    ChaCha(ChaCha20Poly1305),
}

/// Derive a 32-byte key from context + master key using BLAKE3 KDF.
fn derive_key(context: &str, key: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, key)
}

pub struct AeadKey {
    cipher: Cipher,
    nonce: [u8; 12],
}

impl AeadKey {
    pub fn new(context: &str, key: &[u8], use_aes: bool) -> Self {
        let derived = derive_key(context, key);
        let cipher = if use_aes {
            let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&derived);
            Cipher::AesGcm(Box::new(Aes256Gcm::new(aes_key)))
        } else {
            let chacha_key = chacha20poly1305::Key::from_slice(&derived);
            Cipher::ChaCha(ChaCha20Poly1305::new(chacha_key))
        };
        AeadKey {
            cipher,
            nonce: [0u8; 12],
        }
    }

    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AeadError> {
        let nonce = self.increment_nonce();
        let nonce_array = GenericArray::<u8, U12>::from_slice(&nonce);
        match &self.cipher {
            Cipher::AesGcm(aes) => aes
                .encrypt(
                    nonce_array,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| AeadError::EncryptFailed),
            Cipher::ChaCha(chacha) => chacha
                .encrypt(
                    nonce_array,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| AeadError::EncryptFailed),
        }
    }

    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AeadError> {
        let nonce = self.increment_nonce();
        let nonce_array = GenericArray::<u8, U12>::from_slice(&nonce);
        match &self.cipher {
            Cipher::AesGcm(aes) => aes
                .decrypt(
                    nonce_array,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| AeadError::DecryptFailed),
            Cipher::ChaCha(chacha) => chacha
                .decrypt(
                    nonce_array,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| AeadError::DecryptFailed),
        }
    }

    fn increment_nonce(&mut self) -> [u8; 12] {
        let current = self.nonce;
        for i in (0..12).rev() {
            self.nonce[i] = self.nonce[i].wrapping_add(1);
            if self.nonce[i] != 0 {
                break;
            }
        }
        current
    }

    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }
}

pub const MAX_NONCE: [u8; 12] = [0xff; 12];

#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    #[error("decryption failed")]
    DecryptFailed,
    #[error("encryption failed")]
    EncryptFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_seal_open_roundtrip() {
        let key = b"0123456789abcdef0123456789abcdef";
        // Separate instances for encrypt and decrypt (each starts at nonce[0])
        let mut enc = AeadKey::new("test", key, true);
        let mut dec = AeadKey::new("test", key, true);

        let plaintext = b"hello world, this is a test message";
        let ct = enc.seal(plaintext, b"").unwrap();
        let recovered = dec.open(&ct, b"").unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_nonce_increments() {
        let key = b"0123456789abcdef0123456789abcdef";
        let mut aead = AeadKey::new("test", key, true);

        let n0 = *aead.nonce();
        aead.seal(b"msg1", b"").unwrap();
        let n1 = *aead.nonce();
        assert_ne!(n0, n1);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let key2 = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut enc = AeadKey::new("test", key1, true);
        let mut dec = AeadKey::new("test", key2, true);

        let ct = enc.seal(b"hello", b"").unwrap();
        assert!(dec.open(&ct, b"").is_err());
    }
}
