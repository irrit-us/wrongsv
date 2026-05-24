//! NIST ML-KEM (FIPS 203) key encapsulation — post-quantum session-key establishment.
//!
//! Wraps the audited RustCrypto `ml-kem` crate. The shared secret produced by
//! encapsulate/decapsulate is a 32-byte value suitable as a master key for
//! `AeadKey::new()` in the encryption crate.
//!
//! Default parameter set is ML-KEM-512:
//!   pk=800, sk_seed=64, ct=768, ss=32 bytes
//!
//! Secret keys are stored as 64-byte seeds (not the legacy 1632-byte expanded form).

use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem512};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KyberLevel {
    Level512,
}

#[derive(Debug, Error)]
pub enum KyberError {
    #[error("invalid public key: expected {expected} bytes, got {got}")]
    InvalidPublicKey { expected: usize, got: usize },
    #[error("invalid secret key seed: expected {expected} bytes, got {got}")]
    InvalidSecretKey { expected: usize, got: usize },
    #[error("invalid ciphertext: expected {expected} bytes, got {got}")]
    InvalidCiphertext { expected: usize, got: usize },
    #[error("decapsulation failed")]
    DecapsFailed,
}

/// Key sizes for ML-KEM-512.
pub const PK_SIZE: usize = 800;
pub const SK_SEED_SIZE: usize = 64;
pub const CT_SIZE: usize = 768;
pub const SS_SIZE: usize = 32;

/// A generated Kyber keypair.
#[derive(Debug, Clone)]
pub struct KyberKeypair {
    pub pk: Vec<u8>,
    /// 64-byte seed (compact form, not expanded).
    pub sk: Vec<u8>,
}

/// Generate a fresh ML-KEM-512 keypair using system RNG.
pub fn generate_keypair() -> KyberKeypair {
    let (dk, ek) = MlKem512::generate_keypair();
    KyberKeypair {
        pk: ek.to_bytes().as_slice().to_vec(),
        sk: dk.to_seed().expect("key generated from seed").as_slice().to_vec(),
    }
}

/// Encapsulate a shared secret against a public key.
/// Returns (ciphertext, shared_secret).
pub fn encapsulate(pk: &[u8]) -> Result<(Vec<u8>, [u8; SS_SIZE]), KyberError> {
    if pk.len() != PK_SIZE {
        return Err(KyberError::InvalidPublicKey {
            expected: PK_SIZE,
            got: pk.len(),
        });
    }
    let ek = EncapsulationKey::<MlKem512>::new(
        #[allow(deprecated)]
        ml_kem::kem::Key::<EncapsulationKey<MlKem512>>::from_slice(pk),
    )
    .map_err(|_| KyberError::DecapsFailed)?;

    let (ct, ss) = ek.encapsulate();
    let mut ss_arr = [0u8; SS_SIZE];
    ss_arr.copy_from_slice(ss.as_slice());
    Ok((ct.as_slice().to_vec(), ss_arr))
}

/// Decapsulate a shared secret using a 64-byte seed and ciphertext.
pub fn decapsulate(sk_seed: &[u8], ct: &[u8]) -> Result<[u8; SS_SIZE], KyberError> {
    if sk_seed.len() != SK_SEED_SIZE {
        return Err(KyberError::InvalidSecretKey {
            expected: SK_SEED_SIZE,
            got: sk_seed.len(),
        });
    }
    if ct.len() != CT_SIZE {
        return Err(KyberError::InvalidCiphertext {
            expected: CT_SIZE,
            got: ct.len(),
        });
    }
    #[allow(deprecated)]
    let seed = ml_kem::Seed::from_slice(sk_seed);
    let ct_arr = ml_kem::kem::Ciphertext::<MlKem512>::try_from(ct).map_err(|_| KyberError::DecapsFailed)?;
    let dk = DecapsulationKey::<MlKem512>::from_seed(*seed);
    let ss = dk.decapsulate(&ct_arr);
    let mut ss_arr = [0u8; SS_SIZE];
    ss_arr.copy_from_slice(ss.as_slice());
    Ok(ss_arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_encapsulate_decapsulate_roundtrip() {
        let kp = generate_keypair();
        assert_eq!(kp.pk.len(), PK_SIZE);
        assert_eq!(kp.sk.len(), SK_SEED_SIZE);

        let (ct, ss_enc) = encapsulate(&kp.pk).unwrap();
        assert_eq!(ct.len(), CT_SIZE);

        let ss_dec = decapsulate(&kp.sk, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_wrong_ciphertext_produces_different_result() {
        let kp = generate_keypair();
        let kp2 = generate_keypair();

        let (ct2, _) = encapsulate(&kp2.pk).unwrap();
        let (ct1, ss_right) = encapsulate(&kp.pk).unwrap();

        // Decapsulating ct2 with kp's sk produces a different shared secret
        let ss_wrong = decapsulate(&kp.sk, &ct2).unwrap();
        assert_ne!(ss_wrong, ss_right);

        // Correct ct decapsulates correctly
        let ss_good = decapsulate(&kp.sk, &ct1).unwrap();
        assert_eq!(ss_good, ss_right);
    }

    #[test]
    fn test_invalid_key_sizes_rejected() {
        assert!(encapsulate(&[0u8; 10]).is_err());
        assert!(decapsulate(&[0u8; 10], &[0u8; CT_SIZE]).is_err());
        assert!(decapsulate(&[0u8; SK_SEED_SIZE], &[0u8; 10]).is_err());
    }

    #[test]
    fn test_generated_keys_are_different() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        assert_ne!(kp1.pk, kp2.pk);
        assert_ne!(kp1.sk, kp2.sk);
    }

    #[test]
    fn test_seed_roundtrip() {
        let kp = generate_keypair();
        let seed = kp.sk;
        #[allow(deprecated)]
        let dk = DecapsulationKey::<MlKem512>::from_seed(*ml_kem::Seed::from_slice(&seed));
        let ek = dk.encapsulation_key().clone();
        let (ct, ss_enc) = ek.encapsulate();
        let ss_dec = dk.decapsulate(&ct);
        assert_eq!(ss_enc, ss_dec);
    }
}
