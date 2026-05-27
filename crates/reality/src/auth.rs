//! REALITY authentication engine.
//!
//! X25519 ECDH + HKDF-SHA256 key derivation + AES-GCM SessionID decryption + verification.
//!
//! SessionID (32 bytes): AES-GCM encrypted payload containing version, reserved,
//! timestamp, and short_id. Decrypted with auth_key derived from X25519 ECDH.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::Mac;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::hello::ParsedClientHello;
use crate::{RealityConfig, RealityError};

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

/// Derive REALITY auth key via X25519 ECDH + HKDF-SHA256.
fn derive_auth_key(
    server_sk: &StaticSecret,
    client_key_share: &[u8; 32],
    client_random: &[u8; 32],
) -> Result<Vec<u8>, RealityError> {
    let server_pk = x25519_dalek::PublicKey::from(server_sk);
    let client_pub = PublicKey::from(*client_key_share);
    let shared_secret = server_sk.diffie_hellman(&client_pub);

    let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret.as_bytes());
    let mut auth_key = vec![0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key)
        .map_err(|e| RealityError::AuthFailed(format!("HKDF expand: {e}")))?;
    tracing::debug!(
        "REALITY auth: server_pk={} client_ks={} auth_key={}",
        server_pk
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        client_key_share
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        auth_key
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    Ok(auth_key)
}

/// Decrypt the entire 32-byte SessionID and verify its payload.
///
/// Returns (version, timestamp, short_id) on success.
fn decrypt_session_id(
    auth_key: &[u8],
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    aad: &[u8],
) -> Result<([u8; 3], u32, [u8; 4]), RealityError> {
    let key = Key::<Aes256Gcm>::from_slice(auth_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&client_random[20..32]);

    // The full 32-byte session_id is ciphertext (16) + tag (16)
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: session_id as &[u8],
                aad,
            },
        )
        .map_err(|_| RealityError::AuthFailed("AES-GCM decryption failed".into()))?;

    if plaintext.len() < 16 {
        return Err(RealityError::AuthFailed(
            "decrypted payload too short".into(),
        ));
    }

    let mut version = [0u8; 3];
    version.copy_from_slice(&plaintext[0..3]);
    let reserved = plaintext[3];
    let timestamp = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
    let mut short_id = [0u8; 4];
    short_id.copy_from_slice(&plaintext[8..12]);

    if reserved != 0 {
        return Err(RealityError::AuthFailed("reserved byte must be 0".into()));
    }

    Ok((version, timestamp, short_id))
}

/// Verify timestamp is within max_time_diff seconds of now.
fn verify_timestamp(timestamp: u32, max_time_diff: u64) -> Result<(), RealityError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| RealityError::AuthFailed(format!("clock: {e}")))?
        .as_secs();

    let diff = now.abs_diff(timestamp as u64);

    if diff > max_time_diff {
        return Err(RealityError::AuthFailed(format!(
            "timestamp out of range: diff={diff}s, max={max_time_diff}s"
        )));
    }
    Ok(())
}

/// Verify short_id is in the allow-list.
fn verify_short_id(short_id: &[u8; 4], short_ids: &[[u8; 4]]) -> Result<(), RealityError> {
    if short_ids.iter().any(|id| id == short_id) {
        Ok(())
    } else {
        Err(RealityError::AuthFailed(
            "short_id not in allow-list".into(),
        ))
    }
}

/// Run full REALITY authentication on a parsed ClientHello.
///
/// Returns the derived auth_key for downstream use (cert HMAC computation).
pub fn authenticate(
    hello: &ParsedClientHello,
    config: &RealityConfig,
) -> Result<Vec<u8>, RealityError> {
    let server_sk = StaticSecret::from(config.private_key);

    let auth_key = derive_auth_key(&server_sk, &hello.key_share, &hello.random)?;

    // AAD is the ClientHello body with the session_id zeroed out.

    // AAD is the ClientHello body with the session_id zeroed out.
    // Both client and server agree on this so the session_id content doesn't affect AAD.
    let mut aad = hello.raw_body.clone();
    // session_id is at offset 39 within the ClientHello body
    // (handshake_type(1) + len(3) + version(2) + random(32) + sid_len(1))
    let sid_start = 39;
    if aad.len() >= sid_start + 32 {
        aad[sid_start..sid_start + 32].fill(0);
    }

    let (_version, timestamp, short_id) =
        decrypt_session_id(&auth_key, &hello.random, &hello.session_id, &aad)?;

    verify_timestamp(timestamp, config.max_time_diff)?;
    verify_short_id(&short_id, &config.short_ids)?;

    Ok(auth_key)
}

/// HMAC-SHA512 for REALITY cert verification.
///
/// Both server and client compute `HMAC-SHA512(auth_key, raw_pubkey)` where
/// `raw_pubkey` is the 32-byte raw Ed25519 public key (not DER-encoded).
/// The server writes this into the cert's trailing 64-byte signature field;
/// the client compares it against `cert.Signature`.
pub fn compute_cert_hmac(auth_key: &[u8], raw_pubkey: &[u8; 32]) -> Result<Vec<u8>, RealityError> {
    let mut mac = <HmacSha512 as KeyInit>::new_from_slice(auth_key)
        .map_err(|e| RealityError::AuthFailed(format!("hmac key: {e}")))?;
    mac.update(raw_pubkey);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    /// Build encrypted session_id for testing (client side).
    fn build_session_id(
        auth_key: &[u8],
        client_random: &[u8; 32],
        timestamp: u32,
        short_id: &[u8; 4],
        aad: &[u8],
    ) -> [u8; 32] {
        let version = [1u8, 2, 3];
        let mut plaintext = vec![0u8; 16];
        plaintext[0..3].copy_from_slice(&version);
        plaintext[3] = 0; // reserved
        plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
        plaintext[8..12].copy_from_slice(short_id);
        // bytes 12..16 are padding zeros

        let key = Key::<Aes256Gcm>::from_slice(auth_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&client_random[20..32]);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad,
                },
            )
            .unwrap();

        let mut sid = [0u8; 32];
        sid.copy_from_slice(&ct); // ct is 32 bytes (16 msg + 16 tag)
        sid
    }

    #[test]
    fn test_auth_roundtrip() {
        let server_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let server_pk = PublicKey::from(&server_sk);

        let client_ephemeral_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let client_ephemeral_pk = PublicKey::from(&client_ephemeral_sk);

        let shared_secret = client_ephemeral_sk.diffie_hellman(&server_pk);
        let mut client_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_random);

        let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret.as_bytes());
        let mut auth_key = vec![0u8; 32];
        hkdf.expand(b"REALITY", &mut auth_key).unwrap();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let short_id = *b"test";

        let aad = b"fake_client_hello_raw";
        let session_id = build_session_id(&auth_key, &client_random, timestamp, &short_id, aad);

        let hello = ParsedClientHello {
            raw_body: aad.to_vec(),
            random: client_random,
            session_id,
            key_share: *client_ephemeral_pk.as_bytes(),
        };

        let config = test_config(server_sk.to_bytes(), vec![short_id], 300);

        let derived_auth_key = authenticate(&hello, &config).unwrap();
        assert_eq!(auth_key, derived_auth_key);
    }

    #[test]
    fn test_wrong_short_id_rejected() {
        let server_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let server_pk = PublicKey::from(&server_sk);
        let client_ephemeral_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let client_ephemeral_pk = PublicKey::from(&client_ephemeral_sk);
        let shared_secret = client_ephemeral_sk.diffie_hellman(&server_pk);

        let mut client_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_random);

        let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret.as_bytes());
        let mut auth_key = vec![0u8; 32];
        hkdf.expand(b"REALITY", &mut auth_key).unwrap();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let short_id = *b"test";

        let aad = b"fake_aad1";
        let session_id = build_session_id(&auth_key, &client_random, timestamp, &short_id, aad);

        let hello = ParsedClientHello {
            raw_body: aad.to_vec(),
            random: client_random,
            session_id,
            key_share: *client_ephemeral_pk.as_bytes(),
        };

        let config = test_config(server_sk.to_bytes(), vec![*b"nope"], 300);

        assert!(authenticate(&hello, &config).is_err());
    }

    #[test]
    fn test_expired_timestamp_rejected() {
        let server_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let server_pk = PublicKey::from(&server_sk);
        let client_ephemeral_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let client_ephemeral_pk = PublicKey::from(&client_ephemeral_sk);
        let shared_secret = client_ephemeral_sk.diffie_hellman(&server_pk);

        let mut client_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_random);

        let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret.as_bytes());
        let mut auth_key = vec![0u8; 32];
        hkdf.expand(b"REALITY", &mut auth_key).unwrap();

        let timestamp = 0u32;
        let short_id = *b"test";

        let aad = b"fake_aad2";
        let session_id = build_session_id(&auth_key, &client_random, timestamp, &short_id, aad);

        let hello = ParsedClientHello {
            raw_body: aad.to_vec(),
            random: client_random,
            session_id,
            key_share: *client_ephemeral_pk.as_bytes(),
        };

        let config = test_config(server_sk.to_bytes(), vec![short_id], 60);

        assert!(authenticate(&hello, &config).is_err());
    }

    fn test_config(
        private_key: [u8; 32],
        short_ids: Vec<[u8; 4]>,
        max_time_diff: u64,
    ) -> RealityConfig {
        RealityConfig::new(
            private_key,
            short_ids,
            max_time_diff,
            crate::cert::build_cert_material().unwrap(),
            None,
        )
    }
}
