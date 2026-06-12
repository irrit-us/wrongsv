//! REALITY protocol — TLS 1.3 handshake hijacking for VLESS proxy.
//!
//! Intercepts the TLS ClientHello at the TCP layer, extracts REALITY auth
//! data from the SessionID field, performs X25519 ECDH + HKDF key derivation,
//! verifies the client, then generates a dynamic self-signed certificate to
//! complete the handshake. Unauthenticated connections are forwarded to a
//! real target (spider mode) for active probe resistance.

mod auth;
pub mod cert;
mod hello;
mod tls;

pub use auth::{build_session_id, compute_cert_hmac, derive_client_auth_key};
pub use cert::generate_reality_cert;
pub use hello::{ParsedClientHello, build_reality_client_hello};
pub use tls::{
    BufferedStream, RealityTlsStream, accept_reality, complete_handshake, spider_fallback,
};

use std::net::TcpStream;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RealityError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS parse error: {0}")]
    TlsParse(String),
    #[error("auth failed: {0}")]
    AuthFailed(String),
    #[error("cert generation failed: {0}")]
    CertError(String),
    #[error("TLS handshake error: {0}")]
    TlsHandshake(String),
}

/// Returned when `accept_reality` fails authentication.
///
/// Carries the original stream and buffered ClientHello bytes so the
/// caller can forward them to a fallback destination (spider mode).
#[derive(Debug)]
pub struct RealityAcceptError {
    pub error: RealityError,
    pub stream: TcpStream,
    pub buffered_data: Vec<u8>,
}

impl std::fmt::Display for RealityAcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "REALITY accept failed: {}", self.error)
    }
}

impl std::error::Error for RealityAcceptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Pre-generated Ed25519 certificate material shared across all connections.
///
/// Matches Xray-core's approach: one keypair generated at startup, with
/// the DER certificate template cloned per connection and its trailing
/// 64-byte signature field overwritten with HMAC-SHA512(auth_key, raw_pubkey).
#[derive(Debug, Clone)]
pub struct RealityCertMaterial {
    /// DER-encoded certificate template (self-signed Ed25519 cert).
    pub cert_template_der: Vec<u8>,
    /// Raw 32-byte Ed25519 public key (not DER-encoded).
    pub raw_pubkey: [u8; 32],
    /// PKCS#8 DER-encoded Ed25519 private key for TLS signing.
    pub signing_key_der: Vec<u8>,
}

/// Server-side REALITY configuration.
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// X25519 private key (32 bytes)
    pub private_key: [u8; 32],
    /// Allowed short IDs (4 bytes / 8 hex chars each)
    pub short_ids: Vec<[u8; 4]>,
    /// Maximum allowed clock skew in seconds
    pub max_time_diff: u64,
    /// Pre-generated cert material (shared across connections)
    pub cert_material: Arc<RealityCertMaterial>,
    /// Fallback destination for spider mode (e.g. "www.microsoft.com:443").
    /// When set, unauthenticated connections are forwarded here instead of dropped.
    pub dest: Option<String>,
}

/// Derive the base64-encoded X25519 public key from a hex-encoded private key.
/// Used for generating client config.
pub fn private_key_hex_to_public_b64(hex_sk: &str) -> Result<String, String> {
    let bytes = (0..hex_sk.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_sk[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| format!("invalid hex private key: {e}"))?;
    let sk: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "private key must be 32 bytes")?;
    let pk = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(sk));
    use base64::Engine;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk.as_bytes()))
}

impl RealityConfig {
    pub fn new(
        private_key: [u8; 32],
        short_ids: Vec<[u8; 4]>,
        max_time_diff: u64,
        cert_material: RealityCertMaterial,
        dest: Option<String>,
    ) -> Self {
        RealityConfig {
            private_key,
            short_ids,
            max_time_diff,
            cert_material: Arc::new(cert_material),
            dest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_key_hex_to_public_b64_roundtrip() {
        // Generate a known keypair
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pk = x25519_dalek::PublicKey::from(&sk);
        let expected_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk.as_bytes())
        };

        let sk_hex: String = sk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let computed_b64 = private_key_hex_to_public_b64(&sk_hex).unwrap();
        assert_eq!(computed_b64, expected_b64);
    }

    #[test]
    fn test_private_key_hex_to_public_b64_invalid_hex() {
        assert!(private_key_hex_to_public_b64("not-hex").is_err());
    }

    #[test]
    fn test_private_key_hex_to_public_b64_wrong_length() {
        assert!(private_key_hex_to_public_b64("aabbccdd").is_err());
    }
}
