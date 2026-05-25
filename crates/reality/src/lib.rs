//! REALITY protocol — TLS 1.3 handshake hijacking for VLESS proxy.
//!
//! Intercepts the TLS ClientHello at the TCP layer, extracts REALITY auth
//! data from the SessionID field, performs X25519 ECDH + HKDF key derivation,
//! verifies the client, then generates a dynamic self-signed certificate to
//! complete the handshake. Unauthenticated connections are forwarded to a
//! real target (spider mode) for active probe resistance.

mod auth;
mod cert;
mod hello;
mod tls;

pub use auth::compute_cert_hmac;
pub use cert::generate_reality_cert;
pub use hello::ParsedClientHello;
pub use tls::{accept_reality, complete_handshake, BufferedStream, RealityTlsStream};

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

/// Server-side REALITY configuration.
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// X25519 private key (32 bytes)
    pub private_key: [u8; 32],
    /// Allowed short IDs (8 bytes each)
    pub short_ids: Vec<[u8; 8]>,
    /// Maximum allowed clock skew in seconds
    pub max_time_diff: u64,
}
