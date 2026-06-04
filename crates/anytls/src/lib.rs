//! AnyTLS protocol — TLS disguise with password authentication.
//!
//! Wraps VLESS traffic in a standard TLS 1.2/1.3 connection with SHA-256
//! password authentication and configurable padding. Unauthenticated
//! connections are forwarded to a fallback destination for active probe
//! resistance.
//!
//! ## Protocol (mirrors anytls-go wire format)
//!
//! After the TLS handshake completes, the client sends an authentication
//! frame as the first application data:
//!
//! ```text
//! SHA256(password) || padding_len(u16 BE) || random_padding
//! ```
//!
//! If the hash matches, the connection proceeds to VLESS relay. Otherwise
//! the connection is forwarded to the fallback destination.
//!
//! ## Differences from REALITY
//!
//! - AnyTLS uses a standard TLS handshake (no ClientHello hijacking)
//! - Authentication is SHA-256 password, not X25519 ECDH
//! - No dynamic certificate generation needed
//! - Simpler: static TLS cert + password check + optional padding

mod auth;
mod padding;
pub mod session;
pub mod socks;
pub mod stream;

use std::io::{Read, Result as IoResult, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::ServerConfig;

pub use auth::verify_password_hash;
pub use padding::PaddingScheme;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnyTlsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("auth failed")]
    AuthFailed,
}

/// Returned when AnyTLS authentication fails.
///
/// Carries the TLS stream and any buffered data so the caller can forward
/// them to a fallback destination.
#[derive(Debug)]
pub struct AnyTlsAcceptError {
    pub error: AnyTlsError,
    pub stream: TcpStream,
    pub buffered_data: Vec<u8>,
}

impl std::fmt::Display for AnyTlsAcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnyTLS accept failed: {}", self.error)
    }
}

impl std::error::Error for AnyTlsAcceptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Server-side AnyTLS configuration.
#[derive(Clone)]
pub struct AnyTlsConfig {
    /// SHA-256 hash of the password (32 bytes)
    pub password_sha256: [u8; 32],
    /// TLS server config (static certificate, no client auth)
    pub tls_config: Arc<ServerConfig>,
    /// Fallback destination (e.g. "127.0.0.1:8080")
    pub dest: Option<String>,
    /// Optional padding scheme (defaults to nil — no padding)
    pub padding_scheme: Option<PaddingScheme>,
}

/// A TLS connection that has completed the AnyTLS handshake.
///
/// Wraps a `rustls::ServerConnection` over a TCP stream. Read/Write
/// delegates to the inner TLS session.
pub struct AnyTlsStream {
    conn: rustls::ServerConnection,
    stream: TcpStream,
}

impl AnyTlsStream {
    /// Construct an `AnyTlsStream` from an already-handshaked TLS connection.
    pub fn from_parts(conn: rustls::ServerConnection, stream: TcpStream) -> Self {
        Self { conn, stream }
    }

    pub fn get_mut(&mut self) -> (&mut rustls::ServerConnection, &mut TcpStream) {
        (&mut self.conn, &mut self.stream)
    }

    /// Consume the stream, returning the inner TLS connection and TCP stream.
    pub fn into_parts(self) -> (rustls::ServerConnection, TcpStream) {
        (self.conn, self.stream)
    }
}

impl Read for AnyTlsStream {
    /// Non-blocking read. Returns `WouldBlock` when no plaintext is available,
    /// so callers layered behind `Arc<Mutex<>>` don't hold the lock while
    /// waiting. The Vision relay threads handle WouldBlock retry themselves.
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        // Try plaintext first
        match self.conn.reader().read(buf) {
            Ok(n) if n > 0 => return Ok(n),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
            _ => {}
        }

        // No plaintext — pull more from TCP
        match self.conn.read_tls(&mut self.stream) {
            Ok(0) => return Ok(0),
            Ok(_) => {
                self.conn
                    .process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "TLS would block",
                ));
            }
            Err(e) => return Err(e),
        }

        // Try again after processing
        match self.conn.reader().read(buf) {
            Ok(0) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "no plaintext",
            )),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "no plaintext",
            )),
            other => other,
        }
    }
}

impl Write for AnyTlsStream {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.conn.writer().write(buf)?;
        self.flush()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        while self.conn.wants_write() {
            let n = self.conn.write_tls(&mut self.stream)?;
            if n == 0 {
                break;
            }
        }
        Ok(())
    }
}

/// Accept an AnyTLS connection on a raw TCP stream.
///
/// 1. Completes TLS handshake
/// 2. Reads auth frame: SHA256(password) + padding_len + padding
/// 3. Verifies password hash
/// 4. Returns `AnyTlsStream` ready for protocol detection
///
/// On auth failure, returns `Err(AnyTlsAcceptError)` for fallback forwarding.
///
/// Protocol variant detected after AnyTLS auth.
#[derive(Debug, PartialEq)]
pub enum PostAuthProtocol {
    /// Standard VLESS header follows (version byte 0x00).
    Vless,
    /// sing-anytls session protocol follows (cmdSettings 0x04).
    SingAnyTls,
}

/// Read the first post-auth byte to determine which protocol the client uses.
///
/// Returns the protocol variant and the first byte already read. The caller
/// should pass this byte to the appropriate protocol handler.
///
/// On WouldBlock, pulls more data from the TLS stream.
pub fn detect_post_auth_protocol(
    conn: &mut rustls::ServerConnection,
    stream: &mut TcpStream,
) -> Result<(PostAuthProtocol, u8), AnyTlsError> {
    let mut first_byte = [0u8; 1];
    tls_read_exact(conn, stream, &mut first_byte)?;
    let proto = match first_byte[0] {
        session::CMD_SETTINGS => PostAuthProtocol::SingAnyTls,
        _ => PostAuthProtocol::Vless,
    };
    Ok((proto, first_byte[0]))
}

/// Accept an AnyTLS connection on a raw TCP stream.
pub fn accept_anytls(
    mut stream: TcpStream,
    config: &AnyTlsConfig,
) -> Result<AnyTlsStream, AnyTlsAcceptError> {
    let mut conn = match rustls::ServerConnection::new(Arc::clone(&config.tls_config)) {
        Ok(c) => c,
        Err(e) => {
            return Err(AnyTlsAcceptError {
                error: AnyTlsError::Tls(format!("create connection: {e}")),
                stream,
                buffered_data: Vec::new(),
            });
        }
    };

    match complete_tls_handshake(&mut conn, &mut stream) {
        Ok(()) => {}
        Err(e) => {
            return Err(AnyTlsAcceptError {
                error: e,
                stream,
                buffered_data: Vec::new(),
            });
        }
    }

    // Read exactly 34 bytes: 32B hash + 2B padding_len.
    // Use read-exact semantics so pipelined VLESS header data stays in the
    // TLS plaintext buffer for the handler.
    let mut header = [0u8; 34];
    if let Err(e) = tls_read_exact(&mut conn, &mut stream, &mut header) {
        return Err(AnyTlsAcceptError {
            error: e,
            stream,
            buffered_data: header.to_vec(),
        });
    }

    let received_hash: [u8; 32] = header[..32].try_into().unwrap();
    if !auth::verify_password_hash(received_hash, config.password_sha256) {
        return Err(AnyTlsAcceptError {
            error: AnyTlsError::AuthFailed,
            stream,
            buffered_data: header.to_vec(),
        });
    }

    let padding_len = u16::from_be_bytes([header[32], header[33]]) as usize;

    // Consume the padding bytes without disturbing the TLS plaintext buffer
    // more than necessary. Read one byte at a time — padding is small.
    let mut byte = [0u8; 1];
    for _ in 0..padding_len {
        if let Err(e) = tls_read_exact(&mut conn, &mut stream, &mut byte) {
            return Err(AnyTlsAcceptError {
                error: e,
                stream,
                buffered_data: Vec::new(),
            });
        }
    }

    tracing::info!(
        "AnyTLS auth OK from {}, padding={padding_len}B",
        stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    );

    Ok(AnyTlsStream { conn, stream })
}

/// Complete the TLS 1.2/1.3 handshake on a raw TCP stream.
fn complete_tls_handshake(
    conn: &mut rustls::ServerConnection,
    stream: &mut TcpStream,
) -> Result<(), AnyTlsError> {
    loop {
        match conn.complete_io(stream) {
            Ok((_, _)) if !conn.is_handshaking() => return Ok(()),
            Ok(_) => continue,
            Err(e) => return Err(AnyTlsError::Tls(format!("handshake: {e}"))),
        }
    }
}

/// Read exactly `buf.len()` bytes of decrypted data from the TLS session.
pub(crate) fn tls_read_exact(
    conn: &mut rustls::ServerConnection,
    stream: &mut TcpStream,
    buf: &mut [u8],
) -> Result<(), AnyTlsError> {
    let mut pos = 0;
    while pos < buf.len() {
        match conn.reader().read(&mut buf[pos..]) {
            Ok(0) => match conn.read_tls(stream) {
                Ok(0) => {
                    return Err(
                        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "TLS EOF").into(),
                    );
                }
                Ok(_) => {
                    conn.process_new_packets()
                        .map_err(|e| AnyTlsError::Tls(format!("process: {e}")))?;
                    continue;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => return Err(e.into()),
            },
            Ok(n) => pos += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                match conn.read_tls(stream) {
                    Ok(0) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "TLS EOF",
                        )
                        .into());
                    }
                    Ok(_) => {
                        conn.process_new_packets()
                            .map_err(|e| AnyTlsError::Tls(format!("process: {e}")))?;
                        continue;
                    }
                    Err(ref e2) if e2.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e2) => return Err(e2.into()),
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Build a TLS `ServerConfig` from PEM-encoded certificate and key.
pub fn build_tls_config(cert_pem: &str, key_pem: &str) -> Result<ServerConfig, AnyTlsError> {
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AnyTlsError::Tls(format!("parse cert: {e}")))?;
    if certs.is_empty() {
        return Err(AnyTlsError::Tls("no certificates found".into()));
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| AnyTlsError::Tls(format!("parse key: {e}")))?
        .ok_or_else(|| AnyTlsError::Tls("no private key found".into()))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| AnyTlsError::Tls(format!("protocol versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| AnyTlsError::Tls(format!("cert: {e}")))?;
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tls_config)
}

/// Generate a self-signed TLS certificate and key for AnyTLS.
///
/// Uses `rcgen` to produce a self-signed ECDSA P-256 cert
/// with a realistic-looking SAN. ECDSA is used instead of Ed25519
/// because Chrome uTLS fingerprints don't include Ed25519 sig algs.
pub fn generate_self_signed_cert() -> Result<(String, String), AnyTlsError> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| AnyTlsError::Tls(format!("key gen: {e}")))?;
    let mut params = rcgen::CertificateParams::new(Vec::new())
        .map_err(|e| AnyTlsError::Tls(format!("params: {e}")))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "cloudfront.net");
    let dns_name: rcgen::Ia5String = "*.cloudfront.net"
        .try_into()
        .map_err(|e| AnyTlsError::Tls(format!("dns name: {e}")))?;
    params
        .subject_alt_names
        .push(rcgen::SanType::DnsName(dns_name));
    let cert = params
        .self_signed(&key)
        .map_err(|e| AnyTlsError::Tls(format!("self-sign: {e}")))?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Forward an unauthenticated connection to a fallback destination.
///
/// Replays buffered data (the failed auth attempt) to the target, then
/// relays bidirectionally.
pub fn anytls_fallback(
    mut client: TcpStream,
    buffered_data: Vec<u8>,
    dest: &str,
) -> Result<(), AnyTlsError> {
    let mut target = TcpStream::connect(dest)?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;

    if !buffered_data.is_empty() {
        target.write_all(&buffered_data)?;
    }

    let mut c2 = client.try_clone()?;
    let mut t2 = target.try_clone()?;

    let t1 = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match c2.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if t2.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = t2.shutdown(Shutdown::Write);
    });

    let t2 = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match target.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if client.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = client.shutdown(Shutdown::Write);
    });

    t1.join().ok();
    t2.join().ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_password_hash() {
        use sha2::{Digest, Sha256};
        let password = b"test-password";
        let hash: [u8; 32] = Sha256::digest(password).into();
        assert!(auth::verify_password_hash(hash, hash));
        assert!(!auth::verify_password_hash([0u8; 32], hash));
    }

    #[test]
    fn test_generate_self_signed_cert() {
        let (cert, key) = generate_self_signed_cert().unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_build_tls_config() {
        let (cert, key) = generate_self_signed_cert().unwrap();
        let config = build_tls_config(&cert, &key).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn test_padding_scheme_parse_valid() {
        let raw = b"stop=8\n0=30-30\n1=100-400\n";
        let scheme = PaddingScheme::parse(raw).unwrap();
        assert_eq!(scheme.stop, 8);
        assert!(!scheme.stages.is_empty());
    }

    #[test]
    fn test_padding_scheme_parse_invalid_no_stop() {
        let raw = b"0=30-30\n1=100-400\n";
        assert!(PaddingScheme::parse(raw).is_none());
    }

    #[test]
    fn test_padding_generate_sizes() {
        let raw = b"stop=5\n0=30-30\n1=50-50\n";
        let scheme = PaddingScheme::parse(raw).unwrap();
        let sizes = scheme.generate_sizes(0);
        assert!(!sizes.is_empty());
        assert!(sizes.iter().all(|&s| s > 0));
    }
}
