//! TLS acceptor with buffered ClientHello replay.
//!
//! The REALITY handshake requires reading the raw ClientHello before TLS
//! processing. We buffer the initial bytes, parse the ClientHello for
//! REALITY auth, then feed the buffered bytes into rustls via a
//! `BufferedStream` wrapper so rustls sees the complete byte stream.
//!
//! When auth fails and a fallback destination is configured, the buffered
//! ClientHello is forwarded to the real target (spider mode) so the server
//! appears to be a normal HTTPS server to probes.

use std::io::{Read, Result as IoResult, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection};

use crate::RealityAcceptError;
use crate::RealityConfig;
use crate::RealityError;
use crate::auth::authenticate;
use crate::cert::generate_reality_cert;
use crate::hello::parse_client_hello;

/// A TLS stream produced by accepting a REALITY connection.
pub struct RealityTlsStream {
    conn: ServerConnection,
    stream: BufferedStream<TcpStream>,
}

impl RealityTlsStream {
    pub fn get_mut(&mut self) -> (&mut ServerConnection, &mut BufferedStream<TcpStream>) {
        (&mut self.conn, &mut self.stream)
    }
}

impl Read for RealityTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        // Try TLS first, then pending plaintext
        match self.conn.reader().read(buf) {
            Ok(0) => {
                // No decrypted data available — read more from socket
                let n = self.conn.read_tls(&mut self.stream)?;
                if n == 0 {
                    return Ok(0);
                }
                self.conn
                    .process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                self.conn.reader().read(buf)
            }
            other => other,
        }
    }
}

impl Write for RealityTlsStream {
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

/// A `Read` wrapper that first drains an internal buffer, then reads from
/// the underlying stream. Used to replay the buffered ClientHello into rustls.
pub struct BufferedStream<S> {
    inner: S,
    buffer: Vec<u8>,
    pos: usize,
}

impl<S: Read> BufferedStream<S> {
    pub fn new(inner: S, buffer: Vec<u8>) -> Self {
        BufferedStream {
            inner,
            buffer,
            pos: 0,
        }
    }

    /// Borrow the inner stream mutably.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consume self, returning the inner stream and any unread buffered bytes.
    pub fn into_inner(self) -> (S, Vec<u8>) {
        let remaining = self.buffer[self.pos..].to_vec();
        (self.inner, remaining)
    }
}

impl<S: Read> Read for BufferedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        // Drain buffer first
        if self.pos < self.buffer.len() {
            let n = (self.buffer.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.buffer[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

impl<S> Write for BufferedStream<S>
where
    S: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.flush()
    }
}

/// Debug key logger — dumps TLS 1.3 secrets via tracing for debugging.
#[derive(Debug)]
struct DebugKeyLog;

impl rustls::KeyLog for DebugKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let cr_hex = client_random.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let secret_hex = secret.iter().map(|b| format!("{b:02x}")).collect::<String>();
        tracing::info!("KEYLOG {label} {cr_hex} {secret_hex}");
        if let Ok(path) = std::env::var("WRONGSV_KEYLOG_FILE") {
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
                let _ = writeln!(f, "KEYLOG {label} {cr_hex} {secret_hex}");
            }
        }
    }
}

/// Resolves a pre-computed `CertifiedKey` for rustls.
#[derive(Debug)]
struct RealityCertResolver {
    cert_key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for RealityCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // rustls 0.23 ClientHello exposes: server_name, signature_schemes,
        // alpn, cipher_suites, named_groups, cert_types.
        if let Some(sni) = client_hello.server_name() {
            tracing::info!("RUSTLS_CH SNI={sni}");
        }
        tracing::info!(
            "RUSTLS_CH cipher_suites={:?} sig_schemes={:?} named_groups={:?}",
            client_hello.cipher_suites(),
            client_hello.signature_schemes(),
            client_hello.named_groups(),
        );
        Some(Arc::clone(&self.cert_key))
    }
}

/// Accept a REALITY connection on a raw TCP stream.
///
/// 1. Reads the TLS ClientHello from the stream
/// 2. Parses it, extracts REALITY auth data
/// 3. Authenticates the client
/// 4. Generates a dynamic certificate
/// 5. Builds a `RealityTlsStream` ready for `complete_handshake`
///
/// On auth failure, returns `Err(RealityAcceptError)` containing the
/// original stream and buffered ClientHello bytes for spider fallback.
pub fn accept_reality(
    mut stream: TcpStream,
    config: &RealityConfig,
) -> Result<RealityTlsStream, RealityAcceptError> {
    // Read initial bytes (ClientHello typically 200-600 bytes, could be larger
    // with uTLS fingerprints). Read up to 4096.
    let mut buf = vec![0u8; 4096];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(e) => {
            return Err(RealityAcceptError {
                error: e.into(),
                stream,
                buffered_data: Vec::new(),
            });
        }
    };
    buf.truncate(n);

    if n < 5 {
        return Err(RealityAcceptError {
            error: RealityError::TlsParse("connection too short".into()),
            stream,
            buffered_data: buf,
        });
    }

    // Parse ClientHello and run REALITY auth
    let parsed = match parse_client_hello(&buf) {
        Ok(p) => p,
        Err(e) => {
            return Err(RealityAcceptError {
                error: e,
                stream,
                buffered_data: buf,
            });
        }
    };

    // Debug: log what we parsed vs what we're buffering for rustls
    tracing::info!(
        "REALITY parsed: client_random={} key_share={} sid_len={}",
        parsed.random.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        parsed.key_share.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        parsed.session_id.len(),
    );
    // Log first 100 bytes of raw_body (the ClientHello handshake message we feed to rustls)
    let body_preview: String = parsed.raw_body.iter().take(80)
        .map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("");
    tracing::info!("REALITY raw_body[..80]={body_preview}");

    let auth_key = match authenticate(&parsed, config) {
        Ok(k) => k,
        Err(e) => {
            return Err(RealityAcceptError {
                error: e,
                stream,
                buffered_data: buf,
            });
        }
    };

    // Generate dynamic certificate: clone template, patch signature with HMAC
    let certified_key = match generate_reality_cert(&auth_key, &config.cert_material) {
        Ok(ck) => ck,
        Err(e) => {
            return Err(RealityAcceptError {
                error: e,
                stream,
                buffered_data: buf,
            });
        }
    };

    // Build rustls config with explicit crypto provider
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut rustls_config = match ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
    {
        Ok(c) => c,
        Err(e) => {
            return Err(RealityAcceptError {
                error: RealityError::TlsHandshake(format!("protocol versions: {e}")),
                stream,
                buffered_data: buf,
            });
        }
    }
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(RealityCertResolver {
        cert_key: Arc::new(certified_key),
    }));
    rustls_config.key_log = Arc::new(DebugKeyLog);

    // Feed buffered data + rest of stream through rustls
    let conn = match ServerConnection::new(Arc::new(rustls_config)) {
        Ok(c) => c,
        Err(e) => {
            return Err(RealityAcceptError {
                error: RealityError::TlsHandshake(format!("create connection: {e}")),
                stream,
                buffered_data: buf,
            });
        }
    };

    let buffered = BufferedStream::new(stream, buf);

    Ok(RealityTlsStream {
        conn,
        stream: buffered,
    })
}

/// Complete the TLS handshake on a `RealityTlsStream`.
///
/// Must be called after `accept_reality` before reading/writing.
pub fn complete_handshake(tls: &mut RealityTlsStream) -> Result<(), RealityError> {
    loop {
        match tls.conn.complete_io(&mut tls.stream) {
            Ok((_, _)) if !tls.conn.is_handshaking() => break,
            Ok(_) => continue,
            Err(e) => {
                return Err(RealityError::TlsHandshake(format!("handshake: {e}")));
            }
        }
    }
    Ok(())
}

/// Forward an unauthenticated connection to a real target (spider mode).
///
/// Replays the buffered ClientHello bytes to the destination, then relays
/// bidirectionally between the client and the target. This makes the server
/// appear to be a normal HTTPS server to probes that fail REALITY auth.
pub fn spider_fallback(
    mut client: TcpStream,
    buffered_data: Vec<u8>,
    dest: &str,
) -> Result<(), RealityError> {
    let mut target = TcpStream::connect(dest)?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;

    // Replay the buffered ClientHello to the target
    target.write_all(&buffered_data)?;

    // Bidirectional relay — two threads, mirrors relay_raw in handler
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
