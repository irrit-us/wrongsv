//! TLS acceptor with buffered ClientHello replay.
//!
//! The REALITY handshake requires reading the raw ClientHello before TLS
//! processing. We buffer the initial bytes, parse the ClientHello for
//! REALITY auth, then feed the buffered bytes into rustls via a
//! `BufferedStream` wrapper so rustls sees the complete byte stream.

use std::io::{Read, Result as IoResult, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection};

use crate::RealityError;
use crate::hello::parse_client_hello;
use crate::auth::authenticate;
use crate::cert::generate_reality_cert;
use crate::RealityConfig;

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
                self.conn.process_new_packets().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                })?;
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

/// Resolves a pre-computed `CertifiedKey` for rustls.
#[derive(Debug)]
struct RealityCertResolver {
    cert_key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for RealityCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.cert_key))
    }
}

/// Accept a REALITY connection on a raw TCP stream.
///
/// 1. Reads the TLS ClientHello from the stream
/// 2. Parses it, extracts REALITY auth data
/// 3. Authenticates the client
/// 4. Generates a dynamic certificate
/// 5. Completes the TLS 1.3 handshake
///
/// Returns `Ok(RealityTlsStream)` on success, or `Err(RealityError)` if
/// auth or handshake fails.
pub fn accept_reality(
    mut stream: TcpStream,
    config: &RealityConfig,
) -> Result<RealityTlsStream, RealityError> {
    // Read initial bytes (ClientHello typically 200-600 bytes, but could be larger
    // with uTLS fingerprints). Read up to 4096 to be safe.
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf)?;
    buf.truncate(n);

    if n < 5 {
        return Err(RealityError::TlsParse("connection too short".into()));
    }

    // Parse ClientHello and run REALITY auth
    let parsed = parse_client_hello(&buf)?;
    let auth_key = authenticate(&parsed, config)?;

    // Generate dynamic certificate for this connection
    let (certified_key, _pub_key_der) = generate_reality_cert(&auth_key)?;

    // Build rustls config with explicit crypto provider
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let rustls_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| RealityError::TlsHandshake(format!("protocol versions: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(RealityCertResolver {
            cert_key: Arc::new(certified_key),
        }));

    // Feed buffered data + rest of stream through rustls
    let conn = ServerConnection::new(Arc::new(rustls_config))
        .map_err(|e| RealityError::TlsHandshake(format!("create connection: {e}")))?;

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
