//! TLS helpers shared across transport modules — sync I/O.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;

// ── TLS config ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

pub fn make_no_verify_config() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
    )
}

// ── Sync TLS stream ──────────────────────────────────────────────────────

/// A TLS-wrapped stream implementing sync Read + Write.
pub struct TlsConnection {
    conn: rustls::ClientConnection,
    sock: TcpStream,
}

impl TlsConnection {
    pub fn new(conn: rustls::ClientConnection, sock: TcpStream) -> Self {
        Self { conn, sock }
    }

    fn read_tls_inner(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut retries: u32 = 0;
        const MAX_RETRIES: u32 = 20;
        loop {
            match self.conn.reader().read(buf) {
                Ok(0) => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "no application data after max retries",
                        ));
                    }
                    match self.conn.read_tls(&mut self.sock) {
                        Ok(0) => return Ok(0),
                        Ok(_) => {
                            self.conn
                                .process_new_packets()
                                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                            continue;
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(io::Error::new(
                            e.kind(),
                            "no application data after max retries",
                        ));
                    }
                    match self.conn.read_tls(&mut self.sock) {
                        Ok(0) => return Ok(0),
                        Ok(_) => {
                            self.conn
                                .process_new_packets()
                                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                            continue;
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn write_tls_inner(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.conn.writer().write_all(buf)?;
        self.tls_flush()?;
        // Ensure TLS records reach the kernel send buffer immediately
        self.sock.flush()?;
        Ok(buf.len())
    }

    fn tls_flush(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            match self.conn.write_tls(&mut self.sock) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // The socket write timeout (2 s) provides back-pressure —
                    // no need for an extra sleep here.
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl Read for TlsConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_tls_inner(buf)
    }
}

impl Write for TlsConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tls_inner(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_flush()
    }
}

// ── TLS connection helpers ───────────────────────────────────────────────

/// Perform a sync TLS handshake over a TCP stream.
pub fn tls_handshake_sync(sock: TcpStream, server_name: &str) -> io::Result<TlsConnection> {
    sock.set_write_timeout(Some(Duration::from_secs(10)))?;
    sock.set_nodelay(true)?;
    let config = make_no_verify_config();
    let dns_name = rustls::pki_types::DnsName::try_from(server_name.to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad SNI"))?;
    let server_name = rustls::pki_types::ServerName::DnsName(dns_name);
    let mut conn = rustls::ClientConnection::new(config, server_name).map_err(io::Error::other)?;

    let mut sock = sock;
    loop {
        match conn.complete_io(&mut sock) {
            Ok((_, _)) if !conn.is_handshaking() => break,
            Ok(_) => continue,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, e)),
        }
    }

    // Short read timeout for non-blocking poll behavior; longer write
    // timeout so TLS record flushes during bulk uploads aren't throttled.
    sock.set_read_timeout(Some(Duration::from_millis(50)))?;
    sock.set_write_timeout(Some(Duration::from_secs(2)))?;

    Ok(TlsConnection::new(conn, sock))
}

/// Connect via TLS: TCP connect → TLS handshake → VLESS header → response.
pub fn connect_tls(
    sock: TcpStream,
    uuid: &str,
    target_addr: &str,
    target_port: u16,
    flow: &str,
) -> io::Result<Box<dyn super::ReadWrite>> {
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    sock.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut tls = tls_handshake_sync(sock, "cloudfront.net")?;

    let header = super::raw::build_vless_header(uuid, target_addr, target_port, flow);
    tls.write_all(&header)?;

    let mut resp = [0u8; 2];
    super::read_exact_retry(&mut tls, &mut resp)?;
    if resp[1] > 0 {
        let mut addons = vec![0u8; resp[1] as usize];
        super::read_exact_retry(&mut tls, &mut addons)?;
    }

    Ok(Box::new(tls))
}
