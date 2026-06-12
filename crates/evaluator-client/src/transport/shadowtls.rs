//! ShadowTLS transport: TLS 1.3 + RFC 8446 exporter HMAC auth + VLESS.
//!
//! Uses a background thread with channel bridging for the TLS connection.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::JoinHandle;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::BoxedIo;

type HmacSha256 = Hmac<Sha256>;

struct StlsStream {
    read_rx: Receiver<Vec<u8>>,
    write_tx: SyncSender<Vec<u8>>,
    read_buf: Vec<u8>,
    _handle: JoinHandle<()>,
}

impl Read for StlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.len());
            buf[..n].copy_from_slice(&self.read_buf[..n]);
            self.read_buf.drain(..n);
            if n > 0 {
                return Ok(n);
            }
        }
        match self.read_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(data) => {
                if data.is_empty() {
                    return Ok(0);
                }
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf.extend_from_slice(&data[n..]);
                }
                Ok(n)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "ShadowTLS read timeout",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(0),
        }
    }
}

impl Write for StlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx.send(buf.to_vec()).map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "ShadowTLS write channel closed")
        })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ── TLS verifier ──────────────────────────────────────────────────────

#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
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

fn make_stls_tls_config() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Derive the 32-byte HMAC proof from TLS exporter secret.
fn derive_client_proof(
    conn: &rustls::ClientConnection,
    password: &str,
) -> Result<[u8; 32], io::Error> {
    use sha2::Digest;
    let hmac_key: [u8; 32] = sha2::Sha256::digest(password.as_bytes()).into();

    let mut exporter_secret = [0u8; 32];
    conn.export_keying_material(&mut exporter_secret, b"shadow_tls", None)
        .map_err(|e| io::Error::other(format!("stls export_keying_material: {e}")))?;

    let mut mac = HmacSha256::new_from_slice(&hmac_key)
        .map_err(|e| io::Error::other(format!("stls hmac init: {e}")))?;
    mac.update(&exporter_secret);
    let result = mac.finalize();
    Ok(result.into_bytes().into())
}

// ── Read helper: read exactly N bytes of TLS plaintext ───────────────

fn read_tls_exact(
    conn: &mut rustls::ClientConnection,
    sock: &mut TcpStream,
    buf: &mut [u8],
) -> Result<(), io::Error> {
    let mut pos = 0usize;
    while pos < buf.len() {
        match conn.reader().read(&mut buf[pos..]) {
            Ok(0) => {
                let n = conn.read_tls(sock)?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS connection closed",
                    ));
                }
                conn.process_new_packets()
                    .map_err(|e| io::Error::other(format!("tls process: {e}")))?;
            }
            Ok(n) => pos += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                let n = conn.read_tls(sock)?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS connection closed",
                    ));
                }
                conn.process_new_packets()
                    .map_err(|e| io::Error::other(format!("tls process: {e}")))?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ── Connect ───────────────────────────────────────────────────────────

pub fn connect_shadowtls(
    proxy_host: &str,
    proxy_port: u16,
    uuid: &str,
    target_addr: &str,
    target_port: u16,
    flow: &str,
) -> io::Result<BoxedIo> {
    let password = "eval-stls-pass"; // matches evaluator orchestrator default
    let header = super::raw::build_vless_header(uuid, target_addr, target_port, flow);
    let stream = super::connect_proxy(proxy_host, proxy_port)?;

    let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>();
    let (write_tx, write_rx) = mpsc::sync_channel::<Vec<u8>>(32);
    let (hs_tx, hs_rx) = mpsc::sync_channel::<Result<(), io::Error>>(1);

    let handle = std::thread::spawn(move || {
        // ── TLS handshake ───────────────────────────────────────────
        let tls_config = make_stls_tls_config();
        let server_name = match rustls::pki_types::ServerName::try_from("localhost") {
            Ok(sn) => sn,
            Err(e) => {
                let _ = hs_tx.send(Err(io::Error::other(format!("stls servername: {e}"))));
                return;
            }
        };
        let mut conn = match rustls::ClientConnection::new(Arc::new(tls_config), server_name) {
            Ok(c) => c,
            Err(e) => {
                let _ = hs_tx.send(Err(io::Error::other(format!("stls client conn: {e}"))));
                return;
            }
        };
        let mut sock = stream;

        loop {
            match conn.complete_io(&mut sock) {
                Ok((_, _)) if !conn.is_handshaking() => break,
                Ok(_) => {}
                Err(e) => {
                    let _ = hs_tx.send(Err(io::Error::other(format!("stls handshake: {e}"))));
                    return;
                }
            }
        }

        // ── HMAC auth ──────────────────────────────────────────────
        let proof = match derive_client_proof(&conn, password) {
            Ok(p) => p,
            Err(e) => {
                let _ = hs_tx.send(Err(e));
                return;
            }
        };

        let expected_challenge = &proof[..8];
        let client_response = &proof[8..16];

        // Read 8-byte server challenge
        let mut challenge = [0u8; 8];
        if let Err(e) = read_tls_exact(&mut conn, &mut sock, &mut challenge) {
            let _ = hs_tx.send(Err(e));
            return;
        }

        // Verify server challenge
        if challenge != *expected_challenge {
            let _ = hs_tx.send(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ShadowTLS auth failed: server challenge mismatch",
            )));
            return;
        }

        // Send client response
        if conn.writer().write_all(client_response).is_err() {
            let _ = hs_tx.send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stls write response failed",
            )));
            return;
        }
        while conn.wants_write() {
            if conn.write_tls(&mut sock).is_err() {
                let _ = hs_tx.send(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stls flush response failed",
                )));
                return;
            }
        }

        // ── VLESS header ───────────────────────────────────────────
        if conn.writer().write_all(&header).is_err() {
            let _ = hs_tx.send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stls write vless header failed",
            )));
            return;
        }
        while conn.wants_write() {
            if conn.write_tls(&mut sock).is_err() {
                let _ = hs_tx.send(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stls flush vless header failed",
                )));
                return;
            }
        }

        // Read VLESS response (2 bytes)
        let mut resp = [0u8; 2];
        if let Err(e) = read_tls_exact(&mut conn, &mut sock, &mut resp) {
            let _ = hs_tx.send(Err(e));
            return;
        }

        if resp[1] > 0 {
            let mut addons = vec![0u8; resp[1] as usize];
            if let Err(e) = read_tls_exact(&mut conn, &mut sock, &mut addons) {
                let _ = hs_tx.send(Err(e));
                return;
            }
        }

        let _ = hs_tx.send(Ok(()));

        // ── Bidirectional relay ────────────────────────────────────
        let mut sock_r = match sock.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut sock_w = sock;

        // Short read timeout on the reader socket so that read_tls
        // never blocks forever while holding the conn mutex — the
        // writer thread also needs the mutex to send data.
        // 500ms chosen as a balance: short enough that a dead peer
        // is detected quickly, long enough for ~400ms RTT paths
        // (SSH tunnel to remote regions).
        let _ = sock_r.set_read_timeout(Some(Duration::from_millis(500)));

        let conn = Arc::new(std::sync::Mutex::new(conn));
        let conn_r = Arc::clone(&conn);

        // Reader: TLS plaintext → channel
        let rt = std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                // Lock only for the duration of each TLS operation.
                // Blocking socket reads happen inside read_tls, so we
                // must NOT hold the lock across retry loops.
                let mut c = conn_r.lock().unwrap();
                let reader_result = c.reader().read(&mut buf);
                match reader_result {
                    Ok(n) if n > 0 => {
                        drop(c);
                        if read_tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    _ => {
                        // No plaintext available — feed TLS records from socket
                        match c.read_tls(&mut sock_r) {
                            Ok(0) => {
                                let _ = read_tx.send(Vec::new());
                                break;
                            }
                            Ok(_) => {
                                if c.process_new_packets().is_err() {
                                    break;
                                }
                            }
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                drop(c);
                                std::thread::sleep(Duration::from_millis(5));
                                continue;
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        // Writer: channel → TLS plaintext
        loop {
            match write_rx.recv() {
                Ok(data) => {
                    let mut c = conn.lock().unwrap();
                    if c.writer().write_all(&data).is_err() {
                        break;
                    }
                    while c.wants_write() {
                        if c.write_tls(&mut sock_w).is_err() {
                            break;
                        }
                    }
                }
                Err(_) => {
                    let mut c = conn.lock().unwrap();
                    c.send_close_notify();
                    while c.wants_write() {
                        let _ = c.write_tls(&mut sock_w);
                    }
                    break;
                }
            }
        }

        let _ = rt.join();
    });

    hs_rx
        .recv()
        .map_err(|_| io::Error::other("ShadowTLS thread panicked"))??;

    Ok(Box::new(StlsStream {
        read_rx,
        write_tx,
        read_buf: Vec::new(),
        _handle: handle,
    }))
}
