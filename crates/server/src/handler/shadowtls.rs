//! ShadowTLS protocol — TLS 1.3 disguise with HMAC authentication.
//!
//! After a standard TLS 1.3 handshake, both sides derive a shared secret
//! via RFC 8446 keying-material exporter and authenticate with HMAC-SHA256
//! over the password. Valid auth → VLESS relay; invalid → fallback to dest.
//!
//! ## Protocol
//!
//! 1. TLS 1.3 handshake with real-looking cert (self-signed or user-provided)
//! 2. Both sides: `secret = export_keying_material("shadow_tls", 32)`
//! 3. Both sides: `proof = HMAC-SHA256(password, secret)` (32 bytes)
//! 4. Server → Client: proof[..8] (server challenge)
//! 5. Client → Server: proof[8..16] (client response)
//! 6. Server verifies client response matches expected
//! 7. Valid → VLESS header + relay; Invalid → fallback or close

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, info, trace, warn};
use wrongsv_protocol::RequestCommand;
use wrongsv_vless::MemoryValidator;

use crate::config::ShadowTlsServerConfig;

use super::*;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub(crate) struct ShadowTlsConfig {
    pub password_hmac_key: [u8; 32],
    pub tls_config: Arc<rustls::ServerConfig>,
    pub dest: Option<String>,
}

pub(crate) fn parse_shadowtls_config(
    sc: &ShadowTlsServerConfig,
) -> Result<ShadowTlsConfig, String> {
    use sha2::{Digest, Sha256};
    let password_hmac_key: [u8; 32] = Sha256::digest(sc.password.as_bytes()).into();

    let (cert_pem, key_pem) = match (&sc.certificate, &sc.key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => {
            let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                .map_err(|e| format!("shadowtls cert: {e}"))?;
            (cert, key)
        }
    };

    let tls_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
        .map_err(|e| format!("shadowtls tls: {e}"))?;

    Ok(ShadowTlsConfig {
        password_hmac_key,
        tls_config: Arc::new(tls_config),
        dest: sc.dest.clone(),
    })
}

/// Derive the 32-byte HMAC proof from the TLS exporter secret and password.
fn derive_proof(
    conn: &rustls::ServerConnection,
    hmac_key: &[u8; 32],
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut exporter_secret = [0u8; 32];
    conn.export_keying_material(&mut exporter_secret, b"shadow_tls", None)
        .map_err(|e| format!("shadowtls export_keying_material: {e}"))?;

    let mut mac = HmacSha256::new_from_slice(hmac_key).map_err(|e| format!("hmac init: {e}"))?;
    mac.update(&exporter_secret);
    let result = mac.finalize();
    Ok(result.into_bytes().into())
}

/// Perform TLS 1.3 handshake on the given TCP stream.
fn accept_shadowtls_tls(
    stream: TcpStream,
    config: &ShadowTlsConfig,
) -> Result<(rustls::ServerConnection, TcpStream), Box<dyn std::error::Error>> {
    let conn = rustls::ServerConnection::new(Arc::clone(&config.tls_config))
        .map_err(|e| format!("shadowtls create conn: {e}"))?;
    let mut conn = conn;
    let mut sock = stream;
    loop {
        match conn.complete_io(&mut sock) {
            Ok((_, _)) if !conn.is_handshaking() => break,
            Ok(_) => {}
            Err(e) => return Err(format!("shadowtls handshake: {e}").into()),
        }
    }
    Ok((conn, sock))
}

/// ShadowTLS connection handler.
pub(crate) fn handle_shadowtls_connection(
    stream: TcpStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    shadowtls_config: &ShadowTlsConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} ShadowTLS connection");

    // ── TLS 1.3 handshake ──────────────────────────────────────────────
    let (mut conn, mut sock) = match accept_shadowtls_tls(stream, shadowtls_config) {
        Ok(tls) => tls,
        Err(e) => {
            debug!("{peer} ShadowTLS TLS handshake failed: {e}");
            return Err(e);
        }
    };
    info!("{peer} ShadowTLS handshake complete");

    // ── HMAC auth via RFC 8446 exporter ────────────────────────────────
    let proof = match derive_proof(&conn, &shadowtls_config.password_hmac_key) {
        Ok(p) => p,
        Err(e) => {
            warn!("{peer} ShadowTLS proof derivation failed: {e}");
            return Err(e);
        }
    };

    // Send server challenge: proof[..8]
    let server_challenge = &proof[..8];
    conn.writer().write_all(server_challenge)?;
    while conn.wants_write() {
        conn.write_tls(&mut sock)?;
    }

    // Read client response (8 bytes) from TLS plaintext
    let mut client_response = [0u8; 8];
    let expected_response = &proof[8..16];

    // Read 8 bytes of plaintext, looping over TLS records
    let mut read_pos = 0usize;
    while read_pos < 8 {
        match conn.reader().read(&mut client_response[read_pos..]) {
            Ok(0) => {
                // Need more TLS data
                let n = conn.read_tls(&mut sock)?;
                if n == 0 {
                    return Err("connection closed during ShadowTLS auth".into());
                }
                conn.process_new_packets()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            }
            Ok(n) => {
                read_pos += n;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                let n = conn.read_tls(&mut sock)?;
                if n == 0 {
                    return Err("connection closed during ShadowTLS auth".into());
                }
                conn.process_new_packets()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Verify client response
    if client_response != *expected_response {
        debug!(
            "{peer} ShadowTLS auth failed: client response mismatch (expected {:02x?}, got {:02x?})",
            expected_response, client_response
        );
        // Send close_notify and fallback
        conn.send_close_notify();
        while conn.wants_write() {
            let _ = conn.write_tls(&mut sock);
        }

        if let Some(ref dest) = shadowtls_config.dest {
            shadowtls_fallback(sock, dest);
            return Ok(());
        }
        return Err("ShadowTLS authentication failed".into());
    }
    info!("{peer} ShadowTLS auth OK");

    // ── Read VLESS header ──────────────────────────────────────────────
    let mut first = vec![0u8; 8192];
    let n = loop {
        match conn.reader().read(&mut first) {
            Ok(n) if n > 0 => break n,
            Ok(_) => {
                let nread = conn.read_tls(&mut sock)?;
                if nread == 0 {
                    return Err("connection closed before VLESS header".into());
                }
                conn.process_new_packets()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                let nread = conn.read_tls(&mut sock)?;
                if nread == 0 {
                    return Err("connection closed before VLESS header".into());
                }
                conn.process_new_packets()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            }
            Err(e) => return Err(e.into()),
        }
    };
    first.truncate(n);
    trace!("{peer} ShadowTLS read {n} bytes VLESS header");

    let VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    } = decode_vless_request(first, &validator, peer)?;
    let request = &decoded.header;
    let account = &request.user.account;

    log_vless_request(peer, request);
    handle_kyber_addons(peer, &decoded, kyber_sk);
    validate_vless_command(request, use_vision)?;

    let resp_buf = response_header_buf(request)?;
    conn.writer().write_all(&resp_buf)?;
    while conn.wants_write() {
        conn.write_tls(&mut sock)?;
    }

    let tls_stream = wrongsv_anytls::AnyTlsStream::from_parts(conn, sock);

    // UDP relay
    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_anytls_udp(tls_stream, request, remaining_body)?;
        debug!("{peer} ShadowTLS UDP relay finished");
        return Ok(());
    }

    // TCP relay
    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("{peer} connecting to target {target_addr}");
    let target = TcpStream::connect(&target_addr)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(60)))?;

    if use_vision {
        let user_sent_id = account.id.bytes();
        relay_anytls_vision(
            tls_stream,
            target,
            user_sent_id,
            &account.testseed,
            remaining_body,
        )?;
    } else {
        relay_anytls_raw(tls_stream, target, remaining_body)?;
    }
    debug!("{peer} ShadowTLS TCP relay finished");
    Ok(())
}

/// Fallback: forward the raw TCP stream to the given destination.
/// The TLS close_notify has already been sent.
fn shadowtls_fallback(mut client_sock: TcpStream, dest: &str) {
    let mut dest_sock = match TcpStream::connect(dest) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = dest_sock.set_nodelay(true);
    let _ = dest_sock.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client_sock.set_read_timeout(Some(Duration::from_secs(30)));

    let mut client_r = match client_sock.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut dest_r = match dest_sock.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };

    let t1 = thread::spawn(move || {
        let mut buf = [0u8; 32768];
        loop {
            match client_r.read(&mut buf) {
                Ok(0) => {
                    let _ = dest_sock.shutdown(Shutdown::Write);
                    break;
                }
                Ok(n) => {
                    if dest_sock.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => break,
            }
        }
    });

    let mut buf = [0u8; 32768];
    loop {
        match dest_r.read(&mut buf) {
            Ok(0) => {
                let _ = client_sock.shutdown(Shutdown::Write);
                break;
            }
            Ok(n) => {
                if client_sock.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(_) => break,
        }
    }

    let _ = t1.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_shadowtls_config_with_password() {
        let cfg = ShadowTlsServerConfig {
            password: "test-secret".into(),
            dest: Some("127.0.0.1:8080".into()),
            certificate: None,
            key: None,
        };
        let st = parse_shadowtls_config(&cfg).unwrap();
        assert!(st.dest.as_deref() == Some("127.0.0.1:8080"));
    }

    #[test]
    fn test_parse_shadowtls_config_no_dest() {
        let cfg = ShadowTlsServerConfig {
            password: "test".into(),
            dest: None,
            certificate: None,
            key: None,
        };
        let st = parse_shadowtls_config(&cfg).unwrap();
        assert!(st.dest.is_none());
    }
}
