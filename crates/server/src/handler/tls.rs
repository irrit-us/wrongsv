use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, trace};
use wrongsv_protocol::RequestCommand;
use wrongsv_vless::MemoryValidator;

use crate::config::TlsServerConfig;

use super::*;

#[derive(Clone)]
pub(crate) struct TlsConfig {
    pub tls_config: Arc<rustls::ServerConfig>,
    #[allow(dead_code)]
    pub dest: Option<String>,
}

/// WebSocket carrier configuration.
pub(crate) fn parse_tls_config(tc: &TlsServerConfig) -> Result<TlsConfig, String> {
    let (cert_pem, key_pem) = match (&tc.certificate, &tc.key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => {
            let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                .map_err(|e| format!("tls cert: {e}"))?;
            (cert, key)
        }
    };
    let server_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
        .map_err(|e| format!("tls config: {e}"))?;
    Ok(TlsConfig {
        tls_config: Arc::new(server_config),
        dest: tc.dest.clone(),
    })
}
pub(crate) fn accept_tls(
    stream: TcpStream,
    config: &TlsConfig,
) -> Result<wrongsv_anytls::AnyTlsStream, Box<dyn std::error::Error>> {
    let mut conn = rustls::ServerConnection::new(Arc::clone(&config.tls_config))
        .map_err(|e| format!("tls create: {e}"))?;
    let mut stream = stream;
    loop {
        match conn.complete_io(&mut stream) {
            Ok((_, _)) if !conn.is_handshaking() => break,
            Ok(_) => {}
            Err(e) => return Err(format!("tls handshake: {e}").into()),
        }
    }
    Ok(wrongsv_anytls::AnyTlsStream::from_parts(conn, stream))
}
pub(crate) fn read_tls_plaintext(
    conn: &mut rustls::ServerConnection,
    sock: &mut TcpStream,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    loop {
        match conn.reader().read(buf) {
            Ok(n) if n > 0 => return Ok(n),
            Ok(_) => {
                // Need more TLS records
                let n = conn.read_tls(sock)?;
                if n == 0 {
                    return Ok(0); // EOF
                }
                conn.process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let n = conn.read_tls(sock)?;
                if n == 0 {
                    return Ok(0);
                }
                conn.process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Read the HTTP upgrade request from a raw TCP stream into `buf`.
pub(crate) fn stream_read_upgrade(stream: &TcpStream, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    let mut stream = stream;
    buf.clear();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(n) if n > 0 => {
                buf.extend_from_slice(&tmp[..n]);
                // Check for \r\n\r\n header terminator
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    return Ok(buf.len());
                }
                if buf.len() >= 16384 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "HTTP upgrade header too large",
                    ));
                }
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed during HTTP upgrade",
                ));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

pub(crate) fn handle_tls_connection(
    stream: TcpStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    tls_config: &TlsConfig,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} TLS connection");

    let mut tls_stream = match accept_tls(stream, tls_config) {
        Ok(tls) => tls,
        Err(e) => {
            debug!("{peer} TLS handshake failed: {e}");
            return Err(e);
        }
    };
    info!("{peer} TLS handshake complete");

    // Read VLESS header from TLS stream (same as AnyTLS path)
    let mut first = vec![0u8; 8192];
    let (read_conn, write_conn) = tls_stream.get_mut();
    loop {
        let result = read_conn.reader().read(&mut first);
        match result {
            Ok(0) => {
                let n = read_conn.read_tls(write_conn)?;
                if n == 0 {
                    return Err("connection closed before VLESS header".into());
                }
                read_conn
                    .process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            }
            Ok(n) => {
                first.truncate(n);
                break;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let n = read_conn.read_tls(write_conn)?;
                if n == 0 {
                    return Err("connection closed before VLESS header".into());
                }
                read_conn
                    .process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            }
            Err(e) => return Err(e.into()),
        }
    }

    let n = first.len();
    trace!("{peer} TLS read {n} bytes VLESS header");

    let VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    } = decode_vless_request(first, &validator, peer)?;
    let request = &decoded.header;
    let account = &request.user.account;
    let tap = wrongsv_metrics::MetricsTap::new(metrics, request.user.email.clone());
    let _conn_guard = tap.track_connection();

    log_vless_request(peer, request);
    handle_kyber_addons(peer, &decoded, kyber_sk);
    validate_vless_command(request, use_vision)?;

    let resp_buf = response_header_buf(request)?;
    read_conn.writer().write_all(&resp_buf)?;
    while read_conn.wants_write() {
        read_conn.write_tls(write_conn)?;
    }

    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_anytls_udp(tls_stream, request, remaining_body, tap)?;
        debug!("{peer} TLS UDP relay finished");
        return Ok(());
    }

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
            tap,
        )?;
    } else {
        relay_anytls_raw(tls_stream, target, remaining_body, tap)?;
    }
    debug!("{peer} TLS TCP relay finished");
    Ok(())
}
