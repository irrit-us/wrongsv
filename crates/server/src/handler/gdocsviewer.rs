use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use rand::RngCore;
use tracing::debug;
use wrongsv_vless::MemoryValidator;

use crate::config::GdocsViewerServerConfig;

use super::*;

const DEFAULT_GDOCS_POLL_WAIT: Duration = Duration::from_secs(10);
const ENCRYPTED_REQUEST_VERSION: u8 = 1;
const RESPONSE_FRAME_SUCCESS: u8 = 0;
const RESPONSE_FRAME_ERROR: u8 = 1;

#[derive(Clone)]
pub(crate) struct GdocsViewerConfig {
    pub path_prefix: String,
    pub max_request_bytes: usize,
    pub shared_key: Option<[u8; 32]>,
    pub sessions: Arc<RequestSessionRegistry>,
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
    #[allow(dead_code)]
    pub tls_dest: Option<String>,
}

pub(crate) fn parse_gdocsviewer_config(
    gc: &GdocsViewerServerConfig,
) -> Result<GdocsViewerConfig, String> {
    let path_prefix = if gc.path_prefix.starts_with('/') {
        gc.path_prefix.clone()
    } else {
        format!("/{}", gc.path_prefix)
    };
    let (tls_config, tls_dest) = match &gc.tls {
        Some(tls) => {
            let (cert_pem, key_pem) = match (&tls.certificate, &tls.key) {
                (Some(c), Some(k)) => (c.clone(), k.clone()),
                _ => {
                    let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                        .map_err(|e| format!("gdocsviewer tls cert: {e}"))?;
                    (cert, key)
                }
            };
            let server_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
                .map_err(|e| format!("gdocsviewer tls config: {e}"))?;
            (Some(Arc::new(server_config)), tls.dest.clone())
        }
        None => (None, None),
    };
    let shared_key = match &gc.shared_key {
        Some(value) => {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(|_| "gdocsviewer shared_key must be base64".to_string())?;
            let key: [u8; 32] = decoded
                .try_into()
                .map_err(|_| "gdocsviewer shared_key must decode to 32 bytes".to_string())?;
            Some(key)
        }
        None => None,
    };
    let max_response_bytes = gc.max_response_bytes.max(1);
    let max_buffered_response_bytes = max_response_bytes
        .saturating_mul(16)
        .max(max_response_bytes);
    let idle_timeout = if gc.idle_timeout == 0 {
        Duration::ZERO
    } else {
        Duration::from_secs(gc.idle_timeout)
    };
    Ok(GdocsViewerConfig {
        path_prefix,
        max_request_bytes: gc.max_request_bytes.max(1),
        shared_key,
        sessions: Arc::new(RequestSessionRegistry::new(RequestSessionRegistryConfig {
            max_response_bytes,
            max_buffered_response_bytes,
            idle_timeout,
        })),
        tls_config,
        tls_dest,
    })
}

fn write_gdocs_response(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Cache-Control: no-store\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        )
        .as_bytes(),
    )?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush()
}

fn not_found(stream: &mut TcpStream) {
    let _ = stream.write_all(
        b"HTTP/1.1 404 Not Found\r\n\
          Content-Length: 0\r\n\
          Connection: close\r\n\
          \r\n",
    );
    let _ = stream.flush();
}

fn path_tail<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if path == prefix {
        Some("")
    } else {
        path.strip_prefix(prefix)
    }
}

fn parse_http_get_path(buf: &[u8]) -> Result<String, String> {
    let header_end = buf
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "incomplete HTTP headers".to_string())?;
    let headers =
        std::str::from_utf8(&buf[..header_end]).map_err(|_| "invalid HTTP headers".to_string())?;
    let mut lines = headers.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "missing HTTP request line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "invalid HTTP request line".to_string())?;
    if method != "GET" {
        return Err(format!("unsupported method: {method}"));
    }
    let raw_path = parts
        .next()
        .ok_or_else(|| "invalid HTTP request line".to_string())?;
    let path = raw_path.split('?').next().unwrap_or(raw_path);
    Ok(if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    })
}

fn encrypt_aead(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("aes-gcm init: {e}"))?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| format!("aes-gcm encrypt: {e}"))?;
    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_aead(key: &[u8; 32], combined: &[u8]) -> Result<Vec<u8>, String> {
    if combined.len() < 12 + 16 {
        return Err("encrypted blob is too short".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("aes-gcm init: {e}"))?;
    cipher
        .decrypt(Nonce::from_slice(&combined[..12]), &combined[12..])
        .map_err(|e| format!("aes-gcm decrypt: {e}"))
}

fn decrypt_client_request(key: &[u8; 32], combined: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let frame = decrypt_aead(key, combined)?;
    if frame.len() < 3 {
        return Err("encrypted request frame is too short".to_string());
    }
    if frame[0] != ENCRYPTED_REQUEST_VERSION {
        return Err(format!(
            "unknown encrypted request frame version: {}",
            frame[0]
        ));
    }
    let session_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    if frame.len() < 3 + session_len {
        return Err("encrypted request frame has invalid session length".to_string());
    }
    Ok((
        frame[3..3 + session_len].to_vec(),
        frame[3 + session_len..].to_vec(),
    ))
}

fn encrypt_response_frame(key: &[u8; 32], frame: &[u8]) -> Result<Vec<u8>, String> {
    encrypt_aead(key, frame)
}

fn roundtrip_plain(
    config: &GdocsViewerConfig,
    session_segment: &str,
    payload_segment: &str,
    validator: Arc<MemoryValidator>,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<Vec<u8>, String> {
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_segment)
        .map_err(|_| "invalid payload encoding".to_string())?;
    if payload.len() > config.max_request_bytes {
        return Err("request exceeds max_request_bytes".to_string());
    }
    let lease = config.sessions.acquire(session_segment);
    if let Some(stream) = lease.stream {
        spawn_vless_request_session(
            "gdocsviewer",
            session_segment.to_string(),
            Arc::clone(&config.sessions),
            stream,
            validator,
            metrics.clone(),
        );
    }
    let poll_wait = if payload.is_empty() {
        DEFAULT_GDOCS_POLL_WAIT
    } else {
        Duration::from_millis(250)
    };
    lease
        .session
        .submit_roundtrip(&payload, true, poll_wait)
        .map_err(|e| format!("gdocsviewer roundtrip: {e}"))
}

fn roundtrip_encrypted(
    config: &GdocsViewerConfig,
    combined_segment: &str,
    validator: Arc<MemoryValidator>,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<Vec<u8>, String> {
    let Some(shared_key) = config.shared_key.as_ref() else {
        return Err("shared_key not configured".to_string());
    };
    let combined = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(combined_segment)
        .map_err(|_| "invalid encrypted request encoding".to_string())?;
    let (session, payload) = decrypt_client_request(shared_key, &combined)?;
    if payload.len() > config.max_request_bytes {
        return Err("request exceeds max_request_bytes".to_string());
    }
    let session_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&session);
    let lease = config.sessions.acquire(&session_key);
    if let Some(stream) = lease.stream {
        spawn_vless_request_session(
            "gdocsviewer",
            session_key.clone(),
            Arc::clone(&config.sessions),
            stream,
            validator,
            metrics.clone(),
        );
    }
    let poll_wait = if payload.is_empty() {
        DEFAULT_GDOCS_POLL_WAIT
    } else {
        Duration::from_millis(250)
    };
    match lease.session.submit_roundtrip(&payload, true, poll_wait) {
        Ok(response) => {
            let mut frame = Vec::with_capacity(1 + response.len());
            frame.push(RESPONSE_FRAME_SUCCESS);
            frame.extend_from_slice(&response);
            encrypt_response_frame(shared_key, &frame).map(|ciphertext| {
                base64::engine::general_purpose::STANDARD
                    .encode(ciphertext)
                    .into_bytes()
            })
        }
        Err(e) => {
            let mut frame = Vec::with_capacity(1 + e.to_string().len());
            frame.push(RESPONSE_FRAME_ERROR);
            frame.extend_from_slice(e.to_string().as_bytes());
            encrypt_response_frame(shared_key, &frame).map(|ciphertext| {
                base64::engine::general_purpose::STANDARD
                    .encode(ciphertext)
                    .into_bytes()
            })
        }
    }
}

pub(crate) fn handle_gdocsviewer_connection(
    stream: TcpStream,
    validator: Arc<MemoryValidator>,
    gdocs_config: &GdocsViewerConfig,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;

    match &gdocs_config.tls_config {
        Some(tls_config) => {
            let plain = tls_relay(stream, tls_config, peer, "gdocsviewer+tls")?;
            handle_gdocsviewer_connection(
                plain,
                validator,
                &GdocsViewerConfig {
                    tls_config: None,
                    ..gdocs_config.clone()
                },
                metrics,
            )
        }
        None => {
            let mut stream = stream;
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            let mut header_buf = Vec::new();
            stream_read_upgrade(&stream, &mut header_buf)?;
            let path = match parse_http_get_path(&header_buf) {
                Ok(path) => path,
                Err(e) => {
                    debug!("{peer} gdocsviewer rejected: {e}");
                    not_found(&mut stream);
                    return Ok(());
                }
            };
            let Some(tail) = path_tail(&path, &gdocs_config.path_prefix) else {
                not_found(&mut stream);
                return Ok(());
            };

            let response_body = if gdocs_config.shared_key.is_none() {
                let Some(path_tail) = tail.strip_prefix("/r/") else {
                    not_found(&mut stream);
                    return Ok(());
                };
                let parts = path_tail.split('/').collect::<Vec<_>>();
                if parts.len() != 3
                    || !parts[2].ends_with(".txt")
                    || parts[2].trim_end_matches(".txt").is_empty()
                {
                    not_found(&mut stream);
                    return Ok(());
                }
                match roundtrip_plain(gdocs_config, parts[0], parts[1], validator, metrics) {
                    Ok(response) => base64::engine::general_purpose::STANDARD
                        .encode(response)
                        .into_bytes(),
                    Err(e) => {
                        debug!("{peer} gdocsviewer plaintext roundtrip failed: {e}");
                        not_found(&mut stream);
                        return Ok(());
                    }
                }
            } else {
                let Some(combined) = tail.strip_prefix("/t/") else {
                    not_found(&mut stream);
                    return Ok(());
                };
                let Some(combined) = combined.strip_suffix(".log") else {
                    not_found(&mut stream);
                    return Ok(());
                };
                match roundtrip_encrypted(gdocs_config, combined, validator, metrics) {
                    Ok(response) => response,
                    Err(e) => {
                        debug!("{peer} gdocsviewer encrypted roundtrip failed: {e}");
                        not_found(&mut stream);
                        return Ok(());
                    }
                }
            };

            write_gdocs_response(&mut stream, &response_body)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_get_path_extracts_path_without_query() {
        let request =
            b"GET /gdocsviewer/r/abc/def/nonce.txt?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            parse_http_get_path(request).unwrap(),
            "/gdocsviewer/r/abc/def/nonce.txt"
        );
    }

    #[test]
    fn encrypted_request_roundtrip_helpers_match() {
        let key = [7u8; 32];
        let session = b"session";
        let payload = b"payload";
        let mut frame = Vec::new();
        frame.push(ENCRYPTED_REQUEST_VERSION);
        frame.extend_from_slice(&(session.len() as u16).to_be_bytes());
        frame.extend_from_slice(session);
        frame.extend_from_slice(payload);

        let combined = encrypt_aead(&key, &frame).unwrap();
        let (decoded_session, decoded_payload) = decrypt_client_request(&key, &combined).unwrap();
        assert_eq!(decoded_session, session);
        assert_eq!(decoded_payload, payload);
    }
}
