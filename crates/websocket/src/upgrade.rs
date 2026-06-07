//! HTTP WebSocket upgrade handshake.
//!
//! Parses the client's HTTP GET + Upgrade request, validates the path and
//! optional Host header, and writes the 101 Switching Protocols response.

use sha1::{Digest, Sha1};

/// The RFC 6455 WebSocket GUID used in the accept-key computation.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Maximum HTTP header block size we'll buffer during upgrade.
const MAX_HEADER_SIZE: usize = 16384;

#[derive(Debug, Clone)]
pub struct UpgradeRequest {
    pub path: String,
    pub host: Option<String>,
    pub websocket_key: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    #[error("not an HTTP GET request")]
    NotGet,
    #[error("path mismatch: expected '{0}', got '{1}'")]
    PathMismatch(String, String),
    #[error("host mismatch: expected '{0}', got '{1}'")]
    HostMismatch(String, String),
    #[error("header too large (>{MAX_HEADER_SIZE}B)")]
    HeaderTooLarge,
    #[error("not a websocket upgrade request")]
    NotWebSocket,
    #[error("missing 'Sec-WebSocket-Key' header")]
    MissingKey,
    #[error("incomplete HTTP headers (no \\r\\n\\r\\n found)")]
    Incomplete,
    #[error("invalid HTTP request line")]
    InvalidRequestLine,
    #[error("version mismatch: got '{0}', expected '13'")]
    BadVersion(String),
}

/// Compute the `Sec-WebSocket-Accept` header value from the client key.
pub fn compute_accept_key(key: &str) -> String {
    let combined = format!("{key}{WS_GUID}");
    let hash = Sha1::digest(combined.as_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash.as_slice())
}

/// Parse an HTTP upgrade request from a byte buffer.
///
/// Returns the parsed `UpgradeRequest` and any bytes following the `\r\n\r\n`
/// header terminator (early data / pipelined bytes).
pub fn parse_upgrade(
    buf: &[u8],
    expected_path: &str,
    expected_host: Option<&str>,
) -> Result<(UpgradeRequest, Vec<u8>), UpgradeError> {
    if buf.len() > MAX_HEADER_SIZE {
        return Err(UpgradeError::HeaderTooLarge);
    }

    // Find the double-CRLF that marks end of headers
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(UpgradeError::Incomplete)?;

    let headers_buf = &buf[..header_end];
    let remaining = buf[header_end + 4..].to_vec();

    // Parse request line: GET /path HTTP/1.1
    let headers_str =
        std::str::from_utf8(headers_buf).map_err(|_| UpgradeError::InvalidRequestLine)?;
    let mut lines = headers_str.lines();
    let request_line = lines.next().ok_or(UpgradeError::InvalidRequestLine)?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(UpgradeError::InvalidRequestLine)?;
    if method != "GET" {
        return Err(UpgradeError::NotGet);
    }

    let raw_path = parts.next().ok_or(UpgradeError::InvalidRequestLine)?;
    let _version = parts.next().ok_or(UpgradeError::InvalidRequestLine)?;

    // Extract path without query string
    let path = raw_path.split('?').next().unwrap_or(raw_path);
    let normalized_path = if !path.starts_with('/') {
        format!("/{path}")
    } else {
        path.to_string()
    };

    // Validate path (exact match)
    let expected = if expected_path.is_empty() || expected_path == "/" {
        "/"
    } else {
        expected_path
    };
    if normalized_path != expected {
        return Err(UpgradeError::PathMismatch(
            expected.to_string(),
            normalized_path,
        ));
    }

    // Parse headers
    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut websocket_key: Option<String> = None;
    let mut version: Option<String> = None;
    let mut host: Option<String> = None;

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key_lower = key.trim().to_ascii_lowercase();
            let value = value.trim();
            match key_lower.as_str() {
                "upgrade" => {
                    if value.eq_ignore_ascii_case("websocket") {
                        upgrade = true;
                    }
                }
                "connection" => {
                    if value.to_ascii_lowercase().contains("upgrade") {
                        connection_upgrade = true;
                    }
                }
                "sec-websocket-key" => {
                    websocket_key = Some(value.to_string());
                }
                "sec-websocket-version" => {
                    version = Some(value.to_string());
                }
                "host" => {
                    // Strip port and normalize to lowercase
                    let host_only = value.split(':').next().unwrap_or(value);
                    host = Some(host_only.to_ascii_lowercase());
                }
                _ => {}
            }
        }
    }

    if !upgrade || !connection_upgrade {
        return Err(UpgradeError::NotWebSocket);
    }

    let key = websocket_key.ok_or(UpgradeError::MissingKey)?;

    // Validate version (must be 13 per RFC 6455)
    if let Some(ref ver) = version
        && ver != "13"
    {
        return Err(UpgradeError::BadVersion(ver.clone()));
    }

    // Host validation (if configured)
    if let Some(expected) = expected_host {
        let got = host.as_deref().unwrap_or("");
        // Case-insensitive comparison
        if !expected.eq_ignore_ascii_case(got) {
            return Err(UpgradeError::HostMismatch(
                expected.to_string(),
                got.to_string(),
            ));
        }
    }

    Ok((
        UpgradeRequest {
            path: normalized_path,
            host,
            websocket_key: key,
        },
        remaining,
    ))
}

/// Format and return the 101 Switching Protocols HTTP response bytes.
pub fn build_upgrade_response(accept_key: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept_key}\r\n\
         \r\n"
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_upgrade_root_path() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let (upgrade, remaining) = parse_upgrade(req, "/", None).unwrap();
        assert_eq!(upgrade.path, "/");
        assert!(remaining.is_empty());
    }

    #[test]
    fn valid_upgrade_custom_path() {
        let req = b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let (upgrade, _) = parse_upgrade(req, "/ws", None).unwrap();
        assert_eq!(upgrade.path, "/ws");
    }

    #[test]
    fn valid_upgrade_path_with_query() {
        let req = b"GET /ws?foo=bar HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let (upgrade, _) = parse_upgrade(req, "/ws", None).unwrap();
        assert_eq!(upgrade.path, "/ws");
    }

    #[test]
    fn path_without_leading_slash() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let (upgrade, _) = parse_upgrade(req, "", None).unwrap();
        assert_eq!(upgrade.path, "/");
    }

    #[test]
    fn path_mismatch_rejected() {
        let req = b"GET /wrong HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let err = parse_upgrade(req, "/ws", None).unwrap_err();
        assert!(matches!(err, UpgradeError::PathMismatch(..)));
    }

    #[test]
    fn host_validation_match() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let (upgrade, _) = parse_upgrade(req, "/", Some("example.com")).unwrap();
        assert_eq!(upgrade.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn host_validation_case_insensitive() {
        let req = b"GET / HTTP/1.1\r\nHost: Example.COM\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let (upgrade, _) = parse_upgrade(req, "/", Some("example.com")).unwrap();
        assert_eq!(upgrade.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn host_mismatch_rejected() {
        let req = b"GET / HTTP/1.1\r\nHost: attacker.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let err = parse_upgrade(req, "/", Some("example.com")).unwrap_err();
        assert!(matches!(err, UpgradeError::HostMismatch(..)));
    }

    #[test]
    fn not_get_rejected() {
        let req = b"POST / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        let err = parse_upgrade(req, "/", None).unwrap_err();
        assert!(matches!(err, UpgradeError::NotGet));
    }

    #[test]
    fn missing_key_rejected() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let err = parse_upgrade(req, "/", None).unwrap_err();
        assert!(matches!(err, UpgradeError::MissingKey));
    }

    #[test]
    fn accept_key_rfc_test_vector() {
        // RFC 6455 §4.2.2 example
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = compute_accept_key(key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn build_upgrade_response_format() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = compute_accept_key(key);
        let resp = build_upgrade_response(&accept);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 101 "));
        assert!(resp_str.contains("Upgrade: websocket"));
        assert!(resp_str.contains("Connection: Upgrade"));
        assert!(resp_str.contains(&format!("Sec-WebSocket-Accept: {accept}")));
        assert!(resp_str.ends_with("\r\n\r\n"));
    }

    #[test]
    fn remaining_bytes_after_headers() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\npipelined data here";
        let (_, remaining) = parse_upgrade(req, "/", None).unwrap();
        assert_eq!(remaining, b"pipelined data here");
    }
}
