use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tracing::{debug, info, trace};
use wrongsv_protocol::RequestCommand;
use wrongsv_vless::MemoryValidator;

use crate::config::HttpUpgradeServerConfig;

use super::*;

const MAX_HTTPUPGRADE_HEADER_SIZE: usize = 16384;

#[derive(Clone)]
pub(crate) struct HttpUpgradeConfig {
    pub path: String,
    pub host: Option<String>,
    pub max_early_data: usize,
    pub early_data_header_name: Option<String>,
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
    #[allow(dead_code)]
    pub tls_dest: Option<String>,
}

#[derive(Debug)]
pub(crate) struct HttpUpgradeRequest {
    pub path: String,
    #[allow(dead_code)]
    pub host: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HttpUpgradeError {
    #[error("not an HTTP GET request")]
    NotGet,
    #[error("path mismatch: expected '{0}', got '{1}'")]
    PathMismatch(String, String),
    #[error("host mismatch: expected '{0}', got '{1}'")]
    HostMismatch(String, String),
    #[error("header too large (>{MAX_HTTPUPGRADE_HEADER_SIZE}B)")]
    HeaderTooLarge,
    #[error("not an HTTPUpgrade request")]
    NotHttpUpgrade,
    #[error("incomplete HTTP headers (no \\r\\n\\r\\n found)")]
    Incomplete,
    #[error("invalid HTTP request line")]
    InvalidRequestLine,
    #[error("invalid early-data header")]
    InvalidEarlyData,
    #[error("early data exceeds configured limit")]
    EarlyDataTooLarge,
}

pub(crate) fn parse_httpupgrade_config(
    hc: &HttpUpgradeServerConfig,
) -> Result<HttpUpgradeConfig, String> {
    let path = if hc.path.starts_with('/') {
        hc.path.clone()
    } else {
        format!("/{}", hc.path)
    };
    let (tls_config, tls_dest) = match &hc.tls {
        Some(tls) => {
            let (cert_pem, key_pem) = match (&tls.certificate, &tls.key) {
                (Some(c), Some(k)) => (c.clone(), k.clone()),
                _ => {
                    let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                        .map_err(|e| format!("httpupgrade tls cert: {e}"))?;
                    (cert, key)
                }
            };
            let server_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
                .map_err(|e| format!("httpupgrade tls config: {e}"))?;
            (Some(Arc::new(server_config)), tls.dest.clone())
        }
        None => (None, None),
    };
    Ok(HttpUpgradeConfig {
        path,
        host: hc.host.clone(),
        max_early_data: hc.max_early_data,
        early_data_header_name: hc.early_data_header_name.clone(),
        tls_config,
        tls_dest,
    })
}

pub(crate) fn parse_httpupgrade_request(
    buf: &[u8],
    config: &HttpUpgradeConfig,
) -> Result<(HttpUpgradeRequest, Vec<u8>), HttpUpgradeError> {
    if buf.len() > MAX_HTTPUPGRADE_HEADER_SIZE {
        return Err(HttpUpgradeError::HeaderTooLarge);
    }

    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(HttpUpgradeError::Incomplete)?;
    let headers_buf = &buf[..header_end];
    let pipelined = &buf[header_end + 4..];

    let headers_str =
        std::str::from_utf8(headers_buf).map_err(|_| HttpUpgradeError::InvalidRequestLine)?;
    let mut lines = headers_str.lines();
    let request_line = lines.next().ok_or(HttpUpgradeError::InvalidRequestLine)?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(HttpUpgradeError::InvalidRequestLine)?;
    if method != "GET" {
        return Err(HttpUpgradeError::NotGet);
    }
    let raw_path = parts.next().ok_or(HttpUpgradeError::InvalidRequestLine)?;
    let _version = parts.next().ok_or(HttpUpgradeError::InvalidRequestLine)?;

    let path = raw_path.split('?').next().unwrap_or(raw_path);
    let normalized_path = if !path.starts_with('/') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    let expected = if config.path.is_empty() || config.path == "/" {
        "/"
    } else {
        config.path.as_str()
    };
    if normalized_path != expected {
        return Err(HttpUpgradeError::PathMismatch(
            expected.to_string(),
            normalized_path,
        ));
    }

    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut host: Option<String> = None;
    let mut early_data_header: Option<String> = None;
    let early_header_name = config
        .early_data_header_name
        .as_deref()
        .map(str::to_ascii_lowercase);

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key_lower = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key_lower.as_str() {
            "upgrade" => {
                if value.eq_ignore_ascii_case("websocket") {
                    upgrade = true;
                }
            }
            "connection" => {
                if value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
                {
                    connection_upgrade = true;
                }
            }
            "host" => {
                host = Some(normalize_host(value));
            }
            _ if early_header_name.as_deref() == Some(key_lower.as_str()) => {
                early_data_header = Some(value.to_string());
            }
            _ => {}
        }
    }

    if !upgrade || !connection_upgrade {
        return Err(HttpUpgradeError::NotHttpUpgrade);
    }

    if let Some(expected_host) = &config.host {
        let got = host.as_deref().unwrap_or("");
        if !expected_host.eq_ignore_ascii_case(got) {
            return Err(HttpUpgradeError::HostMismatch(
                expected_host.clone(),
                got.to_string(),
            ));
        }
    }

    let mut initial_data = Vec::new();
    if config.max_early_data > 0
        && let Some(value) = early_data_header
        && !value.is_empty()
    {
        let decoded = base64::engine::general_purpose::URL_SAFE
            .decode(value.as_bytes())
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value.as_bytes()))
            .map_err(|_| HttpUpgradeError::InvalidEarlyData)?;
        if decoded.len() > config.max_early_data {
            return Err(HttpUpgradeError::EarlyDataTooLarge);
        }
        initial_data.extend_from_slice(&decoded);
    }
    initial_data.extend_from_slice(pipelined);

    Ok((
        HttpUpgradeRequest {
            path: normalized_path,
            host,
        },
        initial_data,
    ))
}

fn normalize_host(value: &str) -> String {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return rest[..end].to_ascii_lowercase();
    }
    value
        .split(':')
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase()
}

pub(crate) fn build_httpupgrade_response() -> &'static [u8] {
    b"HTTP/1.1 101 Switching Protocols\r\n\
      Upgrade: websocket\r\n\
      Connection: Upgrade\r\n\
      \r\n"
}

pub(crate) fn handle_httpupgrade_connection(
    stream: TcpStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    httpupgrade_config: &HttpUpgradeConfig,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} HTTPUpgrade connection");

    match &httpupgrade_config.tls_config {
        Some(tls_config) => {
            let mut conn = rustls::ServerConnection::new(Arc::clone(tls_config))
                .map_err(|e| format!("httpupgrade+tls create: {e}"))?;
            let mut sock = stream;
            loop {
                match conn.complete_io(&mut sock) {
                    Ok((_, _)) if !conn.is_handshaking() => break,
                    Ok(_) => {}
                    Err(e) => return Err(format!("httpupgrade+tls handshake: {e}").into()),
                }
            }
            info!("{peer} TLS+HTTPUpgrade: TLS handshake done, upgrading...");

            let mut header_buf = Vec::new();
            read_tls_httpupgrade_headers(&mut conn, &mut sock, &mut header_buf)?;
            let (upgrade_req, initial_data) =
                parse_httpupgrade_request(&header_buf, httpupgrade_config)?;

            conn.writer().write_all(build_httpupgrade_response())?;
            while conn.wants_write() {
                conn.write_tls(&mut sock)?;
            }

            let tls_stream = wrongsv_anytls::AnyTlsStream::from_parts(conn, sock);
            info!(
                "{peer} TLS+HTTPUpgrade upgraded on path '{}'",
                upgrade_req.path
            );
            handle_vless_over_httpupgrade_tls(
                tls_stream,
                validator,
                kyber_sk,
                peer,
                initial_data,
                metrics,
            )
        }
        None => {
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            let mut header_buf = Vec::new();
            let _n = stream_read_upgrade(&stream, &mut header_buf)?;
            let (upgrade_req, initial_data) =
                parse_httpupgrade_request(&header_buf, httpupgrade_config)?;

            let mut raw_stream = stream;
            raw_stream.write_all(build_httpupgrade_response())?;
            raw_stream.set_read_timeout(None)?;

            info!("{peer} HTTPUpgrade upgraded on path '{}'", upgrade_req.path);
            handle_vless_over_httpupgrade_raw(
                raw_stream,
                validator,
                kyber_sk,
                peer,
                initial_data,
                metrics,
            )
        }
    }
}

fn read_tls_httpupgrade_headers(
    conn: &mut rustls::ServerConnection,
    sock: &mut TcpStream,
    buf: &mut Vec<u8>,
) -> std::io::Result<()> {
    buf.clear();
    let mut tmp = [0u8; 4096];
    loop {
        match conn.reader().read(&mut tmp) {
            Ok(n) if n > 0 => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    return Ok(());
                }
                if buf.len() >= MAX_HTTPUPGRADE_HEADER_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "HTTPUpgrade header too large",
                    ));
                }
            }
            Ok(_) => {
                let n = conn.read_tls(sock)?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed during HTTPUpgrade",
                    ));
                }
                conn.process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let n = conn.read_tls(sock)?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed during HTTPUpgrade",
                    ));
                }
                conn.process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            }
            Err(e) => return Err(e),
        }
    }
}

fn read_first_vless_chunk<S: Read>(
    stream: &mut S,
    mut initial_data: Vec<u8>,
    peer: SocketAddr,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if initial_data.is_empty() || initial_data.len() < 18 {
        let mut buf = [0u8; 8192];
        let n = stream.read(&mut buf)?;
        if n == 0 && initial_data.is_empty() {
            return Err("HTTPUpgrade closed before VLESS header".into());
        }
        initial_data.extend_from_slice(&buf[..n]);
    }
    trace!(
        "{peer} HTTPUpgrade read {} bytes VLESS header/body",
        initial_data.len()
    );
    Ok(initial_data)
}

fn handle_vless_over_httpupgrade_raw(
    mut stream: TcpStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    peer: SocketAddr,
    initial_data: Vec<u8>,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let first = read_first_vless_chunk(&mut stream, initial_data, peer)?;
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
    stream.write_all(&resp_buf)?;

    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_udp(stream, request, remaining_body, tap)?;
        debug!("{peer} HTTPUpgrade UDP relay finished");
        return Ok(());
    }

    let target = connect_tcp_target(&request.address, request.port)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;
    stream.set_read_timeout(None)?;

    if use_vision {
        relay_vision(stream, target, &decoded.user_sent_id, &account.testseed, tap)?;
    } else {
        relay_raw_with_initial(stream, target, remaining_body, tap)?;
    }
    debug!("{peer} HTTPUpgrade TCP relay finished");
    Ok(())
}

fn handle_vless_over_httpupgrade_tls(
    mut tls_stream: wrongsv_anytls::AnyTlsStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    peer: SocketAddr,
    initial_data: Vec<u8>,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let first = read_first_vless_chunk(&mut tls_stream, initial_data, peer)?;
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
    tls_stream.write_all(&resp_buf)?;
    tls_stream.flush()?;

    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_anytls_udp(tls_stream, request, remaining_body)?;
        debug!("{peer} TLS+HTTPUpgrade UDP relay finished");
        return Ok(());
    }

    let target = connect_tcp_target(&request.address, request.port)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;

    if use_vision {
        relay_anytls_vision(
            tls_stream,
            target,
            &decoded.user_sent_id,
            &account.testseed,
            remaining_body,
        )?;
    } else {
        relay_anytls_raw(tls_stream, target, remaining_body)?;
    }
    debug!("{peer} TLS+HTTPUpgrade TCP relay finished");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(path: &str) -> HttpUpgradeConfig {
        HttpUpgradeConfig {
            path: path.to_string(),
            host: None,
            max_early_data: 0,
            early_data_header_name: None,
            tls_config: None,
            tls_dest: None,
        }
    }

    #[test]
    fn parses_httpupgrade_request() {
        let req = b"GET /up HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n\r\n";
        let (upgrade, remaining) = parse_httpupgrade_request(req, &config("/up")).unwrap();
        assert_eq!(upgrade.path, "/up");
        assert!(remaining.is_empty());
    }

    #[test]
    fn strips_query_before_path_match() {
        let req = b"GET /up?ed=1 HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let (upgrade, _) = parse_httpupgrade_request(req, &config("/up")).unwrap();
        assert_eq!(upgrade.path, "/up");
    }

    #[test]
    fn preserves_pipelined_bytes() {
        let req = b"GET /up HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nvless";
        let (_, remaining) = parse_httpupgrade_request(req, &config("/up")).unwrap();
        assert_eq!(remaining, b"vless");
    }

    #[test]
    fn decodes_early_data_before_pipelined_bytes() {
        let mut cfg = config("/up");
        cfg.max_early_data = 32;
        cfg.early_data_header_name = Some("X-ED".into());
        let req = b"GET /up HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-ED: aGVsbG8=\r\n\r\nworld";
        let (_, remaining) = parse_httpupgrade_request(req, &cfg).unwrap();
        assert_eq!(remaining, b"helloworld");
    }

    #[test]
    fn rejects_host_mismatch() {
        let mut cfg = config("/up");
        cfg.host = Some("example.com".into());
        let req = b"GET /up HTTP/1.1\r\nHost: attacker.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let err = parse_httpupgrade_request(req, &cfg).unwrap_err();
        assert!(matches!(err, HttpUpgradeError::HostMismatch(..)));
    }

    #[test]
    fn rejects_non_upgrade_request() {
        let req = b"GET /up HTTP/1.1\r\nConnection: close\r\n\r\n";
        let err = parse_httpupgrade_request(req, &config("/up")).unwrap_err();
        assert!(matches!(err, HttpUpgradeError::NotHttpUpgrade));
    }
}
