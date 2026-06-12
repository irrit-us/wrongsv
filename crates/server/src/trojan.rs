use std::io::Read;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha224};
use thiserror::Error;
use wrongsv_net_types::{Address, Port};

const PASSWORD_HASH_HEX_LEN: usize = 56;
const MAX_REQUEST_HEAD_LEN: usize = 8192;

#[derive(Clone)]
pub struct TrojanConfig {
    pub passwords: Vec<TrojanPasswordEntry>,
    pub tls_config: Arc<rustls::ServerConfig>,
    pub dest: Option<String>,
}

#[derive(Clone)]
pub struct TrojanPasswordEntry {
    pub hash: [u8; PASSWORD_HASH_HEX_LEN],
    pub email: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanRequest {
    pub command: TrojanCommand,
    pub address: Address,
    pub port: Port,
    pub initial_data: Vec<u8>,
    /// Email of the matched user (None for legacy unnamed password).
    pub email: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanUdpPacket {
    pub address: Address,
    pub port: Port,
    pub payload: Vec<u8>,
    pub consumed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanCommand {
    Connect,
    UdpAssociate,
}

impl TrojanCommand {
    fn from_byte(byte: u8) -> Result<Self, TrojanError> {
        match byte {
            0x01 => Ok(Self::Connect),
            0x03 => Ok(Self::UdpAssociate),
            other => Err(TrojanError::UnsupportedCommand(other)),
        }
    }
}

#[derive(Debug)]
pub struct TrojanAcceptError {
    pub error: TrojanError,
    pub buffered_data: Vec<u8>,
}

impl std::fmt::Display for TrojanAcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Trojan accept failed: {}", self.error)
    }
}

impl std::error::Error for TrojanAcceptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug, Error)]
pub enum TrojanError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("invalid Trojan request")]
    InvalidRequest,
    #[error("Trojan authentication failed")]
    AuthFailed,
    #[error("unsupported Trojan command: 0x{0:02x}")]
    UnsupportedCommand(u8),
    #[error("Trojan request head too large")]
    RequestHeadTooLarge,
    #[error("unexpected EOF before Trojan request")]
    UnexpectedEof,
}

pub fn password_hash_hex(password: &str) -> [u8; PASSWORD_HASH_HEX_LEN] {
    let digest = Sha224::digest(password.as_bytes());
    let mut out = [0u8; PASSWORD_HASH_HEX_LEN];
    for (i, byte) in digest.iter().enumerate() {
        out[i * 2] = lower_hex(byte >> 4);
        out[i * 2 + 1] = lower_hex(byte & 0x0f);
    }
    out
}

fn lower_hex(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'a' + (nibble - 10),
        _ => unreachable!("nibble is 4 bits"),
    }
}

pub fn read_request(
    stream: &mut wrongsv_anytls::AnyTlsStream,
    config: &TrojanConfig,
) -> Result<TrojanRequest, TrojanAcceptError> {
    let mut data = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        match parse_request(&data, &config.passwords) {
            Ok(Some(request)) => return Ok(request),
            Ok(None) => {}
            Err(error) => {
                return Err(TrojanAcceptError {
                    error,
                    buffered_data: data,
                });
            }
        }

        if data.len() >= MAX_REQUEST_HEAD_LEN {
            return Err(TrojanAcceptError {
                error: TrojanError::RequestHeadTooLarge,
                buffered_data: data,
            });
        }

        match stream.read(&mut buf) {
            Ok(0) => {
                return Err(TrojanAcceptError {
                    error: TrojanError::UnexpectedEof,
                    buffered_data: data,
                });
            }
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                return Err(TrojanAcceptError {
                    error: TrojanError::Io(e),
                    buffered_data: data,
                });
            }
        }
    }
}

fn parse_request(
    data: &[u8],
    passwords: &[TrojanPasswordEntry],
) -> Result<Option<TrojanRequest>, TrojanError> {
    if has_non_hex_password_prefix(data) {
        return Err(TrojanError::InvalidRequest);
    }
    if data.len() < PASSWORD_HASH_HEX_LEN + 2 {
        return Ok(None);
    }
    if &data[PASSWORD_HASH_HEX_LEN..PASSWORD_HASH_HEX_LEN + 2] != b"\r\n" {
        return Err(TrojanError::InvalidRequest);
    }
    let matched = passwords
        .iter()
        .find(|entry| hash_eq_ignore_ascii_case(&data[..PASSWORD_HASH_HEX_LEN], &entry.hash))
        .ok_or(TrojanError::AuthFailed)?;
    let email = matched.email.clone();

    let mut pos = PASSWORD_HASH_HEX_LEN + 2;
    if data.len() < pos + 2 {
        return Ok(None);
    }
    let command = TrojanCommand::from_byte(data[pos])?;
    pos += 1;
    let address_type = data[pos];
    pos += 1;

    let Some(address) = parse_socks5_address(data, &mut pos, address_type)? else {
        return Ok(None);
    };

    if data.len() < pos + 4 {
        return Ok(None);
    }
    let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
    if port == 0 && command == TrojanCommand::Connect {
        return Err(TrojanError::InvalidRequest);
    }
    pos += 2;
    if &data[pos..pos + 2] != b"\r\n" {
        return Err(TrojanError::InvalidRequest);
    }
    pos += 2;

    Ok(Some(TrojanRequest {
        command,
        address,
        port: Port(port),
        initial_data: data[pos..].to_vec(),
        email,
    }))
}

pub fn parse_udp_packet(data: &[u8]) -> Result<Option<TrojanUdpPacket>, TrojanError> {
    let mut pos = 0;
    if data.is_empty() {
        return Ok(None);
    }
    let address_type = data[pos];
    pos += 1;
    let Some(address) = parse_socks5_address(data, &mut pos, address_type)? else {
        return Ok(None);
    };
    if data.len() < pos + 6 {
        return Ok(None);
    }
    let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
    if port == 0 {
        return Err(TrojanError::InvalidRequest);
    }
    pos += 2;
    let payload_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if &data[pos..pos + 2] != b"\r\n" {
        return Err(TrojanError::InvalidRequest);
    }
    pos += 2;
    if data.len() < pos + payload_len {
        return Ok(None);
    }

    Ok(Some(TrojanUdpPacket {
        address,
        port: Port(port),
        payload: data[pos..pos + payload_len].to_vec(),
        consumed: pos + payload_len,
    }))
}

pub fn write_udp_packet(
    out: &mut Vec<u8>,
    address: &Address,
    port: Port,
    payload: &[u8],
) -> Result<(), TrojanError> {
    if port.0 == 0 || payload.len() > u16::MAX as usize {
        return Err(TrojanError::InvalidRequest);
    }
    write_socks5_address(out, address)?;
    out.extend_from_slice(&port.0.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(payload);
    Ok(())
}

fn parse_socks5_address(
    data: &[u8],
    pos: &mut usize,
    address_type: u8,
) -> Result<Option<Address>, TrojanError> {
    match address_type {
        0x01 => {
            if data.len() < *pos + 4 {
                return Ok(None);
            }
            let octets: [u8; 4] = data[*pos..*pos + 4]
                .try_into()
                .map_err(|_| TrojanError::InvalidRequest)?;
            *pos += 4;
            Ok(Some(Address::IPv4(octets)))
        }
        0x03 => {
            if data.len() < *pos + 1 {
                return Ok(None);
            }
            let len = data[*pos] as usize;
            *pos += 1;
            if len == 0 {
                return Err(TrojanError::InvalidRequest);
            }
            if data.len() < *pos + len {
                return Ok(None);
            }
            let domain = std::str::from_utf8(&data[*pos..*pos + len])
                .map_err(|_| TrojanError::InvalidRequest)?;
            *pos += len;
            Ok(Some(Address::Domain(domain.to_string())))
        }
        0x04 => {
            if data.len() < *pos + 16 {
                return Ok(None);
            }
            let octets: [u8; 16] = data[*pos..*pos + 16]
                .try_into()
                .map_err(|_| TrojanError::InvalidRequest)?;
            *pos += 16;
            Ok(Some(Address::IPv6(octets)))
        }
        _ => Err(TrojanError::InvalidRequest),
    }
}

fn write_socks5_address(out: &mut Vec<u8>, address: &Address) -> Result<(), TrojanError> {
    match address {
        Address::IPv4(octets) => {
            out.push(0x01);
            out.extend_from_slice(octets);
        }
        Address::Domain(domain) => {
            let len = u8::try_from(domain.len()).map_err(|_| TrojanError::InvalidRequest)?;
            out.push(0x03);
            out.push(len);
            out.extend_from_slice(domain.as_bytes());
        }
        Address::IPv6(octets) => {
            out.push(0x04);
            out.extend_from_slice(octets);
        }
    }
    Ok(())
}

fn has_non_hex_password_prefix(data: &[u8]) -> bool {
    data.iter()
        .take(PASSWORD_HASH_HEX_LEN)
        .any(|byte| !byte.is_ascii_hexdigit())
}

fn hash_eq_ignore_ascii_case(received: &[u8], expected: &[u8; PASSWORD_HASH_HEX_LEN]) -> bool {
    let mut acc = 0u8;
    for i in 0..PASSWORD_HASH_HEX_LEN {
        acc |= received[i].to_ascii_lowercase() ^ expected[i];
    }
    acc == 0
}

pub fn accept_tls(
    mut stream: TcpStream,
    config: &TrojanConfig,
) -> Result<wrongsv_anytls::AnyTlsStream, TrojanError> {
    let mut conn = rustls::ServerConnection::new(Arc::clone(&config.tls_config))
        .map_err(|e| TrojanError::Tls(format!("create connection: {e}")))?;
    loop {
        match conn.complete_io(&mut stream) {
            Ok((_, _)) if !conn.is_handshaking() => break,
            Ok(_) => {}
            Err(e) => return Err(TrojanError::Tls(format!("handshake: {e}"))),
        }
    }
    Ok(wrongsv_anytls::AnyTlsStream::from_parts(conn, stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_prefix(password: &str) -> Vec<u8> {
        let mut data = password_hash_hex(password).to_vec();
        data.extend_from_slice(b"\r\n");
        data
    }

    fn entries(passwords: &[&str]) -> Vec<TrojanPasswordEntry> {
        passwords
            .iter()
            .map(|p| TrojanPasswordEntry {
                hash: password_hash_hex(p),
                email: None,
            })
            .collect()
    }

    #[test]
    fn test_password_hash_hex_sha224() {
        assert_eq!(
            std::str::from_utf8(&password_hash_hex("password")).unwrap(),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[test]
    fn test_parse_connect_domain_with_payload() {
        let mut data = request_prefix("secret");
        data.extend_from_slice(&[0x01, 0x03, 11]);
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        data.extend_from_slice(b"\r\nhello");

        let request = parse_request(&data, &entries(&["secret"]))
            .unwrap()
            .unwrap();

        assert_eq!(request.command, TrojanCommand::Connect);
        assert_eq!(request.address, Address::Domain("example.com".into()));
        assert_eq!(request.port, Port(443));
        assert_eq!(request.initial_data, b"hello");
    }

    #[test]
    fn test_parse_connect_ipv4() {
        let mut data = request_prefix("secret");
        data.extend_from_slice(&[0x01, 0x01, 127, 0, 0, 1]);
        data.extend_from_slice(&80u16.to_be_bytes());
        data.extend_from_slice(b"\r\n");

        let request = parse_request(&data, &entries(&["secret"]))
            .unwrap()
            .unwrap();

        assert_eq!(request.address, Address::IPv4([127, 0, 0, 1]));
        assert_eq!(request.port, Port(80));
    }

    #[test]
    fn test_parse_connect_ipv6() {
        let mut data = request_prefix("secret");
        data.extend_from_slice(&[0x01, 0x04]);
        data.extend_from_slice(&[0u8; 15]);
        data.push(1);
        data.extend_from_slice(&443u16.to_be_bytes());
        data.extend_from_slice(b"\r\n");

        let request = parse_request(&data, &entries(&["secret"]))
            .unwrap()
            .unwrap();

        assert!(matches!(request.address, Address::IPv6(_)));
        assert_eq!(request.port, Port(443));
    }

    #[test]
    fn test_parse_udp_associate_allows_zero_initial_port() {
        let mut data = request_prefix("secret");
        data.extend_from_slice(&[0x03, 0x01, 0, 0, 0, 0]);
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(b"\r\n");

        let request = parse_request(&data, &entries(&["secret"]))
            .unwrap()
            .unwrap();

        assert_eq!(request.command, TrojanCommand::UdpAssociate);
        assert_eq!(request.address, Address::IPv4([0, 0, 0, 0]));
        assert_eq!(request.port, Port(0));
    }

    #[test]
    fn test_udp_packet_roundtrip() {
        let mut data = Vec::new();
        write_udp_packet(
            &mut data,
            &Address::Domain("example.com".into()),
            Port(53),
            b"dns payload",
        )
        .unwrap();

        let packet = parse_udp_packet(&data).unwrap().unwrap();
        assert_eq!(packet.address, Address::Domain("example.com".into()));
        assert_eq!(packet.port, Port(53));
        assert_eq!(packet.payload, b"dns payload");
        assert_eq!(packet.consumed, data.len());
    }

    #[test]
    fn test_udp_packet_waits_for_complete_payload() {
        let mut data = Vec::new();
        write_udp_packet(&mut data, &Address::IPv4([127, 0, 0, 1]), Port(53), b"abc").unwrap();
        data.pop();

        assert!(parse_udp_packet(&data).unwrap().is_none());
    }

    #[test]
    fn test_parse_rejects_bad_password() {
        let mut data = request_prefix("wrong");
        data.extend_from_slice(&[0x01, 0x03, 11]);
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        data.extend_from_slice(b"\r\n");

        assert!(matches!(
            parse_request(&data, &entries(&["secret"])),
            Err(TrojanError::AuthFailed)
        ));
    }

    #[test]
    fn test_parse_rejects_plain_http_probe() {
        assert!(matches!(
            parse_request(b"GET / HTTP/1.1\r\n\r\n", &entries(&["secret"])),
            Err(TrojanError::InvalidRequest)
        ));
    }

    #[test]
    fn test_parse_rejects_unsupported_command() {
        let mut data = request_prefix("secret");
        data.extend_from_slice(&[0x02, 0x01, 127, 0, 0, 1]);
        data.extend_from_slice(&80u16.to_be_bytes());
        data.extend_from_slice(b"\r\n");

        assert!(matches!(
            parse_request(&data, &entries(&["secret"])),
            Err(TrojanError::UnsupportedCommand(0x02))
        ));
    }
}
