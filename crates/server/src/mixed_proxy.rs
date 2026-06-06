use base64::Engine;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use wrongsv_net_types::{Address, Port};

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_NO_AUTH: u8 = 0x00;
const SOCKS_USERPASS: u8 = 0x02;
const SOCKS_NO_ACCEPTABLE_METHODS: u8 = 0xff;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_REP_SUCCEEDED: u8 = 0x00;
const SOCKS_REP_GENERAL_FAILURE: u8 = 0x01;
const SOCKS_REP_CONNECTION_REFUSED: u8 = 0x05;
const SOCKS_REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const SOCKS_REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
const HTTP_HEADER_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct MixedProxyConfig {
    credentials: Option<Credentials>,
}

impl MixedProxyConfig {
    pub fn new(
        username: Option<String>,
        password: Option<String>,
    ) -> Result<Self, MixedProxyError> {
        let credentials = match (username, password) {
            (None, None) => None,
            (Some(username), Some(password)) => Some(Credentials::new(username, password)?),
            _ => return Err(MixedProxyError::InvalidCredentials),
        };
        Ok(Self { credentials })
    }

    fn credentials(&self) -> Option<&Credentials> {
        self.credentials.as_ref()
    }
}

#[derive(Debug, Clone)]
struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    fn new(username: String, password: String) -> Result<Self, MixedProxyError> {
        if username.is_empty()
            || username.len() > 255
            || password.is_empty()
            || password.len() > 255
        {
            return Err(MixedProxyError::InvalidCredentials);
        }
        Ok(Self { username, password })
    }

    fn matches(&self, username: &[u8], password: &[u8]) -> bool {
        self.username.as_bytes() == username && self.password.as_bytes() == password
    }

    fn basic_value(&self) -> String {
        format!("{}:{}", self.username, self.password)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MixedProtocol {
    Socks5,
    HttpConnect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub protocol: MixedProtocol,
    pub address: Address,
    pub port: Port,
    pub initial_data: Vec<u8>,
}

pub fn detect_protocol(stream: &TcpStream) -> Result<MixedProtocol, MixedProxyError> {
    let mut first = [0u8; 1];
    let n = stream.peek(&mut first)?;
    if n == 0 {
        return Err(MixedProxyError::UnexpectedEof);
    }
    if first[0] == SOCKS_VERSION {
        Ok(MixedProtocol::Socks5)
    } else {
        Ok(MixedProtocol::HttpConnect)
    }
}

pub fn accept_socks5_connect(
    stream: &mut TcpStream,
    config: &MixedProxyConfig,
) -> Result<ConnectRequest, MixedProxyError> {
    negotiate_socks_auth(stream, config.credentials())?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != SOCKS_VERSION || header[2] != 0x00 {
        let _ = write_socks5_reply(stream, SOCKS_REP_GENERAL_FAILURE, None);
        return Err(MixedProxyError::InvalidSocksRequest);
    }
    if header[1] != SOCKS_CMD_CONNECT {
        let _ = write_socks5_reply(stream, SOCKS_REP_COMMAND_NOT_SUPPORTED, None);
        return Err(MixedProxyError::UnsupportedSocksCommand(header[1]));
    }

    let address = read_socks_address(stream, header[3])?;
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    let port = Port(u16::from_be_bytes(port));

    Ok(ConnectRequest {
        protocol: MixedProtocol::Socks5,
        address,
        port,
        initial_data: Vec::new(),
    })
}

fn negotiate_socks_auth(
    stream: &mut TcpStream,
    credentials: Option<&Credentials>,
) -> Result<(), MixedProxyError> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting)?;
    if greeting[0] != SOCKS_VERSION {
        return Err(MixedProxyError::UnsupportedSocksVersion(greeting[0]));
    }
    let nmethods = greeting[1] as usize;
    if nmethods == 0 {
        let _ = stream.write_all(&[SOCKS_VERSION, SOCKS_NO_ACCEPTABLE_METHODS]);
        return Err(MixedProxyError::NoAcceptableSocksAuth);
    }

    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods)?;
    match credentials {
        Some(credentials) if methods.contains(&SOCKS_USERPASS) => {
            stream.write_all(&[SOCKS_VERSION, SOCKS_USERPASS])?;
            authenticate_socks_userpass(stream, credentials)
        }
        Some(_) => {
            stream.write_all(&[SOCKS_VERSION, SOCKS_NO_ACCEPTABLE_METHODS])?;
            Err(MixedProxyError::NoAcceptableSocksAuth)
        }
        None if methods.contains(&SOCKS_NO_AUTH) => {
            stream.write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH])?;
            Ok(())
        }
        None => {
            stream.write_all(&[SOCKS_VERSION, SOCKS_NO_ACCEPTABLE_METHODS])?;
            Err(MixedProxyError::NoAcceptableSocksAuth)
        }
    }
}

fn authenticate_socks_userpass(
    stream: &mut TcpStream,
    credentials: &Credentials,
) -> Result<(), MixedProxyError> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    if header[0] != 0x01 || header[1] == 0 {
        let _ = stream.write_all(&[0x01, 0x01]);
        return Err(MixedProxyError::SocksAuthFailed);
    }

    let mut username = vec![0u8; header[1] as usize];
    stream.read_exact(&mut username)?;
    let mut plen = [0u8; 1];
    stream.read_exact(&mut plen)?;
    if plen[0] == 0 {
        let _ = stream.write_all(&[0x01, 0x01]);
        return Err(MixedProxyError::SocksAuthFailed);
    }
    let mut password = vec![0u8; plen[0] as usize];
    stream.read_exact(&mut password)?;

    if credentials.matches(&username, &password) {
        stream.write_all(&[0x01, 0x00])?;
        Ok(())
    } else {
        stream.write_all(&[0x01, 0x01])?;
        Err(MixedProxyError::SocksAuthFailed)
    }
}

fn read_socks_address(stream: &mut TcpStream, atyp: u8) -> Result<Address, MixedProxyError> {
    match atyp {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets)?;
            Ok(Address::IPv4(octets))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            if len[0] == 0 {
                let _ = write_socks5_reply(stream, SOCKS_REP_ADDRESS_TYPE_NOT_SUPPORTED, None);
                return Err(MixedProxyError::InvalidSocksAddress);
            }
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name)?;
            let name = String::from_utf8(name).map_err(|_| MixedProxyError::InvalidSocksAddress)?;
            Ok(Address::Domain(name))
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets)?;
            Ok(Address::IPv6(octets))
        }
        other => {
            let _ = write_socks5_reply(stream, SOCKS_REP_ADDRESS_TYPE_NOT_SUPPORTED, None);
            Err(MixedProxyError::UnsupportedSocksAddressType(other))
        }
    }
}

pub fn accept_http_connect(
    stream: &mut TcpStream,
    config: &MixedProxyConfig,
) -> Result<ConnectRequest, MixedProxyError> {
    let (head, initial_data) = read_http_head(stream)?;
    let head = String::from_utf8(head).map_err(|_| MixedProxyError::InvalidHttpRequest)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(MixedProxyError::InvalidHttpRequest)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(MixedProxyError::InvalidHttpRequest)?;
    let target = parts.next().ok_or(MixedProxyError::InvalidHttpRequest)?;
    let version = parts.next().ok_or(MixedProxyError::InvalidHttpRequest)?;
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return Err(MixedProxyError::InvalidHttpRequest);
    }
    if method != "CONNECT" {
        return Err(MixedProxyError::UnsupportedHttpMethod(method.to_string()));
    }

    if let Some(credentials) = config.credentials() {
        let proxy_auth = lines
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("proxy-authorization"))
            .map(|(_, value)| value.trim());
        authenticate_http_basic(proxy_auth, credentials)?;
    }

    let (address, port) = parse_authority(target)?;
    Ok(ConnectRequest {
        protocol: MixedProtocol::HttpConnect,
        address,
        port,
        initial_data,
    })
}

fn read_http_head(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>), MixedProxyError> {
    let mut data = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        if let Some(pos) = find_header_end(&data) {
            let initial = data.split_off(pos + 4);
            return Ok((data, initial));
        }
        if data.len() >= HTTP_HEADER_LIMIT {
            return Err(MixedProxyError::HttpHeaderTooLarge);
        }
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(MixedProxyError::UnexpectedEof);
        }
        data.extend_from_slice(&buf[..n]);
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn authenticate_http_basic(
    proxy_auth: Option<&str>,
    credentials: &Credentials,
) -> Result<(), MixedProxyError> {
    let value = proxy_auth.ok_or(MixedProxyError::HttpAuthRequired)?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or(MixedProxyError::HttpAuthRequired)?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(MixedProxyError::HttpAuthRequired);
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token.trim())
        .map_err(|_| MixedProxyError::HttpAuthRequired)?;
    if decoded == credentials.basic_value().as_bytes() {
        Ok(())
    } else {
        Err(MixedProxyError::HttpAuthFailed)
    }
}

fn parse_authority(target: &str) -> Result<(Address, Port), MixedProxyError> {
    let (host, port, bracketed) = if let Some(rest) = target.strip_prefix('[') {
        let end = rest.find(']').ok_or(MixedProxyError::InvalidHttpTarget)?;
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .ok_or(MixedProxyError::InvalidHttpTarget)?;
        (host, port, true)
    } else {
        let (host, port) = target
            .rsplit_once(':')
            .ok_or(MixedProxyError::InvalidHttpTarget)?;
        (host, port, false)
    };
    if host.is_empty() || port.is_empty() || (!bracketed && host.contains(':')) {
        return Err(MixedProxyError::InvalidHttpTarget);
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| MixedProxyError::InvalidHttpTarget)?;
    if port == 0 {
        return Err(MixedProxyError::InvalidHttpTarget);
    }
    Ok((Address::parse(host), Port(port)))
}

pub fn write_socks5_success(
    stream: &mut TcpStream,
    bound: Option<SocketAddr>,
) -> Result<(), MixedProxyError> {
    write_socks5_reply(stream, SOCKS_REP_SUCCEEDED, bound)
}

pub fn write_socks5_connect_error(
    stream: &mut TcpStream,
    error: &std::io::Error,
) -> Result<(), MixedProxyError> {
    let rep = match error.kind() {
        std::io::ErrorKind::ConnectionRefused => SOCKS_REP_CONNECTION_REFUSED,
        _ => SOCKS_REP_GENERAL_FAILURE,
    };
    write_socks5_reply(stream, rep, None)
}

fn write_socks5_reply(
    stream: &mut TcpStream,
    rep: u8,
    bound: Option<SocketAddr>,
) -> Result<(), MixedProxyError> {
    let mut response = vec![SOCKS_VERSION, rep, 0x00];
    match bound {
        Some(SocketAddr::V4(addr)) => {
            response.push(0x01);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        Some(SocketAddr::V6(addr)) => {
            response.push(0x04);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        None => {
            response.push(0x01);
            response.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
            response.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    stream.write_all(&response)?;
    Ok(())
}

pub fn write_http_success(stream: &mut TcpStream) -> Result<(), MixedProxyError> {
    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    Ok(())
}

pub fn write_http_error(
    stream: &mut TcpStream,
    error: &MixedProxyError,
) -> Result<(), MixedProxyError> {
    let (status, reason, extra_headers) = match error {
        MixedProxyError::HttpAuthRequired | MixedProxyError::HttpAuthFailed => (
            407,
            "Proxy Authentication Required",
            "Proxy-Authenticate: Basic realm=\"wrongsv\"\r\n",
        ),
        MixedProxyError::UnsupportedHttpMethod(_) => (405, "Method Not Allowed", ""),
        MixedProxyError::HttpHeaderTooLarge => (431, "Request Header Fields Too Large", ""),
        _ => (400, "Bad Request", ""),
    };
    write_http_status(stream, status, reason, extra_headers)
}

pub fn write_http_bad_gateway(stream: &mut TcpStream) -> Result<(), MixedProxyError> {
    write_http_status(stream, 502, "Bad Gateway", "")
}

fn write_http_status(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    extra_headers: &str,
) -> Result<(), MixedProxyError> {
    let body = format!("{status} {reason}\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n{extra_headers}Connection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum MixedProxyError {
    #[error("invalid mixed proxy credentials")]
    InvalidCredentials,
    #[error("connection closed before request completed")]
    UnexpectedEof,
    #[error("unsupported SOCKS version: {0}")]
    UnsupportedSocksVersion(u8),
    #[error("SOCKS client did not offer an acceptable auth method")]
    NoAcceptableSocksAuth,
    #[error("SOCKS username/password authentication failed")]
    SocksAuthFailed,
    #[error("invalid SOCKS request")]
    InvalidSocksRequest,
    #[error("unsupported SOCKS command: {0}")]
    UnsupportedSocksCommand(u8),
    #[error("unsupported SOCKS address type: {0}")]
    UnsupportedSocksAddressType(u8),
    #[error("invalid SOCKS address")]
    InvalidSocksAddress,
    #[error("HTTP proxy header is too large")]
    HttpHeaderTooLarge,
    #[error("invalid HTTP proxy request")]
    InvalidHttpRequest,
    #[error("unsupported HTTP proxy method: {0}")]
    UnsupportedHttpMethod(String),
    #[error("HTTP proxy authentication required")]
    HttpAuthRequired,
    #[error("HTTP proxy authentication failed")]
    HttpAuthFailed,
    #[error("invalid HTTP CONNECT target")]
    InvalidHttpTarget,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_authority_supports_domain_ipv4_and_bracketed_ipv6() {
        assert_eq!(
            parse_authority("example.com:443").unwrap(),
            (Address::Domain("example.com".into()), Port(443))
        );
        assert_eq!(
            parse_authority("127.0.0.1:8080").unwrap(),
            (Address::IPv4([127, 0, 0, 1]), Port(8080))
        );
        assert!(matches!(
            parse_authority("[::1]:443").unwrap().0,
            Address::IPv6(_)
        ));
    }

    #[test]
    fn parse_authority_rejects_invalid_targets() {
        assert!(parse_authority("example.com").is_err());
        assert!(parse_authority("example.com:0").is_err());
        assert!(parse_authority("::1:443").is_err());
        assert!(parse_authority("[::1]443").is_err());
    }

    #[test]
    fn http_basic_auth_matches_credentials() {
        let credentials = Credentials::new("admin".into(), "secret".into()).unwrap();
        assert!(authenticate_http_basic(Some("Basic YWRtaW46c2VjcmV0"), &credentials).is_ok());
        assert!(authenticate_http_basic(Some("Basic YWRtaW46d3Jvbmc="), &credentials).is_err());
        assert!(authenticate_http_basic(None, &credentials).is_err());
    }

    #[test]
    fn header_end_finds_crlf_boundary() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(14));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\n\n"), None);
    }
}
