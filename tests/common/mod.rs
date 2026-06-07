//! Shared helpers for lifecycle integration tests.
// These functions are shared across multiple test binaries — not every
// binary uses every helper, so suppress dead_code warnings for the module.
#![allow(dead_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Mutex, MutexGuard, Once};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

static INIT_LOGGING: Once = Once::new();
static LIFECYCLE_TEST_LOCK: Mutex<()> = Mutex::new(());

pub fn init_logging() {
    INIT_LOGGING.call_once(|| {
        let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    });
}

/// Serialize lifecycle tests that spawn real proxy clients.
///
/// Clients such as mihomo, sing-box, and xray maintain process-level listener
/// state and can interfere with each other when test cases in the same binary
/// run concurrently.
pub fn lifecycle_test_lock() -> MutexGuard<'static, ()> {
    LIFECYCLE_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub struct ServerGuard {
    #[allow(dead_code)]
    pub handle: wrongsv_server::ServerHandle,
}

/// Reserve a random local port.
pub fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Pick distinct local ports for tests that need multiple listeners.
pub fn pick_ports(count: usize) -> Vec<u16> {
    let mut ports = Vec::with_capacity(count);
    while ports.len() < count {
        let port = pick_port();
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    ports
}

/// Spawn a wrongsv server with REALITY config.
pub fn spawn_server(
    port: u16,
    user_id: &str,
    flow: &str,
    reality_private_key: &str,
    reality_short_ids: &[&str],
    reality_dest: Option<&str>,
) -> ServerGuard {
    let short_ids_toml = reality_short_ids
        .iter()
        .map(|s| format!(r#""{}""#, s))
        .collect::<Vec<_>>()
        .join(", ");
    let dest_toml = match reality_dest {
        Some(d) => format!(r#"dest = "{}""#, d),
        None => String::new(),
    };
    let config_toml = format!(
        r#"
listen = "127.0.0.1:{port}"

[[users]]
id = "{user_id}"
email = "test@mihomo.test"
flow = "{flow}"

[reality]
private_key = "{reality_private_key}"
short_ids = [{short_ids_toml}]
max_time_diff = 300
{dest_toml}
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let handle = server.spawn();
    thread::sleep(Duration::from_millis(200));
    ServerGuard { handle }
}

/// Spawn a multi-user server.
pub fn spawn_multi_user_server(
    port: u16,
    users: &[(String, String)],
    reality_private_key: &str,
    reality_short_ids: &[&str],
) -> ServerGuard {
    let short_ids_toml = reality_short_ids
        .iter()
        .map(|s| format!(r#""{}""#, s))
        .collect::<Vec<_>>()
        .join(", ");
    let users_toml = users
        .iter()
        .map(|(id, flow)| {
            format!(
                r#"[[users]]
id = "{id}"
email = "{id}@test"
flow = "{flow}""#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config_toml = format!(
        r#"
listen = "127.0.0.1:{port}"

{users_toml}

[reality]
private_key = "{reality_private_key}"
short_ids = [{short_ids_toml}]
max_time_diff = 300
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let handle = server.spawn();
    thread::sleep(Duration::from_millis(200));
    ServerGuard { handle }
}

/// Spawn a wrongsv Shadowsocks server.
pub fn spawn_shadowsocks_server(port: u16, method: &str, password: &str) -> ServerGuard {
    let config_toml = format!(
        r#"
listen = "127.0.0.1:{port}"

[shadowsocks]
method = "{method}"
password = "{password}"
udp = true
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let handle = server.spawn();
    thread::sleep(Duration::from_millis(200));
    ServerGuard { handle }
}

/// Spawn a wrongsv Trojan-over-TLS server.
#[allow(dead_code)]
pub fn spawn_trojan_server(port: u16, password: &str) -> ServerGuard {
    spawn_trojan_server_with_cert(port, password, None, None)
}

#[allow(dead_code)]
pub fn spawn_trojan_server_with_pinned_cert(port: u16, password: &str) -> (ServerGuard, String) {
    let (cert, key) = wrongsv_anytls::generate_self_signed_cert().unwrap();
    let cert_hash = certificate_sha256_hex(&cert);
    (
        spawn_trojan_server_with_cert(port, password, Some(&cert), Some(&key)),
        cert_hash,
    )
}

fn spawn_trojan_server_with_cert(
    port: u16,
    password: &str,
    certificate: Option<&str>,
    key: Option<&str>,
) -> ServerGuard {
    let cert_toml = match (certificate, key) {
        (Some(cert), Some(key)) => format!(
            r#"
certificate = '''
{cert}'''
key = '''
{key}'''
"#
        ),
        _ => String::new(),
    };
    let config_toml = format!(
        r#"
listen = "127.0.0.1:{port}"

[trojan]
password = "{password}"
{cert_toml}
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let handle = server.spawn();
    thread::sleep(Duration::from_millis(200));
    ServerGuard { handle }
}

/// Spawn a wrongsv WebSocket VLESS server (raw WS, no TLS).
#[allow(dead_code)]
pub fn spawn_ws_server(port: u16, user_id: &str, flow: &str, path: &str) -> ServerGuard {
    let config_toml = format!(
        r#"
listen = "127.0.0.1:{port}"

[[users]]
id = "{user_id}"
email = "test@ws.test"
flow = "{flow}"

[websocket]
path = "{path}"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let handle = server.spawn();
    thread::sleep(Duration::from_millis(200));
    ServerGuard { handle }
}

fn certificate_sha256_hex(cert_pem: &str) -> String {
    let cert = pem::parse(cert_pem).unwrap();
    Sha256::digest(cert.contents())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn spawn_tcp_echo_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut stream = stream;
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

pub fn spawn_udp_echo_target() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&buf[..n], peer);
        }
    });
    addr
}

pub fn spawn_http_echo_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut stream = stream;
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            request.extend_from_slice(&buf[..n]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n")
                                || request.len() > 65536
                            {
                                break;
                            }
                        }
                    }
                }

                let request = String::from_utf8_lossy(&request);
                let mut parts = request
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .split_whitespace();
                let method = parts.next().unwrap_or_default();
                let target = parts.next().unwrap_or_default();
                let body =
                    format!(r#"{{"origin":"local","method":"{method}","target":"{target}"}}"#);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    addr
}

pub fn local_http_url(addr: SocketAddr, path: &str) -> String {
    format!("http://{addr}{path}")
}

pub fn socks5_tcp_echo(
    socks_port: u16,
    target_addr: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut sock = socks5_connect(socks_port)?;
    send_socks5_connect(&mut sock, target_addr)?;
    sock.write_all(payload)
        .map_err(|e| format!("SOCKS5 TCP payload write: {e}"))?;
    let mut response = vec![0u8; payload.len()];
    sock.read_exact(&mut response)
        .map_err(|e| format!("SOCKS5 TCP payload read: {e}"))?;
    Ok(response)
}

pub fn socks5_udp_echo(
    socks_port: u16,
    target_addr: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut control = socks5_connect(socks_port)?;
    let relay_addr = send_socks5_udp_associate(&mut control)?;
    let udp = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("UDP bind: {e}"))?;
    udp.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("set UDP timeout: {e}"))?;

    let packet = encode_socks5_udp_packet(target_addr, payload)?;
    udp.send_to(&packet, relay_addr)
        .map_err(|e| format!("SOCKS5 UDP send: {e}"))?;
    let mut response_packet = [0u8; 65535];
    let (n, _) = udp
        .recv_from(&mut response_packet)
        .map_err(|e| format!("SOCKS5 UDP recv: {e}"))?;
    decode_socks5_udp_payload(&response_packet[..n])
}

/// Make an HTTP request through a SOCKS5 proxy, return response body.
pub fn socks5_get(socks_port: u16, url: &str) -> Result<String, String> {
    let (authority, path, default_port) = if let Some(rest) = url.strip_prefix("http://") {
        if let Some(idx) = rest.find('/') {
            (&rest[..idx], &rest[idx..], 80u16)
        } else {
            (rest, "/", 80u16)
        }
    } else if let Some(rest) = url.strip_prefix("https://") {
        if let Some(idx) = rest.find('/') {
            (&rest[..idx], &rest[idx..], 443u16)
        } else {
            (rest, "/", 443u16)
        }
    } else {
        return Err("unsupported URL scheme".into());
    };
    let (host, port) = parse_http_authority(authority, default_port)?;

    let mut sock = TcpStream::connect(format!("127.0.0.1:{socks_port}"))
        .map_err(|e| format!("SOCKS connect: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("set timeout: {e}"))?;

    // SOCKS5 handshake
    sock.write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("SOCKS5 hello: {e}"))?;
    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp)
        .map_err(|e| format!("SOCKS5 hello resp: {e}"))?;
    if resp != [0x05, 0x00] {
        return Err(format!("SOCKS5 auth method rejected: {:02x?}", resp));
    }

    // SOCKS5 CONNECT request
    let mut req = vec![0x05, 0x01, 0x00];
    append_socks5_host_port(&mut req, host, port)?;
    sock.write_all(&req)
        .map_err(|e| format!("SOCKS5 connect: {e}"))?;

    read_socks5_tcp_reply(&mut sock).map_err(|e| format!("SOCKS5 connect resp: {e}"))?;

    // HTTP request
    let http_req = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    sock.write_all(http_req.as_bytes())
        .map_err(|e| format!("HTTP write: {e}"))?;

    // Read headers until \r\n\r\n
    let mut head_buf = Vec::new();
    let header_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let byte = read_http_byte(&mut sock, header_deadline, "HTTP read")?;
        head_buf.push(byte[0]);
        if head_buf.len() >= 4 && head_buf[head_buf.len() - 4..] == [b'\r', b'\n', b'\r', b'\n'] {
            break;
        }
        if head_buf.len() > 65536 {
            return Err("HTTP headers too large".into());
        }
    }

    let headers_str = String::from_utf8_lossy(&head_buf);
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in headers_str.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().ok();
            } else if name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
            {
                chunked = true;
            }
        }
    }

    sock.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("set timeout: {e}"))?;

    let body = if let Some(cl) = content_length {
        let mut body_bytes = vec![0u8; cl];
        read_exact_with_deadline(
            &mut sock,
            &mut body_bytes,
            Instant::now() + Duration::from_secs(30),
            &format!("HTTP body read ({cl} bytes)"),
        )?;
        String::from_utf8_lossy(&body_bytes).to_string()
    } else if chunked {
        let body_bytes = read_chunked_http_body(&mut sock)?;
        String::from_utf8_lossy(&body_bytes).to_string()
    } else {
        let body_bytes = read_http_body_until_close(&mut sock)?;
        String::from_utf8_lossy(&body_bytes).to_string()
    };

    Ok(body)
}

fn parse_http_authority(authority: &str, default_port: u16) -> Result<(&str, u16), String> {
    if authority.is_empty() {
        return Err("empty HTTP authority".into());
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| "invalid bracketed HTTP authority".to_string())?;
        let host = &rest[..end];
        let suffix = &rest[end + 1..];
        let port = if let Some(port) = suffix.strip_prefix(':') {
            parse_port(port)?
        } else if suffix.is_empty() {
            default_port
        } else {
            return Err("invalid bracketed HTTP authority suffix".into());
        };
        return Ok((host, port));
    }

    if let Some((host, port)) = authority.rsplit_once(':')
        && !port.is_empty()
        && port.as_bytes().iter().all(u8::is_ascii_digit)
    {
        if host.is_empty() {
            return Err("empty HTTP host".into());
        }
        return Ok((host, parse_port(port)?));
    }

    Ok((authority, default_port))
}

fn parse_port(port: &str) -> Result<u16, String> {
    port.parse::<u16>()
        .map_err(|e| format!("invalid HTTP port: {e}"))
}

fn read_http_byte(
    sock: &mut TcpStream,
    deadline: Instant,
    context: &str,
) -> Result<[u8; 1], String> {
    let mut byte = [0u8; 1];
    read_exact_with_deadline(sock, &mut byte, deadline, context)?;
    Ok(byte)
}

fn read_exact_with_deadline(
    sock: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
    context: &str,
) -> Result<(), String> {
    let mut offset = 0;
    while offset < buf.len() {
        match sock.read(&mut buf[offset..]) {
            Ok(0) => return Err(format!("{context}: unexpected EOF")),
            Ok(n) => offset += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if is_retryable_read(&e) && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) if is_retryable_read(&e) => return Err(format!("{context}: timed out")),
            Err(e) => return Err(format!("{context}: {e}")),
        }
    }
    Ok(())
}

fn read_chunked_http_body(sock: &mut TcpStream) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut body = Vec::new();
    loop {
        let line = read_http_line(sock, deadline, "HTTP chunk size read")?;
        let line = String::from_utf8_lossy(&line);
        let size_token = line.trim().split(';').next().unwrap_or_default();
        let size = usize::from_str_radix(size_token, 16)
            .map_err(|e| format!("HTTP chunk size parse: {e}"))?;
        if size == 0 {
            loop {
                let trailer = read_http_line(sock, deadline, "HTTP chunk trailer read")?;
                if trailer == b"\r\n" {
                    return Ok(body);
                }
            }
        }

        let mut chunk = vec![0u8; size];
        read_exact_with_deadline(sock, &mut chunk, deadline, "HTTP chunk read")?;
        body.extend_from_slice(&chunk);

        let mut crlf = [0u8; 2];
        read_exact_with_deadline(sock, &mut crlf, deadline, "HTTP chunk CRLF read")?;
        if crlf != *b"\r\n" {
            return Err("HTTP chunk missing CRLF".into());
        }
    }
}

fn read_http_line(
    sock: &mut TcpStream,
    deadline: Instant,
    context: &str,
) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    loop {
        let byte = read_http_byte(sock, deadline, context)?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
        if line.len() > 8192 {
            return Err(format!("{context}: line too large"));
        }
    }
}

fn read_http_body_until_close(sock: &mut TcpStream) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut body = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match sock.read(&mut buf) {
            Ok(0) => return Ok(body),
            Ok(n) => body.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if is_retryable_read(&e) && !body.is_empty() => return Ok(body),
            Err(e) if is_retryable_read(&e) && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) if is_retryable_read(&e) => return Err("HTTP read: timed out".into()),
            Err(e) => return Err(format!("HTTP read: {e}")),
        }
    }
}

fn is_retryable_read(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn socks5_connect(socks_port: u16) -> Result<TcpStream, String> {
    let mut sock = TcpStream::connect(format!("127.0.0.1:{socks_port}"))
        .map_err(|e| format!("SOCKS connect: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("set timeout: {e}"))?;
    sock.write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("SOCKS5 hello: {e}"))?;
    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp)
        .map_err(|e| format!("SOCKS5 hello resp: {e}"))?;
    if resp != [0x05, 0x00] {
        return Err(format!("SOCKS5 auth method rejected: {:02x?}", resp));
    }
    Ok(sock)
}

fn send_socks5_connect(sock: &mut TcpStream, target_addr: SocketAddr) -> Result<(), String> {
    let mut req = vec![0x05, 0x01, 0x00];
    append_socks5_addr(&mut req, target_addr)?;
    sock.write_all(&req)
        .map_err(|e| format!("SOCKS5 connect: {e}"))?;
    read_socks5_tcp_reply(sock).map(|_| ())
}

fn send_socks5_udp_associate(sock: &mut TcpStream) -> Result<SocketAddr, String> {
    let mut req = vec![0x05, 0x03, 0x00];
    append_socks5_addr(
        &mut req,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    )?;
    sock.write_all(&req)
        .map_err(|e| format!("SOCKS5 UDP associate: {e}"))?;
    let relay = read_socks5_tcp_reply(sock)?;
    let relay_ip = match relay.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    Ok(SocketAddr::new(relay_ip, relay.port()))
}

fn read_socks5_tcp_reply(sock: &mut TcpStream) -> Result<SocketAddr, String> {
    let mut head = [0u8; 4];
    sock.read_exact(&mut head)
        .map_err(|e| format!("SOCKS5 reply head: {e}"))?;
    if head[0] != 0x05 {
        return Err(format!("invalid SOCKS5 version in reply: {:#04x}", head[0]));
    }
    if head[1] != 0x00 {
        return Err(format!("SOCKS5 request rejected: REP={:#04x}", head[1]));
    }
    read_socks5_addr(sock, head[3])
}

fn read_socks5_addr(sock: &mut TcpStream, atyp: u8) -> Result<SocketAddr, String> {
    match atyp {
        0x01 => {
            let mut raw = [0u8; 6];
            sock.read_exact(&mut raw)
                .map_err(|e| format!("SOCKS5 IPv4 addr: {e}"))?;
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
                u16::from_be_bytes([raw[4], raw[5]]),
            ))
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len)
                .map_err(|e| format!("SOCKS5 domain len: {e}"))?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name)
                .map_err(|e| format!("SOCKS5 domain: {e}"))?;
            let mut port = [0u8; 2];
            sock.read_exact(&mut port)
                .map_err(|e| format!("SOCKS5 domain port: {e}"))?;
            let host = String::from_utf8(name).map_err(|e| format!("SOCKS5 domain utf8: {e}"))?;
            if host == "localhost" {
                Ok(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    u16::from_be_bytes(port),
                ))
            } else {
                Err(format!("unsupported SOCKS5 domain reply: {host}"))
            }
        }
        0x04 => {
            let mut raw = [0u8; 18];
            sock.read_exact(&mut raw)
                .map_err(|e| format!("SOCKS5 IPv6 addr: {e}"))?;
            let port = u16::from_be_bytes([raw[16], raw[17]]);
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&raw[..16]).unwrap());
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => Err(format!("unsupported SOCKS5 address type: {atyp:#04x}")),
    }
}

fn append_socks5_addr(out: &mut Vec<u8>, addr: SocketAddr) -> Result<(), String> {
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    Ok(())
}

fn append_socks5_host_port(out: &mut Vec<u8>, host: &str, port: u16) -> Result<(), String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return append_socks5_addr(out, SocketAddr::new(ip, port));
    }
    if host.len() > u8::MAX as usize {
        return Err("SOCKS5 domain name too long".into());
    }
    out.push(0x03);
    out.push(host.len() as u8);
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

fn encode_socks5_udp_packet(target_addr: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut packet = vec![0x00, 0x00, 0x00];
    append_socks5_addr(&mut packet, target_addr)?;
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn decode_socks5_udp_payload(packet: &[u8]) -> Result<Vec<u8>, String> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return Err("invalid SOCKS5 UDP response header".into());
    }
    let mut pos = 3;
    match packet[pos] {
        0x01 => pos += 1 + 4 + 2,
        0x03 => {
            pos += 1;
            let len = *packet
                .get(pos)
                .ok_or_else(|| "short SOCKS5 UDP domain length".to_string())?
                as usize;
            pos += 1 + len + 2;
        }
        0x04 => pos += 1 + 16 + 2,
        atyp => return Err(format!("unsupported SOCKS5 UDP address type: {atyp:#04x}")),
    }
    if packet.len() < pos {
        return Err("short SOCKS5 UDP response".into());
    }
    Ok(packet[pos..].to_vec())
}

// ── test data ─────────────────────────────────────────────────────────────────

pub const TEST_PRIVATE_KEY: &str =
    "60ec256ba191e9610dffc6cd4f9060089b023795cd81b63089bcbb593b955078";
pub const TEST_PUBLIC_KEY: &str = "dWquFtuK9M_7drHITl9Xb-NFxXY7gNvdAyVLyQW6J04";
pub const TEST_SHORT_ID: &str = "ababa486";
pub const TEST_UUID: &str = "41309a00-3cbe-43a2-80e7-76c8a4fe65be";
pub const TEST_SNI: &str = "download-porter.hoyoverse.com";
pub const TEST_SS_AEAD_PASSWORD: &str = "secret";
pub const TEST_SS_2022_AES_128_PASSWORD: &str = "MDEyMzQ1Njc4OWFiY2RlZg==";
pub const TEST_SS_2022_AES_256_PASSWORD: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
pub const TEST_TROJAN_PASSWORD: &str = "secret";
