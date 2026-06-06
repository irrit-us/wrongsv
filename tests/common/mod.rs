//! Shared helpers for lifecycle integration tests.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, MutexGuard, Once};
use std::thread;
use std::time::Duration;

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

/// Make an HTTP request through a SOCKS5 proxy, return response body.
pub fn socks5_get(socks_port: u16, url: &str) -> Result<String, String> {
    let (host, path) = if let Some(rest) = url.strip_prefix("http://") {
        if let Some(idx) = rest.find('/') {
            (&rest[..idx], &rest[idx..])
        } else {
            (rest, "/")
        }
    } else if let Some(rest) = url.strip_prefix("https://") {
        if let Some(idx) = rest.find('/') {
            (&rest[..idx], &rest[idx..])
        } else {
            (rest, "/")
        }
    } else {
        return Err("unsupported URL scheme".into());
    };

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
    let host_bytes = host.as_bytes();
    let port = if url.starts_with("https://") {
        443u16
    } else {
        80u16
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    sock.write_all(&req)
        .map_err(|e| format!("SOCKS5 connect: {e}"))?;

    let mut resp = vec![0u8; 256];
    let n = sock
        .read(&mut resp)
        .map_err(|e| format!("SOCKS5 connect resp: {e}"))?;
    if n < 10 {
        return Err(format!("SOCKS5 connect response too short: {n}"));
    }
    if resp[0..2] != [0x05, 0x00] {
        return Err(format!("SOCKS5 connect rejected: REP={:#04x}", resp[1]));
    }

    // HTTP request
    let http_req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    sock.write_all(http_req.as_bytes())
        .map_err(|e| format!("HTTP write: {e}"))?;

    // Read headers until \r\n\r\n
    let mut head_buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        sock.read_exact(&mut byte)
            .map_err(|e| format!("HTTP read: {e}"))?;
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
    for line in headers_str.lines() {
        if line.len() > 15 && line[..15].eq_ignore_ascii_case("content-length:") {
            content_length = line[15..].trim().parse().ok();
            break;
        }
    }

    sock.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("set timeout: {e}"))?;

    let body = if let Some(cl) = content_length {
        let mut body_bytes = vec![0u8; cl];
        sock.read_exact(&mut body_bytes)
            .map_err(|e| format!("HTTP body read ({cl} bytes): {e}"))?;
        String::from_utf8_lossy(&body_bytes).to_string()
    } else {
        let mut s = String::new();
        sock.read_to_string(&mut s)
            .map_err(|e| format!("HTTP read: {e}"))?;
        s
    };

    Ok(body)
}

// ── test data ─────────────────────────────────────────────────────────────────

pub const TEST_PRIVATE_KEY: &str =
    "60ec256ba191e9610dffc6cd4f9060089b023795cd81b63089bcbb593b955078";
pub const TEST_PUBLIC_KEY: &str = "dWquFtuK9M_7drHITl9Xb-NFxXY7gNvdAyVLyQW6J04";
pub const TEST_SHORT_ID: &str = "ababa486";
pub const TEST_UUID: &str = "41309a00-3cbe-43a2-80e7-76c8a4fe65be";
pub const TEST_SNI: &str = "download-porter.hoyoverse.com";
