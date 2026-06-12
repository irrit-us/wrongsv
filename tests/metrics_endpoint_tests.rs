//! Integration tests for the metrics HTTP endpoint exposed by `InboundServer`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use wrongsv_net_types::Address;
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
use wrongsv_uuid::Uuid;
use wrongsv_vless::{MemoryValidator, Validator};
use wrongsv_vless_encoding::{self as encoding, Addons};

fn reserve_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn http_get(addr: &str, path: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn metrics_disabled_by_default() {
    let listen = reserve_addr();
    let metrics_addr = reserve_addr();
    let config_toml = format!(
        r#"
listen = "{listen}"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "no-metrics-test"
udp = false
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let _handle = server.spawn();
    thread::sleep(Duration::from_millis(100));

    let result = TcpStream::connect_timeout(
        &metrics_addr.parse().unwrap(),
        Duration::from_millis(200),
    );
    assert!(
        result.is_err(),
        "expected no metrics listener; got connection on {metrics_addr}"
    );
}

#[test]
fn metrics_endpoint_serves_prometheus_dump() {
    let listen = reserve_addr();
    let metrics_addr = reserve_addr();
    let port = metrics_addr
        .split(':')
        .next_back()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap();
    let config_toml = format!(
        r#"
listen = "{listen}"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "metrics-test"
udp = false

[metrics]
port = {port}
bind = "127.0.0.1"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let _handle = server.spawn();
    thread::sleep(Duration::from_millis(200));

    let response = http_get(&metrics_addr, "/metrics");
    assert!(response.contains("200 OK"), "got: {response}");
    assert!(
        response.contains("wrongsv_uptime_seconds"),
        "missing uptime metric: {response}"
    );

    let healthz = http_get(&metrics_addr, "/healthz");
    assert!(healthz.contains("200 OK"), "got: {healthz}");
}

fn spawn_echo_target() -> std::net::SocketAddr {
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = echo.local_addr().unwrap();
    thread::spawn(move || {
        for stream in echo.incoming().flatten() {
            thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 8192];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
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

fn vless_connect(server_addr: &str, user_uuid: Uuid, email: &str, target_port: u16) -> TcpStream {
    let validator = Arc::new(MemoryValidator::new());
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(user_uuid),
            flow: String::new(),
            encryption: String::new(),
            udp: true,
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: email.into(),
        level: 0,
    };
    validator.add(user.clone()).unwrap();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(target_port),
        user,
    };
    let addons = Addons {
        flow: String::new(),
        ..Default::default()
    };

    let mut buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut buf, &request, &addons).unwrap();

    let mut stream = TcpStream::connect(server_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&buf).unwrap();

    // Read the server's response header so the caller can read raw bytes.
    let mut cursor_buf = [0u8; 256];
    let n = stream.read(&mut cursor_buf).unwrap();
    let mut cursor = std::io::Cursor::new(&cursor_buf[..n]);
    encoding::decode_response_header(&mut cursor, &request).unwrap();

    stream
}

#[test]
fn metrics_count_bytes_per_user_through_vless_relay() {
    let listen = reserve_addr();
    let metrics_addr = reserve_addr();
    let port = metrics_addr
        .split(':')
        .next_back()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap();
    let user_uuid = Uuid::new_v4();
    let email = "alice@metrics.test";
    let config_toml = format!(
        r#"
listen = "{listen}"

[[users]]
id = "{user_uuid}"
email = "{email}"
flow = ""

[metrics]
port = {port}
bind = "127.0.0.1"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let _handle = server.spawn();
    thread::sleep(Duration::from_millis(150));

    let echo_addr = spawn_echo_target();
    let mut conn = vless_connect(&listen, user_uuid, email, echo_addr.port());

    let payload = b"metrics-roundtrip-test-payload";
    conn.write_all(payload).unwrap();

    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], payload, "echo mismatch");

    // Give the relay threads a beat to flush counters.
    thread::sleep(Duration::from_millis(150));

    let response = http_get(&metrics_addr, "/metrics");
    assert!(response.contains("200 OK"), "got: {response}");
    let want_in = format!("wrongsv_user_bytes_in{{email=\"{email}\"}} {}", payload.len());
    let want_out = format!(
        "wrongsv_user_bytes_out{{email=\"{email}\"}} {}",
        payload.len()
    );
    assert!(
        response.contains(&want_in),
        "missing {want_in}\n--- response ---\n{response}"
    );
    assert!(
        response.contains(&want_out),
        "missing {want_out}\n--- response ---\n{response}"
    );
}
