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

#[test]
fn metrics_count_bytes_per_user_through_reality_relay() {
    use base64::Engine;
    use x25519_dalek::{PublicKey, StaticSecret};

    let listen = reserve_addr();
    let metrics_addr = reserve_addr();
    let port = metrics_addr
        .split(':')
        .next_back()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap();
    let user_uuid = Uuid::new_v4();
    let email = "test@reality.test";

    // Generate REALITY X25519 keypair; configure server with the private key,
    // hand the client the base64-encoded public key.
    let sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let pk = PublicKey::from(&sk);
    let sk_hex = hex::encode(sk.as_bytes());
    let pk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk.as_bytes());
    let short_id = "01234567";

    let config_toml = format!(
        r#"
listen = "{listen}"

[[users]]
id = "{user_uuid}"
email = "{email}"
flow = ""

[reality]
private_key = "{sk_hex}"
short_ids = ["{short_id}"]
max_time_diff = 300

[metrics]
port = {port}
bind = "127.0.0.1"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let _handle = server.spawn();
    thread::sleep(Duration::from_millis(200));

    let echo_addr = spawn_echo_target();

    // raw_pubkey "00...0" disables client-side cert HMAC verification — we
    // only care that bytes flow through `relay_reality_raw` so MetricsTap
    // can record them.
    let proxy_host = listen.split(':').next().unwrap();
    let proxy_port: u16 = listen.split(':').next_back().unwrap().parse().unwrap();
    let mut conn = wrongsv_evaluator_client::transport::connect_for_protocol(
        "reality",
        proxy_host,
        proxy_port,
        echo_addr.port(),
        &user_uuid.to_string(),
        "",
        Some(&pk_b64),
        Some(short_id),
        Some(&"00".repeat(32)),
    )
    .expect("REALITY handshake should succeed");

    let payload = b"reality-metrics-roundtrip-payload";
    conn.write_all(payload).unwrap();
    conn.flush().unwrap();

    let mut got = vec![0u8; payload.len()];
    let mut filled = 0;
    while filled < payload.len() {
        match conn.read(&mut got[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => panic!("REALITY read error: {e}"),
        }
    }
    assert_eq!(&got[..filled], payload, "echo mismatch");

    drop(conn);
    thread::sleep(Duration::from_millis(200));

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

#[test]
fn metrics_count_bytes_per_user_through_vmess_relay() {
    use wrongsv_server::vmess::{
        self, VmessBodyReader, VmessBodyWriter, VmessCommand, VmessRequest,
    };

    let listen = reserve_addr();
    let metrics_addr = reserve_addr();
    let port = metrics_addr
        .split(':')
        .next_back()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap();
    let user_uuid = Uuid::new_v4();
    let email = "vmess-user@metrics.test";
    let config_toml = format!(
        r#"
listen = "{listen}"

[vmess]

[[vmess.users]]
id = "{user_uuid}"
email = "{email}"

[metrics]
port = {port}
bind = "127.0.0.1"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let _handle = server.spawn();
    thread::sleep(Duration::from_millis(200));

    let echo_addr = spawn_echo_target();

    let uuid_bytes: [u8; 16] = *user_uuid.as_bytes();
    let cmd_key = vmess::derive_cmd_key(&uuid_bytes);
    let (_plain, eaudid) = vmess::generate_eaudid(&cmd_key);

    let mut body_key = [0u8; 16];
    let mut body_iv = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut body_key);
    rand::rngs::OsRng.fill_bytes(&mut body_iv);

    let request = VmessRequest {
        command: VmessCommand::Tcp,
        address: "127.0.0.1".into(),
        port: echo_addr.port(),
    };
    let (header_len, header_payload) =
        vmess::build_header(&cmd_key, &eaudid, &body_key, &body_iv, &request).unwrap();

    let mut conn = TcpStream::connect(&listen).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(&eaudid).unwrap();
    conn.write_all(&header_len.to_be_bytes()).unwrap();
    conn.write_all(&header_payload).unwrap();

    let response_key = vmess::derive_response_key(&cmd_key);
    vmess::read_response(&response_key, &mut conn).unwrap();

    let payload = b"vmess-metrics-roundtrip-payload";
    let mut writer = VmessBodyWriter::new(&body_key, &body_iv);
    writer.write_chunk(&mut conn, payload).unwrap();

    let mut reader = VmessBodyReader::new(&body_key, &body_iv);
    let mut plaintext = Vec::with_capacity(payload.len());
    let got_chunk = reader.read_chunk(&mut conn, &mut plaintext).unwrap();
    assert!(got_chunk, "expected echoed VMess body chunk");
    assert_eq!(&plaintext[..], payload, "echo mismatch");

    // Cleanly close to flush counters before scrape.
    let _ = writer.write_eof(&mut conn);
    let _ = conn.shutdown(std::net::Shutdown::Write);
    thread::sleep(Duration::from_millis(200));

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
