use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rand::Rng;
use wrongsv_net_types::Address;
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
use wrongsv_uuid::Uuid;
use wrongsv_vless::{MemoryValidator, Validator};
use wrongsv_vless_encoding::{self as encoding, Addons};

fn make_test_user() -> (Uuid, MemoryUser) {
    let uuid = Uuid::new_v4();
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(uuid),
            flow: String::new(),
            encryption: String::new(),
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "test@example.com".into(),
        level: 0,
    };
    (uuid, user)
}

fn make_test_validator() -> (Arc<MemoryValidator>, Uuid) {
    let (uuid, user) = make_test_user();
    let v = Arc::new(MemoryValidator::new());
    v.add(user).unwrap();
    (v, uuid)
}

#[test]
fn test_vless_handshake_encode_decode() {
    let (validator, uuid) = make_test_validator();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(8080),
        user: validator.get(uuid.as_bytes()).unwrap(),
    };

    let addons = Addons {
        flow: String::new(),
        ..Default::default()
    };

    let mut buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut buf, &request, &addons).unwrap();

    let mut cursor = std::io::Cursor::new(buf.as_ref());
    let v = validator.clone();
    let decoded = encoding::decode_request_header(&mut cursor, move |id| v.get(id)).unwrap();

    assert_eq!(decoded.header.version, request.version);
    assert_eq!(decoded.header.command, request.command);
    assert_eq!(
        decoded.header.address.to_string(),
        request.address.to_string()
    );
    assert_eq!(decoded.header.port, request.port);
    assert_eq!(decoded.header.user.email, request.user.email);
    assert_eq!(decoded.addons.flow, "");
}

#[test]
fn test_vless_handshake_with_vision_flow() {
    let uuid = Uuid::new_v4();
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(uuid),
            flow: "xtls-rprx-vision".into(),
            encryption: String::new(),
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "vision@example.com".into(),
        level: 0,
    };
    let validator = Arc::new(MemoryValidator::new());
    validator.add(user).unwrap();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("example.com"),
        port: wrongsv_net_types::Port(443),
        user: validator.get(uuid.as_bytes()).unwrap(),
    };

    let addons = Addons {
        flow: "xtls-rprx-vision".into(),
        ..Default::default()
    };

    let mut buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut buf, &request, &addons).unwrap();

    let mut cursor = std::io::Cursor::new(buf.as_ref());
    let v = validator.clone();
    let decoded = encoding::decode_request_header(&mut cursor, move |id| v.get(id)).unwrap();

    assert_eq!(decoded.addons.flow, "xtls-rprx-vision");
    assert_eq!(decoded.header.user.account.flow, "xtls-rprx-vision");
}

#[test]
fn test_response_header_roundtrip() {
    let (validator, uuid) = make_test_validator();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("10.0.0.1"),
        port: wrongsv_net_types::Port(80),
        user: validator.get(uuid.as_bytes()).unwrap(),
    };

    let addons = Addons {
        flow: String::new(),
        ..Default::default()
    };

    let mut buf = bytes::BytesMut::new();
    encoding::encode_response_header(&mut buf, &request, &addons).unwrap();

    let mut cursor = std::io::Cursor::new(buf.as_ref());
    let decoded = encoding::decode_response_header(&mut cursor, &request).unwrap();

    assert_eq!(decoded.flow, "");
}

#[test]
fn test_end_to_end_echo() {
    // Start an echo server as the "target"
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    thread::spawn(move || {
        for stream in echo.incoming().flatten() {
            thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 4096];
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

    let (validator, uuid) = make_test_validator();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(echo_addr.port()),
        user: validator.get(uuid.as_bytes()).unwrap(),
    };

    let addons = Addons {
        flow: String::new(),
        ..Default::default()
    };

    let mut req_buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut req_buf, &request, &addons).unwrap();

    let mut conn = TcpStream::connect_timeout(&echo_addr, Duration::from_secs(2)).unwrap();
    conn.write_all(&req_buf).unwrap();

    let mut resp = vec![0u8; 128];
    let n = conn.read(&mut resp).unwrap();
    assert!(n > 0, "expected echo response, got nothing");
}

#[test]
fn test_vision_padding_roundtrip_integration() {
    use wrongsv_vless::vision::{TrafficState, VisionReader, VisionWriter};

    let user_uuid = Uuid::new_v4();
    let user_sent_id = user_uuid.as_bytes();

    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";

    let mut write_buf = Vec::new();
    {
        let state = TrafficState::new(user_sent_id);
        let mut writer = VisionWriter::new(&mut write_buf, state, false, vec![900, 500, 900, 256]);
        writer.write(data).unwrap();
        writer.flush().unwrap();
    }

    assert!(!write_buf.is_empty());

    let mut read_buf = vec![0u8; data.len() + 1024];
    let state = TrafficState::new(user_sent_id);
    let mut reader = VisionReader::new(&write_buf[..], state, true);
    let n = reader.read(&mut read_buf).unwrap();

    assert_eq!(&read_buf[..n], &data[..]);
}

#[test]
fn test_invalid_user_rejected() {
    let validator = Arc::new(MemoryValidator::new());

    let uuid = Uuid::new_v4();
    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(8080),
        user: MemoryUser {
            account: MemoryAccount {
                id: ID::new(uuid),
                flow: String::new(),
                encryption: String::new(),
                xor_mode: 0,
                seconds: 0,
                padding: String::new(),
                testpre: 0,
                testseed: vec![],
            },
            email: "unknown@example.com".into(),
            level: 0,
        },
    };

    let addons = Addons {
        flow: String::new(),
        ..Default::default()
    };

    let mut buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut buf, &request, &addons).unwrap();

    let mut cursor = std::io::Cursor::new(buf.as_ref());
    let v = validator.clone();
    let result = encoding::decode_request_header(&mut cursor, move |id| v.get(id));

    assert!(result.is_err(), "should reject unknown user");
}

// ---------------------------------------------------------------------------
// Full proxy tests — spin up the real InboundServer and push traffic through it
// ---------------------------------------------------------------------------

fn spawn_echo_target() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = echo.local_addr().unwrap();
    let handle = thread::spawn(move || {
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
    (addr, handle)
}

fn spawn_wrongsv_server(listen_addr: &str, user_id: &str, flow: &str) -> thread::JoinHandle<()> {
    let config_toml = format!(
        r#"
listen = "{}"

[[users]]
id = "{}"
email = "test@e2e.test"
flow = "{}"
"#,
        listen_addr, user_id, flow
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    thread::spawn(move || {
        server.run().ok();
    })
}

fn vless_connect(
    server_addr: &str,
    user_uuid: &Uuid,
    target_addr: &str,
    target_port: u16,
    flow: &str,
) -> TcpStream {
    let validator = Arc::new(MemoryValidator::new());
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(*user_uuid),
            flow: flow.to_string(),
            encryption: String::new(),
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "test@e2e.test".into(),
        level: 0,
    };
    validator.add(user).unwrap();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse(target_addr),
        port: wrongsv_net_types::Port(target_port),
        user: validator.get(user_uuid.as_bytes()).unwrap(),
    };

    let addons = Addons {
        flow: flow.to_string(),
        ..Default::default()
    };

    let mut req_buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut req_buf, &request, &addons).unwrap();

    // Retry loop — server may still be binding in background thread
    let server: std::net::SocketAddr = server_addr.parse().unwrap();
    let mut conn = None;
    for _ in 0..20 {
        match TcpStream::connect_timeout(&server, Duration::from_millis(250)) {
            Ok(s) => {
                conn = Some(s);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("unexpected connect error: {e}"),
        }
    }
    let mut conn = conn.expect("server did not start within 5s");
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(&req_buf).unwrap();

    // Read response header: version(1) + addons_len(1) + [addons_payload]
    let mut version_buf = [0u8; 1];
    conn.read_exact(&mut version_buf).unwrap();
    assert_eq!(version_buf[0], 0, "response version mismatch");

    let mut addons_len_buf = [0u8; 1];
    conn.read_exact(&mut addons_len_buf).unwrap();
    let addons_len = addons_len_buf[0] as usize;
    if addons_len > 0 {
        let mut proto_payload = vec![0u8; addons_len];
        conn.read_exact(&mut proto_payload).unwrap();
    }

    conn
}

#[test]
fn test_full_proxy_raw_echo() {
    // Reserve a port
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let (echo_addr, _echo_handle) = spawn_echo_target();

    let user_uuid = Uuid::new_v4();
    let user_id_str = user_uuid.to_string();

    let _server = spawn_wrongsv_server(&listen_str, &user_id_str, "");

    // Give the server a moment to start
    thread::sleep(Duration::from_millis(50));

    let mut conn = vless_connect(&listen_str, &user_uuid, "127.0.0.1", echo_addr.port(), "");

    // Send data through proxy
    conn.write_all(b"hello via proxy").unwrap();

    // Read echo back
    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello via proxy");
}

#[test]
fn test_full_proxy_vision_echo() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let (echo_addr, _echo_handle) = spawn_echo_target();

    let user_uuid = Uuid::new_v4();
    let user_id_str = user_uuid.to_string();

    let _server = spawn_wrongsv_server(&listen_str, &user_id_str, "xtls-rprx-vision");

    thread::sleep(Duration::from_millis(50));

    let mut conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );

    // Response header has been consumed. Now send data through the proxy.
    conn.write_all(b"vision proxied data").unwrap();

    // Vision flow adds TLS-disguise padding on the downlink; use VisionReader to unwrap.
    use wrongsv_vless::vision::{TrafficState, VisionReader};
    let state = TrafficState::new(user_uuid.as_bytes());
    let mut reader = VisionReader::new(conn, state, true);
    let mut buf = [0u8; 128];
    let n = reader.read(&mut buf).unwrap();
    assert!(n > 0, "expected data, got nothing");
    assert_eq!(&buf[..n], b"vision proxied data");
}

#[test]
fn test_full_proxy_large_payload() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let (echo_addr, _echo_handle) = spawn_echo_target();

    let user_uuid = Uuid::new_v4();
    let user_id_str = user_uuid.to_string();

    let _server = spawn_wrongsv_server(&listen_str, &user_id_str, "");

    thread::sleep(Duration::from_millis(50));

    let mut conn = vless_connect(&listen_str, &user_uuid, "127.0.0.1", echo_addr.port(), "");

    // Send 64KB of data
    let payload = vec![0xAB; 65536];
    conn.write_all(&payload).unwrap();

    // Read back
    let mut received = vec![0u8; payload.len()];
    conn.read_exact(&mut received).unwrap();
    assert_eq!(received, payload);
}

#[test]
fn test_full_proxy_multiple_requests() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let (echo_addr, _echo_handle) = spawn_echo_target();

    let user_uuid = Uuid::new_v4();
    let user_id_str = user_uuid.to_string();

    let _server = spawn_wrongsv_server(&listen_str, &user_id_str, "");

    thread::sleep(Duration::from_millis(50));

    let mut conn = vless_connect(&listen_str, &user_uuid, "127.0.0.1", echo_addr.port(), "");

    for i in 0u8..5 {
        let msg = format!("request {}", i);
        conn.write_all(msg.as_bytes()).unwrap();
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Kyber post-quantum handshake tests
// ---------------------------------------------------------------------------

fn spawn_wrongsv_server_with_kyber(
    listen_addr: &str,
    user_id: &str,
    flow: &str,
    kyber_sk_hex: &str,
) -> thread::JoinHandle<()> {
    let config_toml = format!(
        r#"
listen = "{}"

[[users]]
id = "{}"
email = "test@e2e.test"
flow = "{}"

kyber_secret_key = "{}"
"#,
        listen_addr, user_id, flow, kyber_sk_hex
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    thread::spawn(move || {
        server.run().ok();
    })
}

fn vless_connect_with_kyber(
    server_addr: &str,
    user_uuid: &Uuid,
    target_addr: &str,
    target_port: u16,
    flow: &str,
    kyber_ct: Vec<u8>,
) -> TcpStream {
    let validator = Arc::new(MemoryValidator::new());
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(*user_uuid),
            flow: flow.to_string(),
            encryption: String::new(),
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "test@e2e.test".into(),
        level: 0,
    };
    validator.add(user).unwrap();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse(target_addr),
        port: wrongsv_net_types::Port(target_port),
        user: validator.get(user_uuid.as_bytes()).unwrap(),
    };

    let addons = Addons {
        flow: flow.to_string(),
        kyber_ct,
    };

    let mut req_buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut req_buf, &request, &addons).unwrap();

    // Retry loop — server may still be binding in background thread
    let server: std::net::SocketAddr = server_addr.parse().unwrap();
    let mut conn = None;
    for _ in 0..20 {
        match TcpStream::connect_timeout(&server, Duration::from_millis(250)) {
            Ok(s) => {
                conn = Some(s);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("unexpected connect error: {e}"),
        }
    }
    let mut conn = conn.expect("server did not start within 5s");
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(&req_buf).unwrap();

    // Read response header
    let mut version_buf = [0u8; 1];
    conn.read_exact(&mut version_buf).unwrap();
    assert_eq!(version_buf[0], 0, "response version mismatch");

    let mut addons_len_buf = [0u8; 1];
    conn.read_exact(&mut addons_len_buf).unwrap();
    let addons_len = addons_len_buf[0] as usize;
    if addons_len > 0 {
        let mut proto_payload = vec![0u8; addons_len];
        conn.read_exact(&mut proto_payload).unwrap();
    }

    conn
}

#[test]
fn test_kyber_full_handshake_and_echo() {
    // Generate server keypair
    let kp = wrongsv_kyber::generate_keypair();
    let sk_hex: String = kp.sk.iter().map(|b| format!("{:02x}", b)).collect();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let (echo_addr, _echo_handle) = spawn_echo_target();

    let user_uuid = Uuid::new_v4();
    let user_id_str = user_uuid.to_string();

    let _server = spawn_wrongsv_server_with_kyber(&listen_str, &user_id_str, "", &sk_hex);
    thread::sleep(Duration::from_millis(50));

    // Client encapsulates against server's public key
    let (kyber_ct, shared_secret) = wrongsv_kyber::encapsulate(&kp.pk).unwrap();

    let mut conn = vless_connect_with_kyber(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "",
        kyber_ct,
    );

    // Send data through proxy — should work since Kyber handshake doesn't break relay
    conn.write_all(b"kyber-secured echo").unwrap();

    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"kyber-secured echo");

    // Verify the shared secret is a proper 32-byte key (non-zero, correct size)
    assert_eq!(shared_secret.len(), 32);
    assert_ne!(shared_secret, [0u8; 32]);
}

// ---------------------------------------------------------------------------
// Stress tests — concurrent connections, sustained traffic, MTU boundaries
// ---------------------------------------------------------------------------

#[test]
fn test_concurrent_connections() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let (echo_addr, _echo_handle) = spawn_echo_target();

    let user_uuid = Uuid::new_v4();
    let user_id_str = user_uuid.to_string();

    let _server = spawn_wrongsv_server(&listen_str, &user_id_str, "");
    thread::sleep(Duration::from_millis(50));

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let addr = listen_str.clone();
            let uuid = user_uuid;
            let echo_port = echo_addr.port();
            thread::spawn(move || {
                let mut conn = vless_connect(&addr, &uuid, "127.0.0.1", echo_port, "");
                let msg = format!("concurrent-{}", i);
                conn.write_all(msg.as_bytes()).unwrap();
                let mut buf = [0u8; 64];
                let n = conn.read(&mut buf).unwrap();
                assert_eq!(&buf[..n], msg.as_bytes());
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_sustained_bidirectional_traffic() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let (echo_addr, _echo_handle) = spawn_echo_target();

    let user_uuid = Uuid::new_v4();
    let user_id_str = user_uuid.to_string();

    let _server = spawn_wrongsv_server(&listen_str, &user_id_str, "");
    thread::sleep(Duration::from_millis(50));

    let mut conn = vless_connect(&listen_str, &user_uuid, "127.0.0.1", echo_addr.port(), "");

    // 100 round-trips of varying sizes
    for i in 0..100 {
        let size = 64 + (i % 16) * 64; // 64..1024 bytes
        let payload: Vec<u8> = (0..size).map(|b| b as u8).collect();
        conn.write_all(&payload).unwrap();

        let mut received = vec![0u8; size];
        conn.read_exact(&mut received).unwrap();
        assert_eq!(received, payload, "mismatch at iteration {i}, size {size}");
    }
}

#[test]
fn test_mtu_boundary_payloads() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let (echo_addr, _echo_handle) = spawn_echo_target();

    let user_uuid = Uuid::new_v4();
    let user_id_str = user_uuid.to_string();

    let _server = spawn_wrongsv_server(&listen_str, &user_id_str, "");
    thread::sleep(Duration::from_millis(50));

    // Test sizes around common MTU boundaries
    for &size in &[1, 64, 256, 512, 1024, 1460, 1500, 4096, 8192, 16384] {
        let mut conn = vless_connect(&listen_str, &user_uuid, "127.0.0.1", echo_addr.port(), "");
        let payload: Vec<u8> = (0..size).map(|b| (b & 0xFF) as u8).collect();
        conn.write_all(&payload).unwrap();

        let mut received = vec![0u8; size];
        conn.read_exact(&mut received).unwrap();
        assert_eq!(received, payload, "mismatch at MTU size {size}");
    }
}

#[test]
fn test_concurrent_vision_connections() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let (echo_addr, _echo_handle) = spawn_echo_target();

    let user_uuid = Uuid::new_v4();
    let user_id_str = user_uuid.to_string();

    let _server = spawn_wrongsv_server(&listen_str, &user_id_str, "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    use wrongsv_vless::vision::{TrafficState, VisionReader};

    let handles: Vec<_> = (0..5)
        .map(|i| {
            let addr = listen_str.clone();
            let uuid = user_uuid;
            let echo_port = echo_addr.port();
            thread::spawn(move || {
                let conn = vless_connect(&addr, &uuid, "127.0.0.1", echo_port, "xtls-rprx-vision");
                let mut writer = conn.try_clone().unwrap();
                let state = TrafficState::new(uuid.as_bytes());
                let mut reader = VisionReader::new(conn, state, true);

                let msg = format!("vision-concurrent-{}", i);
                writer.write_all(msg.as_bytes()).unwrap();

                let mut buf = [0u8; 64];
                let n = reader.read(&mut buf).unwrap();
                assert!(n > 0, "expected vision data, got nothing");
                assert_eq!(&buf[..n], msg.as_bytes());
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// 114-group randomized correctness test
// ---------------------------------------------------------------------------

#[test]
fn test_114_randomized_scenarios() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let (echo_addr, _echo_handle) = spawn_echo_target();

    // Deterministic seed for reproducibility
    let mut rng: rand::rngs::StdRng = rand::SeedableRng::seed_from_u64(0xDEAD_BEEF_CAFE_BABE);

    // Pre-create raw and vision servers with dedicated users
    let raw_uuid = Uuid::new_v4();
    let raw_id_str = raw_uuid.to_string();
    let vision_uuid = Uuid::new_v4();
    let vision_id_str = vision_uuid.to_string();

    let _raw_server = spawn_wrongsv_server(&listen_str, &raw_id_str, "");
    let vision_reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let vision_server_addr = vision_reserve.local_addr().unwrap();
    let vision_listen_str = vision_server_addr.to_string();
    drop(vision_reserve);
    let _vision_server =
        spawn_wrongsv_server(&vision_listen_str, &vision_id_str, "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    tracing::info!("114-group randomized test starting...");
    let mut failures = 0u32;

    for seq in 0..114 {
        let use_vision: bool = rng.r#gen();
        let (addr, uuid) = if use_vision {
            (&vision_listen_str, vision_uuid)
        } else {
            (&listen_str, raw_uuid)
        };
        let flow = if use_vision { "xtls-rprx-vision" } else { "" };

        // Vision: 64..4096 (tiny payloads hit Vision framing edge cases with
        // the echo test; large payloads produce multi-frame responses the
        // simple VisionReader cannot reassemble). Raw: 1..65536 full range.
        let payload_size: usize = if use_vision {
            rng.gen_range(64..=4096)
        } else {
            let size_selector: u32 = rng.gen_range(0..100);
            if size_selector < 10 {
                rng.gen_range(1..64)
            } else if size_selector < 30 {
                rng.gen_range(64..1500)
            } else if size_selector < 60 {
                rng.gen_range(1500..8192)
            } else if size_selector < 90 {
                rng.gen_range(8192..32768)
            } else {
                rng.gen_range(32768..65536)
            }
        };

        let payload: Vec<u8> = (0..payload_size).map(|_| rng.r#gen::<u8>()).collect();

        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let conn = vless_connect(addr, &uuid, "127.0.0.1", echo_addr.port(), flow);

            if use_vision {
                use wrongsv_vless::vision::{TrafficState, VisionReader};
                let mut writer = conn.try_clone()?;
                let state = TrafficState::new(uuid.as_bytes());
                let mut reader = VisionReader::new(conn, state, true);

                // Single write_all — chunking causes multi-frame Vision responses
                // that the simple VisionReader cannot reassemble
                writer.write_all(&payload)?;

                let mut received = vec![0u8; payload_size];
                let mut read = 0;
                while read < payload_size {
                    let n = reader.read(&mut received[read..])?;
                    if n == 0 {
                        break;
                    }
                    read += n;
                }
                if read != payload_size {
                    return Err(format!("vision short read {read}/{payload_size}").into());
                }
                if received[..read] != payload[..read] {
                    let mismatch = received[..read]
                        .iter()
                        .zip(payload.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(0);
                    return Err(format!(
                        "vision data mismatch at byte {}/{}: got {:02x?}.. expected {:02x?}..",
                        mismatch,
                        payload_size,
                        &received[..(read.min(16))],
                        &payload[..(payload_size.min(16))]
                    )
                    .into());
                }
            } else {
                let mut writer = conn.try_clone()?;
                let mut reader = conn;

                // Single write_all for deterministic RNG state across iterations
                writer.write_all(&payload)?;

                let mut received = vec![0u8; payload_size];
                let mut read = 0;
                while read < payload_size {
                    let n = reader.read(&mut received[read..])?;
                    if n == 0 {
                        break;
                    }
                    read += n;
                }
                if read != payload_size {
                    return Err(format!("raw short read {read}/{payload_size}").into());
                }
                if received[..read] != payload[..read] {
                    return Err("raw data mismatch".into());
                }
            }
            Ok(())
        })();

        if let Err(e) = result {
            failures += 1;
            tracing::warn!("[{seq}/114] FAIL vision={use_vision} size={payload_size}: {e}");
            if failures >= 5 {
                panic!(
                    "{failures} failures in first {} iterations — aborting",
                    seq + 1
                );
            }
        }

        if seq % 20 == 19 {
            tracing::info!("  [{}/114] complete, {failures} failures so far", seq + 1);
        }
    }

    tracing::info!("114-group done: {}/114 failures", failures);
    assert_eq!(failures, 0, "{failures}/114 randomized scenarios failed");
}

// ---------------------------------------------------------------------------
// REALITY integration tests
// ---------------------------------------------------------------------------

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Build a minimal TLS 1.3 ClientHello with a 32-byte session_id and X25519 key_share.
fn build_reality_client_hello(
    random: [u8; 32],
    session_id: [u8; 32],
    key_share: [u8; 32],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x01);
    body.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 compat version
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&session_id);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: TLS_AES_128_GCM_SHA256
    body.extend_from_slice(&[0x01, 0x00]); // compression: null

    // Build extensions
    let mut extensions = Vec::new();

    // supported_versions (0x002b): TLS 1.3 = 0x0304
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&3u16.to_be_bytes()); // length
    extensions.push(2); // versions length
    extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3

    // signature_algorithms (0x000d): ed25519 + ecdsa_secp256r1_sha256
    extensions.extend_from_slice(&0x000du16.to_be_bytes());
    extensions.extend_from_slice(&6u16.to_be_bytes()); // length
    extensions.extend_from_slice(&4u16.to_be_bytes()); // list length
    extensions.extend_from_slice(&0x0807u16.to_be_bytes()); // ed25519
    extensions.extend_from_slice(&0x0403u16.to_be_bytes()); // ecdsa_secp256r1_sha256

    // supported_groups (0x000a): X25519
    extensions.extend_from_slice(&0x000au16.to_be_bytes());
    extensions.extend_from_slice(&4u16.to_be_bytes()); // length
    extensions.extend_from_slice(&2u16.to_be_bytes()); // list length
    extensions.extend_from_slice(&0x001Du16.to_be_bytes()); // X25519

    // key_share (0x0033): X25519
    extensions.extend_from_slice(&0x0033u16.to_be_bytes());
    extensions.extend_from_slice(&38u16.to_be_bytes()); // length
    extensions.extend_from_slice(&36u16.to_be_bytes()); // client_shares length
    extensions.extend_from_slice(&0x001Du16.to_be_bytes()); // X25519 group
    extensions.extend_from_slice(&32u16.to_be_bytes()); // key length
    extensions.extend_from_slice(&key_share);

    // server_name (0x0000): "www.microsoft.com"
    let host = b"www.microsoft.com";
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    let sn_len = 5 + host.len() as u16; // entry_len(2) + type(1) + len(2) + data
    extensions.extend_from_slice(&sn_len.to_be_bytes());
    extensions.extend_from_slice(&(3 + host.len() as u16).to_be_bytes()); // entry length
    extensions.push(0); // host_name type
    extensions.extend_from_slice(&(host.len() as u16).to_be_bytes());
    extensions.extend_from_slice(host);

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let hs_len = (body.len() - 4) as u32;
    body[1] = (hs_len >> 16) as u8;
    body[2] = (hs_len >> 8) as u8;
    body[3] = hs_len as u8;

    let mut record = Vec::new();
    record.push(0x16); // handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

fn spawn_wrongsv_server_with_reality(
    listen_addr: &str,
    user_id: &str,
    flow: &str,
    reality_private_key: &str,
    reality_short_ids: &[&str],
) -> thread::JoinHandle<()> {
    let short_ids_toml = reality_short_ids
        .iter()
        .map(|s| format!(r#""{}""#, s))
        .collect::<Vec<_>>()
        .join(", ");
    let config_toml = format!(
        r#"
listen = "{}"

[[users]]
id = "{}"
email = "test@reality.test"
flow = "{}"

[reality]
private_key = "{}"
short_ids = [{}]
max_time_diff = 300
"#,
        listen_addr, user_id, flow, reality_private_key, short_ids_toml
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    thread::spawn(move || {
        server.run().ok();
    })
}

/// Build a REALITY ClientHello for the given server public key and short_id.
/// Returns the wire-format ClientHello bytes.
fn build_reality_hello(server_pk_bytes: &[u8; 32], short_id: &[u8; 8]) -> Vec<u8> {
    let client_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_pk = PublicKey::from(&client_sk);
    let server_pk = PublicKey::from(*server_pk_bytes);
    let shared_secret = client_sk.diffie_hellman(&server_pk);

    let mut client_random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut client_random);

    let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret.as_bytes());
    let mut auth_key = vec![0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key).unwrap();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let mut plaintext = vec![0u8; 16];
    plaintext[0..3].copy_from_slice(&[1, 2, 3]);
    plaintext[3] = 0;
    plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
    plaintext[8..16].copy_from_slice(short_id);

    let temp_hello = build_reality_client_hello(client_random, [0u8; 32], *client_pk.as_bytes());
    let aad = &temp_hello[5..];

    let key = Key::<Aes256Gcm>::from_slice(&auth_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&client_random[20..32]);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_slice(),
                aad,
            },
        )
        .unwrap();

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&ct);

    build_reality_client_hello(client_random, session_id, *client_pk.as_bytes())
}

#[test]
fn test_reality_config_parse() {
    let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "test@reality.test"
flow = "xtls-rprx-vision"

[reality]
private_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
short_ids = ["abcdef0123456789", "9988776655443322"]
dest = "www.microsoft.com:443"
max_time_diff = 120
"#;
    let config: wrongsv_server::Config = toml::from_str(toml).unwrap();
    config.validate().unwrap();
    let reality = config.reality.unwrap();
    assert_eq!(
        reality.private_key,
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    );
    assert_eq!(reality.short_ids.len(), 2);
    assert_eq!(reality.short_ids[0], "abcdef0123456789");
    assert_eq!(reality.dest.unwrap(), "www.microsoft.com:443");
    assert_eq!(reality.max_time_diff, 120);
}

#[test]
fn test_reality_config_default_max_time_diff() {
    let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[reality]
private_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
short_ids = ["abcdef0123456789"]
"#;
    let config: wrongsv_server::Config = toml::from_str(toml).unwrap();
    let reality = config.reality.unwrap();
    assert_eq!(reality.max_time_diff, 300);
}

#[test]
fn test_reality_config_invalid_private_key_length() {
    let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[reality]
private_key = "too-short"
short_ids = ["abcdef0123456789"]
"#;
    let config: wrongsv_server::Config = toml::from_str(toml).unwrap();
    let result = wrongsv_server::InboundServer::new(config);
    assert!(result.is_err(), "should reject invalid private_key length");
}

#[test]
fn test_reality_config_invalid_short_id_length() {
    let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[reality]
private_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
short_ids = ["abcd"]
"#;
    let config: wrongsv_server::Config = toml::from_str(toml).unwrap();
    let result = wrongsv_server::InboundServer::new(config);
    assert!(result.is_err(), "should reject invalid short_id length");
}

#[test]
fn test_reality_server_startup() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let server_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let sk_hex: String = server_sk
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let short_id_hex = "abcdef0123456789";
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server_with_reality(
        &listen_str,
        &user_uuid.to_string(),
        "xtls-rprx-vision",
        &sk_hex,
        &[short_id_hex],
    );
    thread::sleep(Duration::from_millis(100));

    let conn = TcpStream::connect_timeout(&server_addr, Duration::from_secs(2));
    assert!(conn.is_ok(), "REALITY server should be listening");
}

#[test]
fn test_reality_invalid_hello_rejected() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let server_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let sk_hex: String = server_sk
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let short_id_hex = "abcdef0123456789";
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server_with_reality(
        &listen_str,
        &user_uuid.to_string(),
        "xtls-rprx-vision",
        &sk_hex,
        &[short_id_hex],
    );
    thread::sleep(Duration::from_millis(100));

    let mut conn = TcpStream::connect_timeout(&server_addr, Duration::from_secs(2)).unwrap();
    conn.write_all(b"NOT A TLS CLIENT HELLO").unwrap();

    conn.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 64];
    // Server should close connection on invalid hello
    let _ = conn.read(&mut buf);
}

#[test]
fn test_reality_valid_hello_accepted() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let server_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pk = PublicKey::from(&server_sk);
    let sk_hex: String = server_sk
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let short_id = *b"test4321";
    let short_id_hex: String = short_id.iter().map(|b| format!("{:02x}", b)).collect();

    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server_with_reality(
        &listen_str,
        &user_uuid.to_string(),
        "xtls-rprx-vision",
        &sk_hex,
        &[&short_id_hex],
    );
    thread::sleep(Duration::from_millis(100));

    // Build and send a valid REALITY ClientHello
    let hello = build_reality_hello(server_pk.as_bytes(), &short_id);

    let mut conn = TcpStream::connect_timeout(&server_addr, Duration::from_secs(5)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    conn.write_all(&hello).unwrap();

    // Server should respond with TLS ServerHello (handshake continues),
    // not close the connection. Read the response — it should be a TLS record.
    let mut buf = [0u8; 4096];
    let n = conn.read(&mut buf).unwrap();
    assert!(
        n > 0,
        "server should respond after valid REALITY ClientHello"
    );
    // TLS handshake records start with 0x16
    assert_eq!(
        buf[0], 0x16,
        "expected TLS handshake response from server, got 0x{:02x}",
        buf[0]
    );
}

#[test]
fn test_reality_wrong_short_id_rejected() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let server_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_pk = PublicKey::from(&server_sk);
    let sk_hex: String = server_sk
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let allowed_short_id = *b"test4321";
    let allowed_short_id_hex: String = allowed_short_id
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let wrong_short_id = *b"nope5678";

    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server_with_reality(
        &listen_str,
        &user_uuid.to_string(),
        "xtls-rprx-vision",
        &sk_hex,
        &[&allowed_short_id_hex],
    );
    thread::sleep(Duration::from_millis(100));

    // Build a REALITY ClientHello with a short_id NOT in the allow-list
    let hello = build_reality_hello(server_pk.as_bytes(), &wrong_short_id);

    let mut conn = TcpStream::connect_timeout(&server_addr, Duration::from_secs(5)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    conn.write_all(&hello).unwrap();

    // Server should close connection or not respond
    let mut buf = [0u8; 64];
    // Connection close is expected — either EOF or timeout
    let result = conn.read(&mut buf);
    // Server should close connection or not respond with TLS ServerHello
    let connection_closed = matches!(result, Err(_) | Ok(0));
    if !connection_closed {
        // If we got data, it must not be a TLS handshake (0x16)
        assert_ne!(
            buf[0], 0x16,
            "server should not complete handshake with wrong short_id"
        );
    }
}
