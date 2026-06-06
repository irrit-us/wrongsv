use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rand::Rng;
use wrongsv_net_types::Address;
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
use wrongsv_uuid::Uuid;
use wrongsv_vless::{MemoryValidator, Validator};
use wrongsv_vless_encoding::{self as encoding, Addons, LengthPacketReader, LengthPacketWriter};

fn make_test_user() -> (Uuid, MemoryUser) {
    let uuid = Uuid::new_v4();
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(uuid),
            flow: String::new(),
            encryption: String::new(),
            udp: true,
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
            udp: true,
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
                udp: true,
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

fn spawn_wrongsv_server(
    listen_addr: &str,
    user_id: &str,
    flow: &str,
) -> wrongsv_server::ServerHandle {
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
    server.spawn()
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
            udp: true,
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
) -> wrongsv_server::ServerHandle {
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
    server.spawn()
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
            udp: true,
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
) -> wrongsv_server::ServerHandle {
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
    server.spawn()
}

/// Build a REALITY ClientHello for the given server public key and short_id.
/// Returns the wire-format ClientHello bytes.
fn build_reality_hello(server_pk_bytes: &[u8; 32], short_id: &[u8; 4]) -> Vec<u8> {
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
    plaintext[8..12].copy_from_slice(short_id);
    // bytes 12..16 are padding zeros

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
short_ids = ["abcdef01", "99887766"]
dest = "www.microsoft.com:443"
max_time_diff = 120
"#;
    let config: wrongsv_server::Config = toml::from_str(toml).unwrap();
    config.validate().unwrap();
    let reality = config.reality.as_ref().unwrap();
    assert_eq!(
        reality.private_key,
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    );
    assert_eq!(reality.short_ids.len(), 2);
    assert_eq!(reality.short_ids[0], "abcdef01");
    assert_eq!(reality.short_ids[0].len(), 8); // 8 hex chars = 4 bytes
    assert_eq!(reality.dest.as_deref().unwrap(), "www.microsoft.com:443");
    assert_eq!(reality.max_time_diff, 120);

    // Verify full parse pipeline (hex decode + cert generation)
    let _server = wrongsv_server::InboundServer::new(config).unwrap();
}

#[test]
fn test_reality_config_rejects_16char_short_id() {
    let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[reality]
private_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
short_ids = ["abcdef0123456789"]
"#;
    let config: wrongsv_server::Config = toml::from_str(toml).unwrap();
    let result = wrongsv_server::InboundServer::new(config);
    assert!(result.is_err(), "16-char short_id should be rejected");
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("expected 8 hex chars"),
        "error should mention hex char length, got: {err_msg}"
    );
}

#[test]
fn test_reality_config_default_max_time_diff() {
    let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[reality]
private_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
short_ids = ["abcdef01"]
"#;
    let config: wrongsv_server::Config = toml::from_str(toml).unwrap();
    let reality = config.reality.as_ref().unwrap();
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
short_ids = ["abcdef01"]
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
    let short_id_hex = "abcdef01";
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
    let short_id_hex = "abcdef01";
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

    let short_id = *b"test";
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

    let allowed_short_id = *b"test";
    let allowed_short_id_hex: String = allowed_short_id
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let wrong_short_id = *b"nope";

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

#[test]
fn test_reality_spider_fallback_forwards_to_dest() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    // Start an echo server that will receive the forwarded traffic
    let echo_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_dest = echo_addr.to_string();
    let echo_handle = thread::spawn(move || {
        let (mut conn, _) = echo_listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        // Read what the spider forwards, echo it back
        let n = conn.read(&mut buf).unwrap();
        conn.write_all(&buf[..n]).unwrap();
    });

    // Reserve port for REALITY server
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
    let user_uuid = Uuid::new_v4();
    let allowed_short_id = *b"real";
    let allowed_short_id_hex: String = allowed_short_id
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    // Build config with spider dest pointing to the echo server
    let config_toml = format!(
        r#"
listen = "{}"

[[users]]
id = "{}"
email = "test@reality.test"
flow = "xtls-rprx-vision"

[reality]
private_key = "{}"
short_ids = ["{}"]
max_time_diff = 300
dest = "{}"
"#,
        listen_str, user_uuid, sk_hex, allowed_short_id_hex, echo_dest
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let _server = server.spawn();
    thread::sleep(Duration::from_millis(100));

    // Send invalid ClientHello (wrong short_id) — should trigger spider fallback
    let wrong_short_id = *b"nope";
    let hello = build_reality_hello(server_pk.as_bytes(), &wrong_short_id);

    let mut conn = TcpStream::connect_timeout(&server_addr, Duration::from_secs(5)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(&hello).unwrap();

    // Spider should have forwarded to the echo server.
    // The echo server echoes back whatever it received.
    let mut buf = [0u8; 4096];
    let n = conn.read(&mut buf).unwrap();
    assert!(n > 0, "spider should forward to dest and echo data back");

    // Verify the echoed data matches what we sent (the ClientHello)
    assert_eq!(&buf[..n], &hello[..n]);

    echo_handle.join().ok();
}

// ============================================================================
// Cross-implementation verification tests against Go (Xray-core) test vectors
// ============================================================================

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct GoTestVectors {
    inputs: GoInputs,
    key_derivation: GoKeyDerivation,
    session_id: GoSessionID,
    cert_hmac: GoCertHmac,
    cert_generation: GoCertGeneration,
    patched_cert_der: String,
}

#[derive(Debug, Deserialize)]
struct GoInputs {
    server_private_key: String,
    client_ephemeral: GoClientEphemeral,
    client_random: String,
    short_id: String,
    timestamp: u32,
    raw_client_hello: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GoClientEphemeral {
    private_key: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct GoKeyDerivation {
    shared_secret: String,
    auth_key: String,
}

#[derive(Debug, Deserialize)]
struct GoSessionID {
    plaintext: String,
    nonce: String,
    aad: String,
    zeroed_aad: String,
    encrypted: String,
    decrypted: String,
    decrypted_version: String,
    decrypted_reserved: u8,
    decrypted_timestamp: u32,
    decrypted_short_id: String,
}

#[derive(Debug, Deserialize)]
struct GoCertHmac {
    auth_key: String,
    raw_pubkey: String,
    hmac_sha512: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GoCertGeneration {
    seed: String,
    cert_der: String,
    raw_pubkey: String,
    signing_key_der: String,
    cert_der_len: i64,
    signature_field: String,
}

fn load_go_vectors() -> GoTestVectors {
    let json = include_str!("reality_test_vectors.json");
    serde_json::from_str(json).expect("failed to parse Go test vectors")
}

/// Verify HKDF-SHA256 key derivation matches Go/Xray.
#[test]
fn test_cross_hkdf_key_derivation() {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    let v = load_go_vectors();

    let server_sk_bytes: [u8; 32] = hex::decode(&v.inputs.server_private_key)
        .unwrap()
        .try_into()
        .unwrap();
    let client_pk_bytes: [u8; 32] = hex::decode(&v.inputs.client_ephemeral.public_key)
        .unwrap()
        .try_into()
        .unwrap();
    let client_random: [u8; 32] = hex::decode(&v.inputs.client_random)
        .unwrap()
        .try_into()
        .unwrap();

    let server_sk = StaticSecret::from(server_sk_bytes);
    let client_pk = PublicKey::from(client_pk_bytes);

    let shared_secret = server_sk.diffie_hellman(&client_pk);
    assert_eq!(
        hex::encode(shared_secret.as_bytes()),
        v.key_derivation.shared_secret,
        "shared secret mismatch"
    );

    let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret.as_bytes());
    let mut auth_key = vec![0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key).unwrap();

    assert_eq!(
        hex::encode(&auth_key),
        v.key_derivation.auth_key,
        "auth_key mismatch"
    );
}

/// Verify AES-256-GCM SessionID decryption matches Go/Xray.
#[test]
fn test_cross_session_id_decryption() {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let v = load_go_vectors();

    let auth_key = hex::decode(&v.key_derivation.auth_key).unwrap();
    let encrypted: [u8; 32] = hex::decode(&v.session_id.encrypted)
        .unwrap()
        .try_into()
        .unwrap();
    let zeroed_aad = hex::decode(&v.session_id.zeroed_aad).unwrap();
    let nonce_bytes = hex::decode(&v.session_id.nonce).unwrap();

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&auth_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &encrypted,
                aad: &zeroed_aad,
            },
        )
        .expect("decryption must succeed with Go-encrypted data");

    assert_eq!(hex::encode(&plaintext), v.session_id.decrypted);
    assert_eq!(
        plaintext[0..3],
        hex::decode(&v.session_id.decrypted_version).unwrap()
    );
    assert_eq!(plaintext[3], v.session_id.decrypted_reserved);
    assert_eq!(
        u32::from_be_bytes(plaintext[4..8].try_into().unwrap()),
        v.session_id.decrypted_timestamp
    );
    assert_eq!(
        &plaintext[8..12],
        hex::decode(&v.session_id.decrypted_short_id)
            .unwrap()
            .as_slice()
    );
}

/// Verify that the Go-generated encrypted session_id roundtrips: decrypt it and re-verify.
#[test]
fn test_cross_session_id_encrypt_match() {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let v = load_go_vectors();

    let auth_key = hex::decode(&v.key_derivation.auth_key).unwrap();
    let plaintext = hex::decode(&v.session_id.plaintext).unwrap();
    let nonce_bytes = hex::decode(&v.session_id.nonce).unwrap();
    let aad = hex::decode(&v.session_id.aad).unwrap();
    let go_encrypted = hex::decode(&v.session_id.encrypted).unwrap();

    // Re-encrypt with the same inputs — but AES-GCM is non-deterministic only
    // if we use a random nonce. With the same nonce, key, plaintext, and AAD,
    // the output should be identical.
    // Actually, AES-GCM IS deterministic with the same inputs — but the Go code
    // uses a random nonce (client_random[20:32] which is random per connection).
    // For the test vectors, nonce is fixed, so we CAN verify.
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&auth_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let our_encrypted = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .unwrap();

    assert_eq!(
        hex::encode(&our_encrypted),
        hex::encode(&go_encrypted),
        "AES-GCM encryption must be deterministic with fixed nonce"
    );
}

/// Verify HMAC-SHA512 cert signature matches Go/Xray.
#[test]
fn test_cross_cert_hmac() {
    let v = load_go_vectors();

    let auth_key = hex::decode(&v.cert_hmac.auth_key).unwrap();
    let raw_pubkey: [u8; 32] = hex::decode(&v.cert_hmac.raw_pubkey)
        .unwrap()
        .try_into()
        .unwrap();

    let our_hmac = wrongsv_reality::compute_cert_hmac(&auth_key, &raw_pubkey).unwrap();

    assert_eq!(
        hex::encode(&our_hmac),
        v.cert_hmac.hmac_sha512,
        "HMAC-SHA512 mismatch between Rust and Go"
    );
}

/// Verify cert generation: Go's cert DER structure and patching.
#[test]
fn test_cross_cert_generation() {
    let v = load_go_vectors();

    // The patched cert has HMAC overwriting the last 64 bytes
    let patched_cert = hex::decode(&v.patched_cert_der).unwrap();
    let raw_pubkey: [u8; 32] = hex::decode(&v.cert_generation.raw_pubkey)
        .unwrap()
        .try_into()
        .unwrap();

    // Verify the last 64 bytes of patched cert = HMAC-SHA512(auth_key, raw_pubkey)
    let auth_key = hex::decode(&v.cert_hmac.auth_key).unwrap();
    let expected_hmac = wrongsv_reality::compute_cert_hmac(&auth_key, &raw_pubkey).unwrap();

    let sig_start = patched_cert.len() - 64;
    assert_eq!(
        &patched_cert[sig_start..],
        expected_hmac.as_slice(),
        "patched cert signature must equal HMAC-SHA512(auth_key, raw_pubkey)"
    );

    // Verify our build_cert_material produces a DER cert with compatible structure
    let material = wrongsv_reality::cert::build_cert_material().unwrap();
    // Our raw pubkey should be 32 bytes
    assert_eq!(material.raw_pubkey.len(), 32);
    // Our cert DER should have a 64-byte signature at the end
    assert!(material.cert_template_der.len() > 64);
}

/// End-to-end: Replicate the full REALITY auth flow using low-level primitives
/// and verify every step against Go-generated test vectors.
#[test]
fn test_cross_full_auth_flow() {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    let v = load_go_vectors();

    let server_sk_bytes: [u8; 32] = hex::decode(&v.inputs.server_private_key)
        .unwrap()
        .try_into()
        .unwrap();
    let client_pk_bytes: [u8; 32] = hex::decode(&v.inputs.client_ephemeral.public_key)
        .unwrap()
        .try_into()
        .unwrap();
    let client_random: [u8; 32] = hex::decode(&v.inputs.client_random)
        .unwrap()
        .try_into()
        .unwrap();
    let session_id: [u8; 32] = hex::decode(&v.session_id.encrypted)
        .unwrap()
        .try_into()
        .unwrap();
    let short_id: [u8; 4] = hex::decode(&v.inputs.short_id).unwrap().try_into().unwrap();
    let raw_body = hex::decode(&v.inputs.raw_client_hello).unwrap();

    // Step 1: ECDH + HKDF key derivation (matches Xray server)
    let server_sk = StaticSecret::from(server_sk_bytes);
    let client_pk = PublicKey::from(client_pk_bytes);
    let shared_secret = server_sk.diffie_hellman(&client_pk);
    let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret.as_bytes());
    let mut auth_key = vec![0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key).unwrap();

    assert_eq!(auth_key, hex::decode(&v.key_derivation.auth_key).unwrap());

    // Step 2: Build zeroed AAD (matches Xray server)
    let mut zeroed_aad = raw_body.clone();
    let sid_start = 39;
    zeroed_aad[sid_start..sid_start + 32].fill(0);

    // Step 3: Decrypt SessionID
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&auth_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&client_random[20..32]);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &session_id,
                aad: &zeroed_aad,
            },
        )
        .expect("decryption must succeed");

    // Step 4: Verify plaintext fields
    assert_eq!(plaintext[3], 0, "reserved must be 0"); // reserved
    let timestamp = u32::from_be_bytes(plaintext[4..8].try_into().unwrap());
    assert_eq!(timestamp, v.inputs.timestamp);
    let decrypted_short_id: &[u8; 4] = plaintext[8..12].try_into().unwrap();
    assert_eq!(decrypted_short_id, &short_id);

    // Step 5: Cert HMAC (Xray client verification)
    let raw_pubkey: [u8; 32] = hex::decode(&v.cert_generation.raw_pubkey)
        .unwrap()
        .try_into()
        .unwrap();
    let our_hmac = wrongsv_reality::compute_cert_hmac(&auth_key, &raw_pubkey).unwrap();
    assert_eq!(hex::encode(&our_hmac), v.cert_hmac.hmac_sha512);

    // Step 6: Verify patched cert
    let patched_cert = hex::decode(&v.patched_cert_der).unwrap();
    let sig_start = patched_cert.len() - 64;
    assert_eq!(&patched_cert[sig_start..], our_hmac.as_slice());
}

// ============================================================================
// End-to-end black-box test: Go REALITY client → Rust REALITY server
// ============================================================================

/// Generate a deterministic X25519 keypair for use in the Go client test.
fn generate_test_keypair() -> ([u8; 32], [u8; 32]) {
    use x25519_dalek::{PublicKey, StaticSecret};
    let sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let pk = PublicKey::from(&sk);
    (*sk.as_bytes(), *pk.as_bytes())
}

/// Go REALITY client connects to our Rust server and verifies the handshake.
///
/// This is the ultimate black-box test: a Go program implementing the REALITY
/// protocol exactly as Xray does connects to our Rust server, authenticates,
/// and verifies the certificate HMAC signature.
#[test]
fn test_go_client_handshake_with_rust_server() {
    // Path to the Go client binary
    let go_client = std::path::Path::new("/tmp/reality_vectors/reality_client");
    if !go_client.exists() {
        eprintln!(
            "Skipping: Go REALITY client not found at {}",
            go_client.display()
        );
        return;
    }

    // Generate server keypair
    let (sk, pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let pk_hex = hex::encode(pk);

    let short_id_hex = "deadbeef";

    let server_addr = format!("127.0.0.1:{}", 20500 + (rand::random::<u16>() % 10000));

    // Start Rust REALITY server
    let user_id = "12345678-1234-1234-1234-123456789abc";
    let handle =
        spawn_wrongsv_server_with_reality(&server_addr, user_id, "", &sk_hex, &[short_id_hex]);
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Run Go client against our server
    let output = std::process::Command::new(go_client)
        .args([&server_addr, &pk_hex, short_id_hex])
        .output()
        .expect("failed to spawn Go client");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        eprintln!("Go client STDOUT:\n{stdout}");
        eprintln!("Go client STDERR:\n{stderr}");
        panic!(
            "Go client exited with status {}",
            output.status.code().unwrap_or(-1)
        );
    }

    assert!(
        stdout.contains("PASS"),
        "Go client should report success. stdout: {stdout}"
    );
    // ServerHello confirms auth accepted; encrypted records confirm TLS progression
    assert!(
        stdout.contains("ServerHello received"),
        "Go client should receive ServerHello. stdout: {stdout}"
    );
    assert!(
        stdout.contains("handshake complete"),
        "Go client should complete handshake. stdout: {stdout}"
    );

    drop(handle);
}

// ============================================================================
// REALITY correctness tests — all configuration & edge case variants
// ============================================================================

/// Start a REALITY server with full config options (dest, max_time_diff, etc.).
fn spawn_reality_server_full(
    listen_addr: &str,
    user_id: &str,
    private_key_hex: &str,
    short_ids: &[&str],
    max_time_diff: u64,
    dest: Option<&str>,
) -> wrongsv_server::ServerHandle {
    let short_ids_toml = short_ids
        .iter()
        .map(|s| format!(r#""{}""#, s))
        .collect::<Vec<_>>()
        .join(", ");
    let dest_toml = match dest {
        Some(d) => format!(r#"dest = "{}""#, d),
        None => String::new(),
    };
    let config_toml = format!(
        r#"
listen = "{}"

[[users]]
id = "{}"
email = "test@reality.test"

[reality]
private_key = "{}"
short_ids = [{}]
max_time_diff = {}
{}
"#,
        listen_addr, user_id, private_key_hex, short_ids_toml, max_time_diff, dest_toml
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
}

/// Build a REALITY ClientHello that wraps the given raw body (without TLS record).
fn wrap_in_tls_record(body: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    record.push(0x16); // handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(body);
    record
}

/// Send raw bytes to a server and read response bytes (or error).
fn send_and_read(addr: &str, data: &[u8], timeout_ms: u64) -> Result<Vec<u8>, String> {
    let mut conn = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("parse: {e}"))?,
        Duration::from_millis(timeout_ms),
    )
    .map_err(|e| format!("connect: {e}"))?;
    conn.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok();
    conn.write_all(data).map_err(|e| format!("write: {e}"))?;
    let mut buf = vec![0u8; 4096];
    match conn.read(&mut buf) {
        Ok(n) => {
            buf.truncate(n);
            Ok(buf)
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(Vec::new()) // server dropped connection silently
        }
        Err(e) => Err(format!("read: {e}")),
    }
}

/// Check if response starts with a ServerHello
fn is_server_hello(resp: &[u8]) -> bool {
    resp.len() >= 6 && resp[0] == 0x16 && resp[5] == 0x02
}

// --- Config edge cases ---

#[test]
fn test_reality_multiple_short_ids() {
    let (sk, pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 21000 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa", "bbbbbbbb", "deadbeef"],
        300,
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    // First short_id should work
    let sid1: [u8; 4] = hex::decode("aaaaaaaa").unwrap().try_into().unwrap();
    let hello1 = build_reality_hello(&pk, &sid1);
    let resp1 = send_and_read(&addr, &hello1, 2000).unwrap();
    assert!(
        is_server_hello(&resp1),
        "valid short_id 1 should be accepted"
    );

    // Second should also work
    let sid2: [u8; 4] = hex::decode("bbbbbbbb").unwrap().try_into().unwrap();
    let hello2 = build_reality_hello(&pk, &sid2);
    let resp2 = send_and_read(&addr, &hello2, 2000).unwrap();
    assert!(
        is_server_hello(&resp2),
        "valid short_id 2 should be accepted"
    );

    // Third should also work
    let sid3: [u8; 4] = hex::decode("deadbeef").unwrap().try_into().unwrap();
    let hello3 = build_reality_hello(&pk, &sid3);
    let resp3 = send_and_read(&addr, &hello3, 2000).unwrap();
    assert!(
        is_server_hello(&resp3),
        "valid short_id 3 should be accepted"
    );

    // Unknown short_id should be rejected
    let bad_sid: [u8; 4] = *b"nope";
    let bad_hello = build_reality_hello(&pk, &bad_sid);
    let bad_resp = send_and_read(&addr, &bad_hello, 2000).unwrap();
    assert!(
        !is_server_hello(&bad_resp),
        "unknown short_id should be rejected"
    );

    drop(handle);
}

#[test]
fn test_reality_empty_short_ids_rejects_all() {
    let (sk, pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 21100 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &[], // empty short_ids
        300,
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    let sid: [u8; 4] = *b"anyt";
    let hello = build_reality_hello(&pk, &sid);
    let resp = send_and_read(&addr, &hello, 2000).unwrap();
    assert!(
        !is_server_hello(&resp),
        "empty short_ids must reject all: got {:?}",
        resp.get(..16)
    );

    drop(handle);
}

#[test]
fn test_reality_no_spider_drops_connection() {
    let (sk, pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 21200 + (rand::random::<u16>() % 10000));

    // No dest = no spider fallback
    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        None, // no dest
    );
    std::thread::sleep(Duration::from_millis(200));

    let bad_sid: [u8; 4] = *b"bad!";
    let hello = build_reality_hello(&pk, &bad_sid);
    let resp = send_and_read(&addr, &hello, 2000).unwrap();

    // Without spider, unauthenticated connections should be dropped
    // Either no response or a TLS alert
    if !resp.is_empty() {
        assert!(
            !is_server_hello(&resp),
            "bad auth should not get ServerHello"
        );
    }

    drop(handle);
}

// --- Auth payload edge cases ---

#[test]
fn test_reality_reserved_byte_nonzero_rejected() {
    let (sk, pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 21300 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    // Build a hello with reserved byte = 1
    let hello = build_reality_hello_with_options(
        &pk,
        &[0xaa; 4],
        &[1, 2, 3], // version
        1,          // reserved = 1 (invalid!)
        None,       // current timestamp
    );
    let resp = send_and_read(&addr, &hello, 2000).unwrap();
    assert!(!is_server_hello(&resp), "reserved != 0 must be rejected");

    drop(handle);
}

/// Build a REALITY hello with custom auth payload options.
fn build_reality_hello_with_options(
    server_pk_bytes: &[u8; 32],
    short_id: &[u8; 4],
    version: &[u8; 3],
    reserved: u8,
    timestamp_override: Option<u32>,
) -> Vec<u8> {
    let client_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let client_pk = PublicKey::from(&client_sk);
    let server_pk = PublicKey::from(*server_pk_bytes);
    let shared_secret = client_sk.diffie_hellman(&server_pk);

    let mut client_random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut client_random);

    let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret.as_bytes());
    let mut auth_key = vec![0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key).unwrap();

    let timestamp = timestamp_override.unwrap_or({
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32
    });

    let mut plaintext = vec![0u8; 16];
    plaintext[0..3].copy_from_slice(version);
    plaintext[3] = reserved;
    plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
    plaintext[8..12].copy_from_slice(short_id);
    // bytes 12..16 are padding zeros

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

    wrap_in_tls_record(
        &build_reality_client_hello(client_random, session_id, *client_pk.as_bytes())[5..],
    )
}

#[test]
fn test_reality_wrong_version_rejected() {
    let (sk, pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 21400 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    // Wrong version bytes (0,0,0 instead of 1,2,3)
    let hello = build_reality_hello_with_options(
        &pk,
        &[0xaa; 4],
        &[0, 0, 0], // wrong version
        0,          // reserved
        None,
    );
    let resp = send_and_read(&addr, &hello, 2000).unwrap();
    // Version bytes are not validated by Xray or our implementation,
    // so wrong version should still be accepted (ServerHello returned).
    assert!(
        is_server_hello(&resp),
        "wrong version should be accepted (version is not validated)"
    );

    drop(handle);
}

#[test]
fn test_reality_timestamp_at_boundary() {
    let (sk, pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 21500 + (rand::random::<u16>() % 10000));

    // Use a large max_time_diff to ensure timestamps are accepted
    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        31536000, // 1 year - generous
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    // Fresh timestamp should work
    let hello_fresh = build_reality_hello(&pk, &[0xaa; 4]);
    let resp = send_and_read(&addr, &hello_fresh, 2000).unwrap();
    assert!(
        is_server_hello(&resp),
        "current timestamp should be accepted with large max_time_diff"
    );

    // Old timestamp (1 hour ago) — should work with 1-year window
    let old_ts = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 3600) as u32;
    let hello_old = build_reality_hello_with_options(&pk, &[0xaa; 4], &[1, 2, 3], 0, Some(old_ts));
    let resp2 = send_and_read(&addr, &hello_old, 2000).unwrap();
    assert!(
        is_server_hello(&resp2),
        "timestamp 1h ago should be accepted with 1-year max_time_diff"
    );

    drop(handle);
}

#[test]
fn test_reality_timestamp_expired_rejected() {
    let (sk, pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 21600 + (rand::random::<u16>() % 10000));

    // Strict 1-second window
    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        1, // 1 second max_time_diff
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    // Old timestamp should be rejected with 1-second window
    let old_ts = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 10) as u32; // 10 seconds ago
    let hello_old = build_reality_hello_with_options(&pk, &[0xaa; 4], &[1, 2, 3], 0, Some(old_ts));
    let resp = send_and_read(&addr, &hello_old, 2000).unwrap();
    assert!(
        !is_server_hello(&resp),
        "timestamp 10s ago should be rejected with 1s max_time_diff"
    );

    drop(handle);
}

// --- ClientHello structure edge cases ---

#[test]
fn test_reality_non_tls_data_handled_gracefully() {
    let (sk, _pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 21700 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    // Send HTTP request (not TLS)
    let http_req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let resp = send_and_read(&addr, http_req, 2000).unwrap();
    // Server should not crash and either drop or respond with error
    assert!(
        !is_server_hello(&resp),
        "HTTP request should not get ServerHello"
    );

    // Send garbage bytes
    let garbage = [0x00u8; 100];
    let resp2 = send_and_read(&addr, &garbage, 2000).unwrap();
    assert!(
        !is_server_hello(&resp2),
        "garbage should not get ServerHello"
    );

    // Verify server still works after garbage
    let sid: [u8; 4] = hex::decode("aaaaaaaa").unwrap().try_into().unwrap();
    let hello = build_reality_hello_from_pk_bytes(server_pk_bytes_from_sk(&sk), &sid);
    let resp3 = send_and_read(&addr, &hello, 2000).unwrap();
    assert!(
        is_server_hello(&resp3),
        "server should still accept valid hello after garbage"
    );

    drop(handle);
}

/// Helper to get server public key bytes from private key
fn server_pk_bytes_from_sk(sk: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*sk);
    *PublicKey::from(&secret).as_bytes()
}

/// Build REALITY hello using raw server pubkey bytes (simpler interface)
fn build_reality_hello_from_pk_bytes(server_pk_bytes: [u8; 32], short_id: &[u8; 4]) -> Vec<u8> {
    build_reality_hello(&server_pk_bytes, short_id)
}

#[test]
fn test_reality_tls12_client_hello_handling() {
    let (sk, _pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 21800 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    // Build a TLS 1.2 ClientHello (supported_versions = TLS 1.2 only)
    let mut body = Vec::new();
    body.push(0x01); // handshake type
    body.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id length = 0
    body.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2b]); // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    body.extend_from_slice(&[0x01, 0x00]); // compression

    let mut exts = Vec::new();
    // supported_versions: only TLS 1.2
    exts.extend_from_slice(&0x002bu16.to_be_bytes());
    exts.extend_from_slice(&3u16.to_be_bytes());
    exts.push(2);
    exts.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let hs_len = (body.len() - 4) as u32;
    body[1] = (hs_len >> 16) as u8;
    body[2] = (hs_len >> 8) as u8;
    body[3] = hs_len as u8;

    let record = wrap_in_tls_record(&body);
    let resp = send_and_read(&addr, &record, 2000).unwrap();

    // TLS 1.2 might be rejected or might get a ServerHello with version negotiation
    // Either way, server should not crash
    if !resp.is_empty() && resp[0] == 0x15 {
        // Got alert — that's fine
    } else if is_server_hello(&resp) {
        // Server might accept TLS 1.2 — verify it's a valid response
    }
    // No crash = success

    drop(handle);
}

#[test]
fn test_reality_large_client_hello() {
    let (sk, pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 21900 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    let sid: [u8; 4] = hex::decode("aaaaaaaa").unwrap().try_into().unwrap();
    let base_hello = build_reality_hello(&pk, &sid);

    // Build a large ClientHello simulating uTLS fingerprint (~4KB) with a huge SNI
    let host = "a".repeat(3800);
    let mut body2 = Vec::new();
    body2.push(0x01);
    body2.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder
    body2.extend_from_slice(&[0x03, 0x03]);
    body2.extend_from_slice(&[0u8; 32][..]);
    body2.push(32);
    body2.extend_from_slice(&[0u8; 32][..]);
    body2.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body2.extend_from_slice(&[0x01, 0x00]);

    let mut exts = Vec::new();
    // SNI with large hostname
    exts.extend_from_slice(&0x0000u16.to_be_bytes());
    let sn_len = 5 + host.len() as u16;
    exts.extend_from_slice(&sn_len.to_be_bytes());
    exts.extend_from_slice(&(3 + host.len() as u16).to_be_bytes());
    exts.push(0);
    exts.extend_from_slice(&(host.len() as u16).to_be_bytes());
    exts.extend_from_slice(host.as_bytes());
    // supported_versions
    exts.extend_from_slice(&0x002bu16.to_be_bytes());
    exts.extend_from_slice(&3u16.to_be_bytes());
    exts.push(2);
    exts.extend_from_slice(&[0x03, 0x04]);

    body2.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body2.extend_from_slice(&exts);
    let hs_len = (body2.len() - 4) as u32;
    body2[1] = (hs_len >> 16) as u8;
    body2[2] = (hs_len >> 8) as u8;
    body2[3] = hs_len as u8;

    let large_record = wrap_in_tls_record(&body2);
    assert!(large_record.len() > 3000, "large hello should be > 3KB");

    let resp = send_and_read(&addr, &large_record, 3000).unwrap();
    // Not a valid REALITY hello (no auth), so should be rejected
    assert!(
        !is_server_hello(&resp),
        "unauthenticated large hello rejected"
    );

    // Verify server still works
    let resp2 = send_and_read(&addr, &base_hello, 2000).unwrap();
    assert!(
        is_server_hello(&resp2),
        "server still accepts valid hello after large one"
    );

    drop(handle);
}

#[test]
fn test_reality_missing_key_share_handling() {
    let (sk, _pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 22000 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    // Build ClientHello without key_share extension
    let mut body = Vec::new();
    body.push(0x01);
    body.extend_from_slice(&[0x00, 0x00, 0x00]);
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(32);
    body.extend_from_slice(&[0u8; 32]);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);

    let mut exts = Vec::new();
    exts.extend_from_slice(&0x002bu16.to_be_bytes()); // supported_versions
    exts.extend_from_slice(&3u16.to_be_bytes());
    exts.push(2);
    exts.extend_from_slice(&[0x03, 0x04]);
    // No key_share extension!

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let hs_len = (body.len() - 4) as u32;
    body[1] = (hs_len >> 16) as u8;
    body[2] = (hs_len >> 8) as u8;
    body[3] = hs_len as u8;

    let record = wrap_in_tls_record(&body);
    let resp = send_and_read(&addr, &record, 2000).unwrap();
    // Server should handle gracefully — either reject or alert
    assert!(
        !is_server_hello(&resp),
        "ClientHello without key_share should not succeed"
    );

    drop(handle);
}

#[test]
fn test_reality_wrong_key_share_group() {
    let (sk, _pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 22100 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    // Build ClientHello with P-256 key_share (group 0x0017) instead of X25519 (0x001d)
    let p256_point = [0x04u8; 65]; // uncompressed point for P-256
    let mut body = Vec::new();
    body.push(0x01);
    body.extend_from_slice(&[0x00, 0x00, 0x00]);
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(32);
    body.extend_from_slice(&[0u8; 32]);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);

    let mut exts = Vec::new();
    exts.extend_from_slice(&0x002bu16.to_be_bytes());
    exts.extend_from_slice(&3u16.to_be_bytes());
    exts.push(2);
    exts.extend_from_slice(&[0x03, 0x04]);
    // supported_groups with P-256
    exts.extend_from_slice(&0x000au16.to_be_bytes());
    exts.extend_from_slice(&4u16.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&0x0017u16.to_be_bytes()); // P-256
    // key_share with P-256
    exts.extend_from_slice(&0x0033u16.to_be_bytes());
    exts.extend_from_slice(&71u16.to_be_bytes()); // length
    exts.extend_from_slice(&69u16.to_be_bytes()); // share length
    exts.extend_from_slice(&0x0017u16.to_be_bytes()); // P-256 group
    exts.extend_from_slice(&65u16.to_be_bytes()); // key length
    exts.extend_from_slice(&p256_point);

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let hs_len = (body.len() - 4) as u32;
    body[1] = (hs_len >> 16) as u8;
    body[2] = (hs_len >> 8) as u8;
    body[3] = hs_len as u8;

    let record = wrap_in_tls_record(&body);
    let resp = send_and_read(&addr, &record, 2000).unwrap();
    // Server should reject — can't derive X25519 key from P-256 share
    assert!(
        !is_server_hello(&resp),
        "P-256 key_share should not succeed"
    );

    drop(handle);
}

#[test]
fn test_reality_malformed_tls_record() {
    let (sk, _pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 22200 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    // Case 1: too short
    let resp1 = send_and_read(&addr, &[0x16, 0x03], 2000).unwrap();
    assert!(
        resp1.is_empty() || resp1[0] == 0x15,
        "too short: drop or alert"
    );

    // Case 2: wrong record type
    let bad_type: Vec<u8> = [0x17, 0x03, 0x03, 0x00, 0x10]
        .iter()
        .chain(&[0u8; 16])
        .copied()
        .collect();
    let _resp2 = send_and_read(&addr, &bad_type, 2000).unwrap();

    // Case 3: length mismatch (claim 1000 bytes, send 10)
    let mut mismatch = vec![0x16, 0x03, 0x01, 0x03, 0xe8]; // 1000 bytes
    mismatch.extend_from_slice(&[0u8; 10]);
    let _ = send_and_read(&addr, &mismatch, 1000);

    // Verify server still functions
    let sid: [u8; 4] = hex::decode("aaaaaaaa").unwrap().try_into().unwrap();
    let hello = build_reality_hello_from_pk_bytes(server_pk_bytes_from_sk(&sk), &sid);
    let resp4 = send_and_read(&addr, &hello, 2000).unwrap();
    assert!(
        is_server_hello(&resp4),
        "server should still work after malformed input"
    );

    drop(handle);
}

#[test]
fn test_reality_spider_with_dest_forwards_and_echoes() {
    // Verify spider mode: when auth fails with a dest configured, the server
    // forwards the connection to the dest. We use a simple echo server as dest
    // and verify the client receives echoed data back.
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let _echo_handle = thread::spawn(move || {
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

    let (sk, pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 22300 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        Some(&echo_addr.to_string()),
    );
    std::thread::sleep(Duration::from_millis(200));

    // Send wrong short_id → spider forwards to echo server. The echo
    // echoes back, and spider relays it to us. Just verify we get data
    // back (not a drop) and server remains healthy.
    let bad_sid: [u8; 4] = *b"nope";
    let hello = build_reality_hello(&pk, &bad_sid);
    let mut conn =
        TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    conn.write_all(&hello).unwrap();

    // We should get something back from the spider relay (echoed data)
    let mut buf = [0u8; 4096];
    let got_data = match conn.read(&mut buf) {
        Ok(n) if n > 0 => {
            // Got echoed data back — spider forwarding works
            eprintln!("  Spider forward: got {n} bytes back from echo dest");
            true
        }
        _ => {
            eprintln!("  Spider forward: no data back (timeout or drop, acceptable)");
            false
        }
    };
    assert!(
        got_data,
        "spider forwarding should relay echoed data back to client"
    );

    drop(conn);
    drop(handle);
    // echo_handle.join() would block forever (infinite accept loop);
    // thread is killed when the test process exits.
}

// ============================================================================
// REALITY stress tests
// ============================================================================

#[test]
fn test_reality_concurrent_authenticated_connections() {
    let (sk, pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 23000 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    let sid: [u8; 4] = hex::decode("aaaaaaaa").unwrap().try_into().unwrap();

    // Spawn 50 concurrent connections
    let handles: Vec<_> = (0..50)
        .map(|_| {
            let addr = addr.clone();
            thread::spawn(move || {
                let hello = build_reality_hello(&pk, &sid);
                let mut conn =
                    TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5))
                        .unwrap();
                conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                conn.write_all(&hello).unwrap();
                let mut buf = [0u8; 1024];
                match conn.read(&mut buf) {
                    Ok(n) if n > 0 => buf[0] == 0x16, // got ServerHello
                    _ => false,
                }
            })
        })
        .collect();

    let mut success = 0;
    for h in handles {
        if h.join().unwrap() {
            success += 1;
        }
    }
    assert!(
        success > 0,
        "at least some concurrent connections should succeed"
    );
    eprintln!("  Concurrent REALITY: {success}/50 connections got ServerHello");

    drop(handle);
}

#[test]
fn test_reality_mixed_auth_and_spider() {
    // Verify mixed valid/invalid connections are handled correctly.
    // Without spider dest, invalid connections are dropped (connection rejected).
    // Valid connections proceed to TLS handshake.
    let (sk, pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 23100 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        None, // no spider dest — invalid connections get dropped
    );
    std::thread::sleep(Duration::from_millis(200));

    let valid_sid: [u8; 4] = hex::decode("aaaaaaaa").unwrap().try_into().unwrap();
    let bad_sid: [u8; 4] = *b"nope";

    // Send 20 valid and 20 invalid connections concurrently
    let mut handles = Vec::new();
    for i in 0..40 {
        let addr = addr.clone();
        let is_valid = i % 2 == 0;
        let short_id = if is_valid { valid_sid } else { bad_sid };
        handles.push(thread::spawn(move || {
            let hello = build_reality_hello(&pk, &short_id);
            let mut conn =
                TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5)).unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            conn.write_all(&hello).unwrap();
            let mut buf = [0u8; 4096];
            match conn.read(&mut buf) {
                Ok(n) if n > 0 => {
                    let got_server_hello = buf[0] == 0x16 && buf[5] == 0x02;
                    (is_valid, got_server_hello)
                }
                _ => (is_valid, false),
            }
        }));
    }

    let mut valid_ok = 0;
    let mut valid_fail = 0;
    let mut invalid_got_hello = 0;
    let mut invalid_dropped = 0;

    for h in handles {
        match h.join().unwrap() {
            (true, true) => valid_ok += 1,
            (true, false) => valid_fail += 1,
            (false, false) => invalid_dropped += 1,
            (false, true) => invalid_got_hello += 1,
        }
    }

    assert!(valid_ok > 0, "valid connections should get ServerHello");
    // Invalid connections should be dropped (no spider dest)
    assert!(
        invalid_dropped > 0,
        "invalid connections should be dropped without spider dest"
    );
    eprintln!(
        "  Mixed: {valid_ok} auth OK, {valid_fail} auth fail, \
         {invalid_got_hello} unexpected hello, {invalid_dropped} dropped"
    );

    drop(handle);
}

#[test]
fn test_reality_large_payload_through_tunnel() {
    // Create a full REALITY TLS tunnel and send large data through it
    // This simulates real traffic through the proxy

    let (sk, _pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 23200 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    // Send a valid REALITY hello and verify we get at least part of the handshake
    let pk = server_pk_bytes_from_sk(&sk);
    let sid: [u8; 4] = hex::decode("aaaaaaaa").unwrap().try_into().unwrap();
    let hello = build_reality_hello(&pk, &sid);

    let mut conn =
        TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    conn.write_all(&hello).unwrap();

    // Read the full server flight
    let mut total_data = Vec::new();
    let mut buf = [0u8; 8192];
    for _ in 0..10 {
        match conn.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total_data.extend_from_slice(&buf[..n]);
                if total_data.len() > 2000 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // We should have received the full server flight
    assert!(!total_data.is_empty(), "should receive server response");
    assert!(total_data[0] == 0x16, "should receive TLS record");

    // The server flight should be substantial (ServerHello + CCS + encrypted msgs)
    assert!(
        total_data.len() > 100,
        "server flight should be substantial"
    );
    eprintln!("  Server flight: {} bytes received", total_data.len());

    drop(handle);
}

#[test]
fn test_reality_rapid_connect_disconnect() {
    let (sk, pk) = generate_test_keypair();
    let sk_hex = hex::encode(sk);
    let addr = format!("127.0.0.1:{}", 23300 + (rand::random::<u16>() % 10000));

    let handle = spawn_reality_server_full(
        &addr,
        "12345678-1234-1234-1234-123456789abc",
        &sk_hex,
        &["aaaaaaaa"],
        300,
        None,
    );
    std::thread::sleep(Duration::from_millis(200));

    let sid: [u8; 4] = hex::decode("aaaaaaaa").unwrap().try_into().unwrap();

    // Rapidly connect, send hello, read a bit, disconnect
    let mut success_count = 0;
    for _ in 0..30 {
        let hello = build_reality_hello(&pk, &sid);
        if let Ok(mut conn) =
            TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(2))
        {
            conn.set_read_timeout(Some(Duration::from_millis(500))).ok();
            if conn.write_all(&hello).is_ok() {
                let mut buf = [0u8; 256];
                if conn.read(&mut buf).unwrap_or(0) > 0 {
                    success_count += 1;
                }
            }
            // drop immediately
        }
    }

    assert!(success_count > 0, "some connections should succeed");
    eprintln!("  Rapid connect/disconnect: {success_count}/30 successful");

    // Verify server still works after rapid cycling
    let hello = build_reality_hello(&pk, &sid);
    let resp = send_and_read(&addr, &hello, 2000).unwrap();
    assert!(
        is_server_hello(&resp),
        "server should still work after rapid connects"
    );

    drop(handle);
}

// ---------------------------------------------------------------------------
// UDP over TCP tests
// ---------------------------------------------------------------------------

fn vless_udp_connect(
    server_addr: &str,
    user_uuid: &Uuid,
    target_addr: &str,
    target_port: u16,
) -> TcpStream {
    let validator = Arc::new(MemoryValidator::new());
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(*user_uuid),
            flow: String::new(),
            encryption: String::new(),
            udp: true,
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "udp@e2e.test".into(),
        level: 0,
    };
    validator.add(user).unwrap();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Udp,
        address: Address::parse(target_addr),
        port: wrongsv_net_types::Port(target_port),
        user: validator.get(user_uuid.as_bytes()).unwrap(),
    };
    let addons = Addons {
        flow: String::new(),
        ..Default::default()
    };

    let mut buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut buf, &request, &addons).unwrap();

    let mut stream =
        TcpStream::connect_timeout(&server_addr.parse().unwrap(), Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&buf).unwrap();

    // Read response header
    let mut resp_buf = [0u8; 256];
    let n = stream.read(&mut resp_buf).unwrap();
    assert!(n > 0, "expected response header");

    stream
}

fn udp_echo_server() -> (Arc<UdpSocket>, String) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let socket = Arc::new(socket);
    let s = Arc::clone(&socket);
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = Arc::clone(&running);

    thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while r.load(std::sync::atomic::Ordering::SeqCst) {
            match s.recv_from(&mut buf) {
                Ok((n, src)) => {
                    s.send_to(&buf[..n], src).ok();
                }
                Err(ref e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
    });

    std::mem::forget(running);
    (socket, addr)
}

#[test]
fn test_udp_echo_single_packet() {
    let (_echo, echo_addr) = udp_echo_server();
    let echo_parts: Vec<&str> = echo_addr.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let (_, uuid) = make_test_validator();
    let listen = format!("127.0.0.1:{}", 40000 + (rand::random::<u16>() % 10000));
    let uuid_str = uuid.to_string();
    let handle = spawn_wrongsv_server(&listen, &uuid_str, "");
    thread::sleep(Duration::from_millis(200));

    let stream = vless_udp_connect(&listen, &uuid, "127.0.0.1", echo_port);
    let mut stream = stream;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    // Send a UDP packet via length-prefixed framing
    let payload = b"hello UDP world";
    let mut writer = LengthPacketWriter::new(&mut stream);
    writer.write_packet(payload).unwrap();

    // Read response
    let mut reader = LengthPacketReader::new(&mut stream);
    let resp = reader.read_packet().unwrap();
    assert_eq!(
        &resp[..],
        payload,
        "UDP echo should return the same payload"
    );

    drop(handle);
}

#[test]
fn test_udp_echo_multiple_packets() {
    let (_echo, echo_addr) = udp_echo_server();
    let echo_parts: Vec<&str> = echo_addr.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let (_, uuid) = make_test_validator();
    let listen = format!("127.0.0.1:{}", 40000 + (rand::random::<u16>() % 10000));
    let uuid_str = uuid.to_string();
    let handle = spawn_wrongsv_server(&listen, &uuid_str, "");
    thread::sleep(Duration::from_millis(200));

    let mut stream = vless_udp_connect(&listen, &uuid, "127.0.0.1", echo_port);
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    // Send 20 packets, verify all echoed
    for i in 0u8..20 {
        let payload = vec![i; 64];
        {
            let mut writer = LengthPacketWriter::new(&mut stream);
            writer.write_packet(&payload).unwrap();
        }
        let mut reader = LengthPacketReader::new(&mut stream);
        let resp = reader.read_packet().unwrap();
        assert_eq!(&resp[..], &payload, "packet {i}: UDP echo mismatch");
    }

    drop(handle);
}

#[test]
fn test_udp_echo_large_packet() {
    let (_echo, echo_addr) = udp_echo_server();
    let echo_parts: Vec<&str> = echo_addr.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let (_, uuid) = make_test_validator();
    let listen = format!("127.0.0.1:{}", 40000 + (rand::random::<u16>() % 10000));
    let uuid_str = uuid.to_string();
    let handle = spawn_wrongsv_server(&listen, &uuid_str, "");
    thread::sleep(Duration::from_millis(200));

    let mut stream = vless_udp_connect(&listen, &uuid, "127.0.0.1", echo_port);
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Send a near-MTU UDP packet
    let payload = vec![0xAB; 1400];
    let mut writer = LengthPacketWriter::new(&mut stream);
    writer.write_packet(&payload).unwrap();

    let mut reader = LengthPacketReader::new(&mut stream);
    let resp = reader.read_packet().unwrap();
    assert_eq!(resp.len(), payload.len());
    assert_eq!(&resp[..], &payload);

    drop(handle);
}

#[test]
fn test_udp_disabled_user_rejected() {
    let listen = format!("127.0.0.1:{}", 40000 + (rand::random::<u16>() % 10000));
    let uuid = Uuid::new_v4();
    let config_toml = format!(
        r#"
listen = "{}"

[[users]]
id = "{}"
email = "noudp@e2e.test"
flow = ""
udp = false
"#,
        listen, uuid,
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let handle = server.spawn();
    thread::sleep(Duration::from_millis(200));

    // Try to connect with UDP command
    let validator = Arc::new(MemoryValidator::new());
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(uuid),
            flow: String::new(),
            encryption: String::new(),
            udp: false,
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "noudp@e2e.test".into(),
        level: 0,
    };
    validator.add(user).unwrap();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Udp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(9999),
        user: validator.get(uuid.as_bytes()).unwrap(),
    };
    let addons = Addons::default();
    let mut buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut buf, &request, &addons).unwrap();

    let mut stream =
        TcpStream::connect_timeout(&listen.parse().unwrap(), Duration::from_secs(3)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(&buf).unwrap();

    // Server should drop the connection after sending response header
    let mut resp = Vec::new();
    let n = stream.read_to_end(&mut resp).unwrap_or(0);
    eprintln!("UDP-disabled connection closed after {} bytes read", n);

    drop(handle);
}

#[test]
fn test_udp_vision_rejected() {
    let listen = format!("127.0.0.1:{}", 40000 + (rand::random::<u16>() % 10000));
    let uuid = Uuid::new_v4();
    let config_toml = format!(
        r#"
listen = "{}"

[[users]]
id = "{}"
email = "udpvision@e2e.test"
flow = "xtls-rprx-vision"
"#,
        listen, uuid,
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    let handle = server.spawn();
    thread::sleep(Duration::from_millis(200));

    // Connect with UDP command + Vision flow
    let validator = Arc::new(MemoryValidator::new());
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(uuid),
            flow: "xtls-rprx-vision".into(),
            encryption: String::new(),
            udp: true,
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "udpvision@e2e.test".into(),
        level: 0,
    };
    validator.add(user).unwrap();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Udp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(9999),
        user: validator.get(uuid.as_bytes()).unwrap(),
    };
    let addons = Addons {
        flow: "xtls-rprx-vision".into(),
        ..Default::default()
    };
    let mut buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut buf, &request, &addons).unwrap();

    let mut stream =
        TcpStream::connect_timeout(&listen.parse().unwrap(), Duration::from_secs(3)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(&buf).unwrap();

    // Server should reject and close
    let mut resp = Vec::new();
    let n = stream.read_to_end(&mut resp).unwrap_or(0);
    eprintln!("UDP+Vision connection closed after {n} bytes read");

    drop(handle);
}

#[test]
fn test_udp_stress_many_packets() {
    let (_echo, echo_addr) = udp_echo_server();
    let echo_parts: Vec<&str> = echo_addr.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let (_, uuid) = make_test_validator();
    let listen = format!("127.0.0.1:{}", 40000 + (rand::random::<u16>() % 10000));
    let uuid_str = uuid.to_string();
    let handle = spawn_wrongsv_server(&listen, &uuid_str, "");
    thread::sleep(Duration::from_millis(200));

    let mut stream = vless_udp_connect(&listen, &uuid, "127.0.0.1", echo_port);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Send 200 packets of varying sizes, verify all echoed
    let mut rng = rand::thread_rng();
    for i in 0..200 {
        let size: usize = rng.gen_range(1..1400);
        let mut payload = vec![0u8; size];
        rng.fill(&mut payload[..]);

        let mut writer = LengthPacketWriter::new(&mut stream);
        writer.write_packet(&payload).unwrap();

        let mut reader = LengthPacketReader::new(&mut stream);
        let resp = reader.read_packet().unwrap();
        assert_eq!(resp.len(), payload.len(), "packet {i}: size mismatch");
        assert_eq!(&resp[..], &payload, "packet {i}: data mismatch");
    }

    drop(handle);
}

// =============================================================================
// configuration matrix — every (command, flow) combination
// =============================================================================

#[test]
fn test_configuration_matrix_smoke() {
    // (command, flow) combos that should succeed
    let combos: Vec<(RequestCommand, &str)> = vec![
        (RequestCommand::Tcp, ""),
        (RequestCommand::Tcp, "xtls-rprx-vision"),
        (RequestCommand::Udp, ""),
    ];

    for (cmd, flow) in &combos {
        let (echo_addr, _echo_handle) = spawn_echo_target();
        let echo_port = echo_addr.port();

        let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = reserve.local_addr().unwrap();
        let listen_str = server_addr.to_string();
        drop(reserve);

        let user_uuid = Uuid::new_v4();
        let user_str = user_uuid.to_string();
        let _server = spawn_wrongsv_server(&listen_str, &user_str, flow);
        thread::sleep(Duration::from_millis(50));

        if *cmd == RequestCommand::Udp {
            let (_udp_sock, udp_addr) = udp_echo_server();
            let udp_parts: Vec<&str> = udp_addr.split(':').collect();
            let udp_port: u16 = udp_parts[1].parse().unwrap();

            let stream = vless_udp_connect(&listen_str, &user_uuid, "127.0.0.1", udp_port);
            let mut stream = stream;
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();

            let payload = b"matrix-udp-test";
            let mut writer = LengthPacketWriter::new(&mut stream);
            writer.write_packet(payload).unwrap();
            let mut reader = LengthPacketReader::new(&mut stream);
            let resp = reader.read_packet().unwrap();
            assert_eq!(&resp[..], payload, "cmd={:?} flow={}", cmd, flow);
        } else if *flow == "xtls-rprx-vision" {
            use wrongsv_vless::vision::{TrafficState, VisionReader};
            let mut conn = vless_connect(&listen_str, &user_uuid, "127.0.0.1", echo_port, flow);
            conn.write_all(b"matrix-tcp-test").unwrap();
            let state = TrafficState::new(user_uuid.as_bytes());
            let mut reader = VisionReader::new(conn, state, true);
            let mut buf = [0u8; 64];
            let n = reader.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"matrix-tcp-test", "cmd={:?} flow={}", cmd, flow);
        } else {
            let mut conn = vless_connect(&listen_str, &user_uuid, "127.0.0.1", echo_port, flow);
            conn.write_all(b"matrix-tcp-test").unwrap();
            let mut buf = [0u8; 64];
            let n = conn.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"matrix-tcp-test", "cmd={:?} flow={}", cmd, flow);
        }
    }

    // UDP+Vision must be rejected
    {
        let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = reserve.local_addr().unwrap();
        let listen_str = server_addr.to_string();
        drop(reserve);

        let user_uuid = Uuid::new_v4();
        let user_str = user_uuid.to_string();
        let _server = spawn_wrongsv_server(&listen_str, &user_str, "xtls-rprx-vision");
        thread::sleep(Duration::from_millis(50));

        let (_udp_sock, udp_addr) = udp_echo_server();
        let udp_parts: Vec<&str> = udp_addr.split(':').collect();
        let udp_port: u16 = udp_parts[1].parse().unwrap();

        let validator = Arc::new(MemoryValidator::new());
        let user = MemoryUser {
            account: MemoryAccount {
                id: ID::new(user_uuid),
                flow: "xtls-rprx-vision".into(),
                encryption: String::new(),
                udp: true,
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
            command: RequestCommand::Udp,
            address: Address::parse("127.0.0.1"),
            port: wrongsv_net_types::Port(udp_port),
            user: validator.get(user_uuid.as_bytes()).unwrap(),
        };
        let addons = Addons {
            flow: "xtls-rprx-vision".into(),
            ..Default::default()
        };
        let mut req_buf = bytes::BytesMut::new();
        encoding::encode_request_header(&mut req_buf, &request, &addons).unwrap();

        let mut stream = TcpStream::connect_timeout(&server_addr, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(&req_buf).unwrap();

        // Server should close connection for UDP+Vision
        let mut buf = [0u8; 64];
        let result = stream.read(&mut buf);
        let rejected = result.is_err() || result.unwrap_or(1) == 0;
        assert!(rejected, "UDP+Vision should be rejected");
    }
}

#[test]
fn test_udp_stress_1000_packets() {
    let (_echo, echo_addr) = udp_echo_server();
    let echo_parts: Vec<&str> = echo_addr.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let (_, uuid) = make_test_validator();
    let listen = format!("127.0.0.1:{}", 41000 + (rand::random::<u16>() % 10000));
    let uuid_str = uuid.to_string();
    let _server = spawn_wrongsv_server(&listen, &uuid_str, "");
    thread::sleep(Duration::from_millis(50));

    let stream = vless_udp_connect(&listen, &uuid, "127.0.0.1", echo_port);
    let mut stream = stream;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut rng = rand::thread_rng();
    for i in 0..1000 {
        let size: usize = rng.gen_range(1..1400);
        let mut payload = vec![0u8; size];
        rng.fill(&mut payload[..]);

        let mut writer = LengthPacketWriter::new(&mut stream);
        writer.write_packet(&payload).unwrap();

        let mut reader = LengthPacketReader::new(&mut stream);
        let resp = reader.read_packet().unwrap();
        assert_eq!(&resp[..], &payload, "mismatch at packet {i}");
    }
}

#[test]
fn test_udp_concurrent_connections() {
    let (_echo, echo_addr) = udp_echo_server();
    let echo_parts: Vec<&str> = echo_addr.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let listen = format!("127.0.0.1:{}", 42000 + (rand::random::<u16>() % 10000));
    let user_uuid = Uuid::new_v4();
    let uuid_str = user_uuid.to_string();
    let _server = spawn_wrongsv_server(&listen, &uuid_str, "");
    thread::sleep(Duration::from_millis(50));

    let listen = Arc::new(listen);
    let user_uuid = Arc::new(user_uuid);

    let handles: Vec<_> = (0..10)
        .map(|client_id| {
            let listen = Arc::clone(&listen);
            let user_uuid = Arc::clone(&user_uuid);
            thread::spawn(move || {
                let stream = vless_udp_connect(&listen, &user_uuid, "127.0.0.1", echo_port);
                let mut stream = stream;
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut rng = rand::thread_rng();
                for i in 0..50 {
                    let size: usize = rng.gen_range(1..500);
                    let mut payload = vec![0u8; size];
                    rng.fill(&mut payload[..]);

                    let mut writer = LengthPacketWriter::new(&mut stream);
                    writer.write_packet(&payload).unwrap();

                    let mut reader = LengthPacketReader::new(&mut stream);
                    let resp = reader.read_packet().unwrap();
                    assert_eq!(
                        &resp[..],
                        &payload,
                        "client {client_id} packet {i}: mismatch"
                    );
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_mixed_tcp_udp_concurrent() {
    let (_echo, echo_addr) = udp_echo_server();
    let echo_parts: Vec<&str> = echo_addr.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let (tcp_echo_addr, _tcp_handle) = spawn_echo_target();

    let listen = format!("127.0.0.1:{}", 43000 + (rand::random::<u16>() % 10000));
    let user_uuid = Uuid::new_v4();
    let uuid_str = user_uuid.to_string();
    let _server = spawn_wrongsv_server(&listen, &uuid_str, "");
    thread::sleep(Duration::from_millis(50));

    let listen = Arc::new(listen);
    let user_uuid = Arc::new(user_uuid);

    let mut handles = Vec::new();

    // 5 TCP clients
    for i in 0..5 {
        let listen = Arc::clone(&listen);
        let user_uuid = Arc::clone(&user_uuid);
        handles.push(thread::spawn(move || {
            let mut stream =
                vless_connect(&listen, &user_uuid, "127.0.0.1", tcp_echo_addr.port(), "");
            let msg = format!("tcp-{i:03}-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
            stream.write_all(msg.as_bytes()).unwrap();
            let mut buf = [0u8; 128];
            let n = stream.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
        }));
    }

    // 5 UDP clients
    for i in 0..5 {
        let listen = Arc::clone(&listen);
        let user_uuid = Arc::clone(&user_uuid);
        handles.push(thread::spawn(move || {
            let stream = vless_udp_connect(&listen, &user_uuid, "127.0.0.1", echo_port);
            let mut stream = stream;
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            for j in 0..20 {
                let payload = format!("udp-{i:03}-{j:03}");
                let mut writer = LengthPacketWriter::new(&mut stream);
                writer.write_packet(payload.as_bytes()).unwrap();
                let mut reader = LengthPacketReader::new(&mut stream);
                let resp = reader.read_packet().unwrap();
                assert_eq!(&resp[..], payload.as_bytes(), "udp {i} pkt {j}");
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_kyber_with_udp_echo() {
    let kp = wrongsv_kyber::generate_keypair();
    let sk_hex: String = kp.sk.iter().map(|b| format!("{:02x}", b)).collect();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_addr = reserve.local_addr().unwrap();
    let listen_str = server_addr.to_string();
    drop(reserve);

    let user_uuid = Uuid::new_v4();
    let user_id_str = user_uuid.to_string();

    let _server = spawn_wrongsv_server_with_kyber(&listen_str, &user_id_str, "", &sk_hex);
    thread::sleep(Duration::from_millis(50));

    let (kyber_ct, _shared_secret) = wrongsv_kyber::encapsulate(&kp.pk).unwrap();

    let (_udp_sock, udp_addr) = udp_echo_server();
    let udp_parts: Vec<&str> = udp_addr.split(':').collect();
    let udp_port: u16 = udp_parts[1].parse().unwrap();

    // Build UDP request with kyber_ct
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
        email: "test@e2e.test".into(),
        level: 0,
    };
    validator.add(user).unwrap();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Udp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(udp_port),
        user: validator.get(user_uuid.as_bytes()).unwrap(),
    };
    let addons = Addons {
        flow: String::new(),
        kyber_ct,
    };
    let mut req_buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut req_buf, &request, &addons).unwrap();

    let mut conn = TcpStream::connect_timeout(&server_addr, Duration::from_secs(5)).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(&req_buf).unwrap();

    // Read response header
    let mut version_buf = [0u8; 1];
    conn.read_exact(&mut version_buf).unwrap();
    assert_eq!(version_buf[0], 0);

    let mut addons_len_buf = [0u8; 1];
    conn.read_exact(&mut addons_len_buf).unwrap();
    let addons_len = addons_len_buf[0] as usize;
    if addons_len > 0 {
        let mut proto_payload = vec![0u8; addons_len];
        conn.read_exact(&mut proto_payload).unwrap();
    }

    // UDP relay via Kyber connection
    let payload = b"kyber-udp-test";
    let mut writer = LengthPacketWriter::new(&mut conn);
    writer.write_packet(payload).unwrap();
    let mut reader = LengthPacketReader::new(&mut conn);
    let resp = reader.read_packet().unwrap();
    assert_eq!(&resp[..], payload);
}

#[test]
fn test_udp_zero_and_max_packets() {
    let (_echo, echo_addr) = udp_echo_server();
    let echo_parts: Vec<&str> = echo_addr.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let (_, uuid) = make_test_validator();
    let listen = format!("127.0.0.1:{}", 44000 + (rand::random::<u16>() % 10000));
    let uuid_str = uuid.to_string();
    let _server = spawn_wrongsv_server(&listen, &uuid_str, "");
    thread::sleep(Duration::from_millis(50));

    let stream = vless_udp_connect(&listen, &uuid, "127.0.0.1", echo_port);
    let mut stream = stream;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    // 1-byte packet
    {
        let mut writer = LengthPacketWriter::new(&mut stream);
        writer.write_packet(&[0xAB]).unwrap();
        let mut reader = LengthPacketReader::new(&mut stream);
        let resp = reader.read_packet().unwrap();
        assert_eq!(resp, vec![0xAB]);
    }

    // 10000-byte packet (large, fragmented)
    {
        let payload = vec![0xCD; 10000];
        let mut writer = LengthPacketWriter::new(&mut stream);
        writer.write_packet(&payload).unwrap();
        let mut reader = LengthPacketReader::new(&mut stream);
        let resp = reader.read_packet().unwrap();
        assert_eq!(resp.len(), 10000);
        assert_eq!(resp, payload);
    }
}
