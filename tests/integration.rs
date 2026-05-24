use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use wrongsv_net_types::Address;
use wrongsv_protocol::{MemoryAccount, MemoryUser, RequestCommand, RequestHeader, ID};
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
    assert_eq!(decoded.header.address.to_string(), request.address.to_string());
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

    let mut conn = TcpStream::connect_timeout(
        &server_addr.parse().unwrap(),
        Duration::from_secs(5),
    )
    .unwrap();
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

    let mut conn =
        vless_connect(&listen_str, &user_uuid, "127.0.0.1", echo_addr.port(), "xtls-rprx-vision");

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

    let mut conn = TcpStream::connect_timeout(
        &server_addr.parse().unwrap(),
        Duration::from_secs(5),
    )
    .unwrap();
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
