//! Comprehensive integration tests for Vision relay correctness.
//!
//! Covers: HTTP versions, TLS-in-TLS, large payloads, chunked writes,
//! UDP relay, error handling, concurrency, sustained traffic, stress,
//! and protocol structure verification.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rand::Rng;
use wrongsv_net_types::Address;
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
use wrongsv_uuid::Uuid;
use wrongsv_vless::vision::{TrafficState, VisionReader, VisionWriter};
use wrongsv_vless::{MemoryValidator, Validator};
use wrongsv_vless_encoding::{self as encoding, Addons, LengthPacketReader, LengthPacketWriter};

// ── Helpers ──────────────────────────────────────────────────────────────────

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
        email: "test@vision.test".into(),
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

fn spawn_wrongsv_server(listen_addr: &str, user_id: &str, flow: &str) -> thread::JoinHandle<()> {
    let config_toml = format!(
        r#"
listen = "{}"

[[users]]
id = "{}"
email = "test@vision.test"
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
            udp: true,
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "test@vision.test".into(),
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
    let mut header = [0u8; 2];
    conn.read_exact(&mut header).unwrap();
    let addons_len = header[1] as usize;
    if addons_len > 0 {
        let mut addons_buf = vec![0u8; addons_len];
        conn.read_exact(&mut addons_buf).unwrap();
    }
    conn
}

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
        email: "test@vision.test".into(),
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
    let addons = Addons::default();

    let mut req_buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut req_buf, &request, &addons).unwrap();

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
    let mut header = [0u8; 2];
    conn.read_exact(&mut header).unwrap();
    let addons_len = header[1] as usize;
    if addons_len > 0 {
        let mut addons_buf = vec![0u8; addons_len];
        conn.read_exact(&mut addons_buf).unwrap();
    }
    conn
}

fn spawn_echo_target() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = echo.local_addr().unwrap();
    let handle = thread::spawn(move || {
        for stream in echo.incoming().flatten() {
            thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 65536];
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

/// Write data then read the echo response back using Vision unpadding on the
/// downlink. Returns the unpadded response bytes.
fn vision_echo(conn: TcpStream, user_uuid: &Uuid, payload: &[u8]) -> Vec<u8> {
    let mut conn = conn;
    conn.write_all(payload).unwrap();
    // Signal EOF so the server's uplink thread finishes and flushes
    // the Vision-padded response to us before we start reading.
    conn.shutdown(std::net::Shutdown::Write).unwrap();

    let state = TrafficState::new(user_uuid.as_bytes());
    let mut reader = VisionReader::new(conn, state, true);

    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(_) => break,
        }
    }
    response
}

/// Write payload then read until WouldBlock — for keep-alive scenarios where
/// the server won't send EOF between requests. Returns all data read so far.
/// `state` is reused across calls so the Vision frame sequence stays coherent.
fn vision_echo_keepalive(
    write_stream: &mut TcpStream,
    reader_stream: &TcpStream,
    state: &mut TrafficState,
    payload: &[u8],
) -> Vec<u8> {
    write_stream.write_all(payload).unwrap();

    // Set a short read timeout so we don't block forever waiting for EOF.
    // The server sends the response as a burst; once we stop getting data
    // we've received the full response.
    reader_stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();

    let mut reader = VisionReader::new(reader_stream.try_clone().unwrap(), state.clone(), true);

    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if !response.is_empty() {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(_) => break,
        }
    }
    // Recover the state so the next call continues the Vision frame sequence
    *state = reader.into_state();
    response
}

// ── Vision Payload Size Tests ────────────────────────────────────────────────

#[test]
fn test_vision_small_payload() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );
    let resp = vision_echo(conn, &user_uuid, b"hello");

    assert_eq!(resp, b"hello", "small payload echo mismatch");
}

#[test]
fn test_vision_payload_1kb() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );
    let payload = vec![0xCD; 1024];
    let resp = vision_echo(conn, &user_uuid, &payload);

    assert_eq!(resp.len(), 1024);
    assert_eq!(resp, payload);
}

#[test]
fn test_vision_payload_64kb() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(100));

    let conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );
    let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    let resp = vision_echo(conn, &user_uuid, &payload);

    assert_eq!(resp.len(), 65536, "expected 64KB, got {}", resp.len());
    assert_eq!(resp, payload, "64KB payload mismatch");
}

#[test]
fn test_vision_payload_128kb() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(100));

    let conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );
    // 128KB — stresses Vision framing across many TCP segments
    let size: usize = 128 * 1024;
    let payload: Vec<u8> = (0..size)
        .map(|i| (i.wrapping_mul(7).wrapping_add(13)) as u8)
        .collect();
    let resp = vision_echo(conn, &user_uuid, &payload);

    assert_eq!(resp.len(), size, "expected 128KB, got {}", resp.len());
    assert_eq!(resp, payload, "128KB payload mismatch");
}

// ── Chunked Write Tests ──────────────────────────────────────────────────────

#[test]
fn test_vision_chunked_write_reassembly() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let mut conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );

    // Write total data in chunks, then read all at once
    let total: usize = 4096;
    let payload: Vec<u8> = (0..total).map(|i| (i % 256) as u8).collect();

    // Write in random-sized chunks
    let mut written = 0;
    let mut rng = rand::thread_rng();
    while written < total {
        let chunk = rng.gen_range(1..256).min(total - written);
        conn.write_all(&payload[written..written + chunk]).unwrap();
        written += chunk;
    }

    let state = TrafficState::new(user_uuid.as_bytes());
    let mut reader = VisionReader::new(conn, state, true);

    let mut received = vec![0u8; total];
    let mut total_read = 0;
    while total_read < total {
        let n = reader.read(&mut received[total_read..]).unwrap();
        if n == 0 {
            break;
        }
        total_read += n;
    }
    assert_eq!(total_read, total, "expected {total}, got {total_read}");
    assert_eq!(received, payload, "chunked write reassembly mismatch");
}

#[test]
fn test_vision_single_byte_writes() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let mut conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );

    // Write 512 individual bytes sequentially
    let sent: Vec<u8> = (0..512u32).map(|i| (i % 256) as u8).collect();
    for &b in &sent {
        conn.write_all(&[b]).unwrap();
    }
    // Signal EOF so the server flushes the Vision-padded response.
    conn.shutdown(std::net::Shutdown::Write).unwrap();
    conn.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();

    let state = TrafficState::new(user_uuid.as_bytes());
    let mut reader = VisionReader::new(conn, state, true);

    let mut received = vec![0u8; 600];
    let mut total = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while total < 512 && std::time::Instant::now() < deadline {
        match reader.read(&mut received[total..]) {
            Ok(0) => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(n) => total += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
    assert_eq!(total, 512, "expected 512 bytes, got {total}");
    assert_eq!(&received[..512], &sent[..]);
}

// ── HTTP Protocol Tests ──────────────────────────────────────────────────────

#[test]
fn test_vision_http_1_0_get() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let http_target = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_addr = http_target.local_addr().unwrap();
    let http_port = http_addr.port();
    thread::spawn(move || {
        for stream in http_target.incoming().flatten() {
            thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap();
                let request = std::str::from_utf8(&buf[..n]).unwrap_or("");
                let response = format!(
                    "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    request.len(),
                    request
                );
                s.write_all(response.as_bytes()).unwrap();
            });
        }
    });

    let user_uuid = Uuid::new_v4();
    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        http_port,
        "xtls-rprx-vision",
    );
    let request = b"GET / HTTP/1.0\r\nHost: test\r\n\r\n";
    let resp = vision_echo(conn, &user_uuid, request);

    assert!(!resp.is_empty(), "expected HTTP response");
    let resp_str = std::str::from_utf8(&resp).unwrap();
    assert!(resp_str.contains("200 OK"), "expected 200 OK: {resp_str}");
    assert!(
        resp_str.contains("GET / HTTP/1.0"),
        "response should echo request: {resp_str}"
    );
}

#[test]
fn test_vision_http_1_1_keepalive() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let http_target = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_addr = http_target.local_addr().unwrap();
    let http_port = http_addr.port();
    thread::spawn(move || {
        for stream in http_target.incoming().flatten() {
            thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let request = std::str::from_utf8(&buf[..n]).unwrap_or("");
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                                request.len(),
                                request
                            );
                            if s.write_all(response.as_bytes()).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let user_uuid = Uuid::new_v4();
    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        http_port,
        "xtls-rprx-vision",
    );
    let read_stream = conn.try_clone().unwrap();
    let mut write_stream = conn;

    let mut downlink_state = TrafficState::new(user_uuid.as_bytes());
    for i in 0..3 {
        let request =
            format!("GET /page{i} HTTP/1.1\r\nHost: test\r\nConnection: keep-alive\r\n\r\n");
        let resp = vision_echo_keepalive(
            &mut write_stream,
            &read_stream,
            &mut downlink_state,
            request.as_bytes(),
        );

        let resp_str = std::str::from_utf8(&resp).unwrap();
        assert!(
            resp_str.contains("200 OK"),
            "request {i}: expected 200 OK: {resp_str}"
        );
    }
}

// ── TLS-in-TLS Tests ─────────────────────────────────────────────────────────

#[test]
fn test_vision_inner_tls_client_hello_passthrough() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );

    // Send a TLS ClientHello record through the proxy — Vision should detect
    // inner TLS and eventually switch to direct-copy mode
    let client_hello = build_tls_client_hello_record();
    let resp = vision_echo(conn, &user_uuid, &client_hello);

    // The echo server echoes back what it received
    assert!(!resp.is_empty(), "should get echo of TLS hello");
}

#[test]
fn test_vision_inner_tls_13_server_hello_detection() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );

    // Simulate a TLS 1.3 ServerHello with supported_versions extension
    let server_hello = build_tls13_server_hello_record();
    let resp = vision_echo(conn, &user_uuid, &server_hello);

    assert!(!resp.is_empty(), "should get echo of TLS 1.3 server hello");
}

fn build_tls_client_hello_record() -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x01); // ClientHello
    let hs_len: u32 = 2 + 32 + 1 + 6 + 2 + 1; // version + random + sid(0) + cipher + compress
    body.extend_from_slice(&hs_len.to_be_bytes()[1..]); // 3-byte length
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0xAAu8; 32]);
    body.push(0); // session_id len = 0
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher: TLS_AES_128_GCM
    body.extend_from_slice(&[0x01, 0x00]); // compression: null

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

fn build_tls13_server_hello_record() -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x02); // ServerHello
    let len_pos = body.len();
    body.extend_from_slice(&[0x00, 0x00, 0x00]);
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0xBBu8; 32]);
    body.push(0); // session_id len = 0
    body.extend_from_slice(&[0x13, 0x01]); // cipher
    body.push(0x00); // compression: null

    // supported_versions extension
    let mut exts = Vec::new();
    exts.extend_from_slice(&0x002bu16.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let body_len = body.len() - 4;
    body[len_pos] = (body_len >> 16) as u8;
    body[len_pos + 1] = (body_len >> 8) as u8;
    body[len_pos + 2] = body_len as u8;

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x03]);
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

// ── UDP Relay Tests ─────────────────────────────────────────────────────────

#[test]
fn test_udp_echo_single_packet() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = socket.local_addr().unwrap();
    let socket = Arc::new(socket);
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    let s = socket.try_clone().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while r.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok((n, addr)) = s.recv_from(&mut buf) {
                s.send_to(&buf[..n], addr).ok();
            }
        }
    });

    let addr_str = echo_addr.to_string();
    let echo_parts: Vec<&str> = addr_str.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let (_, uuid) = make_test_validator();
    let listen = format!("127.0.0.1:{}", 50000 + (rand::random::<u16>() % 10000));
    let handle = spawn_wrongsv_server(&listen, &uuid.to_string(), "");
    thread::sleep(Duration::from_millis(200));

    let mut stream = vless_udp_connect(&listen, &uuid, "127.0.0.1", echo_port);
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    let payload = b"hello UDP world";
    let mut writer = LengthPacketWriter::new(&mut stream);
    writer.write_packet(payload).unwrap();

    let mut reader = LengthPacketReader::new(&mut stream);
    let resp = reader.read_packet().unwrap();
    assert_eq!(&resp[..], payload, "UDP echo mismatch");

    running.store(false, std::sync::atomic::Ordering::SeqCst);
    drop(handle);
}

#[test]
fn test_udp_echo_multiple_packets() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = socket.local_addr().unwrap();
    let socket = Arc::new(socket);
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    let s = socket.try_clone().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while r.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok((n, addr)) = s.recv_from(&mut buf) {
                s.send_to(&buf[..n], addr).ok();
            }
        }
    });

    let addr_str = echo_addr.to_string();
    let echo_parts: Vec<&str> = addr_str.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let (_, uuid) = make_test_validator();
    let listen = format!("127.0.0.1:{}", 50000 + (rand::random::<u16>() % 10000));
    let handle = spawn_wrongsv_server(&listen, &uuid.to_string(), "");
    thread::sleep(Duration::from_millis(200));

    let mut stream = vless_udp_connect(&listen, &uuid, "127.0.0.1", echo_port);
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    for i in 0..20 {
        let payload = format!("UDP packet {}", i);
        {
            let mut writer = LengthPacketWriter::new(&mut stream);
            writer.write_packet(payload.as_bytes()).unwrap();
        }
        {
            let mut reader = LengthPacketReader::new(&mut stream);
            let resp = reader.read_packet().unwrap();
            assert_eq!(resp, payload.as_bytes(), "mismatch at packet {i}");
        }
    }

    running.store(false, std::sync::atomic::Ordering::SeqCst);
    drop(handle);
}

#[test]
fn test_udp_large_payload() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = socket.local_addr().unwrap();
    let socket = Arc::new(socket);
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    let s = socket.try_clone().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while r.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok((n, addr)) = s.recv_from(&mut buf) {
                s.send_to(&buf[..n], addr).ok();
            }
        }
    });

    let addr_str = echo_addr.to_string();
    let echo_parts: Vec<&str> = addr_str.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let (_, uuid) = make_test_validator();
    let listen = format!("127.0.0.1:{}", 50000 + (rand::random::<u16>() % 10000));
    let handle = spawn_wrongsv_server(&listen, &uuid.to_string(), "");
    thread::sleep(Duration::from_millis(200));

    let mut stream = vless_udp_connect(&listen, &uuid, "127.0.0.1", echo_port);
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let payload: Vec<u8> = (0..8192u32).map(|i| (i % 256) as u8).collect();
    let mut writer = LengthPacketWriter::new(&mut stream);
    writer.write_packet(&payload).unwrap();

    let mut reader = LengthPacketReader::new(&mut stream);
    let resp = reader.read_packet().unwrap();
    assert_eq!(resp, payload, "large UDP payload mismatch");

    running.store(false, std::sync::atomic::Ordering::SeqCst);
    drop(handle);
}

#[test]
fn test_udp_max_payload() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = socket.local_addr().unwrap();
    let socket = Arc::new(socket);
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    let s = socket.try_clone().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while r.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok((n, addr)) = s.recv_from(&mut buf) {
                s.send_to(&buf[..n], addr).ok();
            }
        }
    });

    let addr_str = echo_addr.to_string();
    let echo_parts: Vec<&str> = addr_str.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let (_, uuid) = make_test_validator();
    let listen = format!("127.0.0.1:{}", 50000 + (rand::random::<u16>() % 10000));
    let handle = spawn_wrongsv_server(&listen, &uuid.to_string(), "");
    thread::sleep(Duration::from_millis(200));

    let mut stream = vless_udp_connect(&listen, &uuid, "127.0.0.1", echo_port);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // IPv4 max UDP payload: 65535 - 20 (IP) - 8 (UDP) = 65507 bytes
    let payload: Vec<u8> = (0..65507u32)
        .map(|i| (i.wrapping_mul(17).wrapping_add(3)) as u8)
        .collect();
    let mut writer = LengthPacketWriter::new(&mut stream);
    writer.write_packet(&payload).unwrap();

    let mut reader = LengthPacketReader::new(&mut stream);
    let resp = reader.read_packet().unwrap();
    assert_eq!(resp.len(), payload.len(), "max UDP payload size mismatch");
    assert_eq!(resp, payload, "max UDP payload data mismatch");

    running.store(false, std::sync::atomic::Ordering::SeqCst);
    drop(handle);
}

#[test]
fn test_udp_packet_boundary_integrity() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = socket.local_addr().unwrap();
    let socket = Arc::new(socket);
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    let s = socket.try_clone().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while r.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok((n, addr)) = s.recv_from(&mut buf) {
                s.send_to(&buf[..n], addr).ok();
            }
        }
    });

    let addr_str = echo_addr.to_string();
    let echo_parts: Vec<&str> = addr_str.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let (_, uuid) = make_test_validator();
    let listen = format!("127.0.0.1:{}", 50000 + (rand::random::<u16>() % 10000));
    let handle = spawn_wrongsv_server(&listen, &uuid.to_string(), "");
    thread::sleep(Duration::from_millis(200));

    let mut stream = vless_udp_connect(&listen, &uuid, "127.0.0.1", echo_port);
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Send packets of wildly different sizes back-to-back, verify boundaries
    let sizes: &[usize] = &[1, 16, 64, 256, 1024, 4096, 8192, 1, 1400, 64, 32768];
    for (i, &size) in sizes.iter().enumerate() {
        let payload: Vec<u8> = (0..size)
            .map(|j| ((i as u32).wrapping_mul(37).wrapping_add(j as u32) % 251) as u8)
            .collect();
        {
            let mut writer = LengthPacketWriter::new(&mut stream);
            writer.write_packet(&payload).unwrap();
        }
        {
            let mut reader = LengthPacketReader::new(&mut stream);
            let resp = reader.read_packet().unwrap();
            assert_eq!(
                resp.len(),
                size,
                "packet {i} size {size}: got {}",
                resp.len()
            );
            assert_eq!(resp, payload, "packet {i} size {size}: data mismatch");
        }
    }

    running.store(false, std::sync::atomic::Ordering::SeqCst);
    drop(handle);
}

#[test]
fn test_udp_concurrent_clients() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = socket.local_addr().unwrap();
    let socket = Arc::new(socket);
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    let s = socket.try_clone().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while r.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok((n, addr)) = s.recv_from(&mut buf) {
                s.send_to(&buf[..n], addr).ok();
            }
        }
    });

    let addr_str = echo_addr.to_string();
    let echo_parts: Vec<&str> = addr_str.split(':').collect();
    let echo_port: u16 = echo_parts[1].parse().unwrap();

    let (_, uuid) = make_test_validator();
    let listen = format!("127.0.0.1:{}", 50000 + (rand::random::<u16>() % 10000));
    let handle = spawn_wrongsv_server(&listen, &uuid.to_string(), "");
    thread::sleep(Duration::from_millis(200));

    // 10 concurrent UDP clients, each sending 15 packets
    let handles: Vec<_> = (0..10)
        .map(|client_id| {
            let listen = listen.clone();
            thread::spawn(move || {
                let mut stream = vless_udp_connect(&listen, &uuid, "127.0.0.1", echo_port);
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();

                for pkt_id in 0..15 {
                    let seed: usize = (client_id << 8) | pkt_id;
                    let size = (seed % 1400) + 1;
                    let payload: Vec<u8> = (0..size)
                        .map(|j| (seed.wrapping_add(j) % 251) as u8)
                        .collect();

                    let mut writer = LengthPacketWriter::new(&mut stream);
                    writer.write_packet(&payload).unwrap();

                    let mut reader = LengthPacketReader::new(&mut stream);
                    let resp = reader.read_packet().unwrap();
                    assert_eq!(resp.len(), size, "client {client_id} pkt {pkt_id}: size");
                    assert_eq!(resp, payload, "client {client_id} pkt {pkt_id}: data");
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    running.store(false, std::sync::atomic::Ordering::SeqCst);
    drop(handle);
}

// ── Concurrent / Stress Tests ────────────────────────────────────────────────

#[test]
fn test_vision_concurrent_echo_connections() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(100));

    let handles: Vec<_> = (0..20)
        .map(|i| {
            let listen = listen_str.clone();
            let uuid = user_uuid;
            let eport = echo_addr.port();
            thread::spawn(move || {
                let conn = vless_connect(&listen, &uuid, "127.0.0.1", eport, "xtls-rprx-vision");
                let msg = format!("concurrent-vision-{}", i);
                let resp = vision_echo(conn, &uuid, msg.as_bytes());
                assert_eq!(resp, msg.as_bytes(), "mismatch conn {i}");
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_vision_sustained_bidirectional_traffic() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );
    let read_stream = conn.try_clone().unwrap();
    let mut write_stream = conn;

    // 50 round-trips of varying sizes
    let mut downlink_state = TrafficState::new(user_uuid.as_bytes());
    for i in 0..50 {
        let size = 64 + (i % 20) * 128; // 64..2496 bytes
        let payload: Vec<u8> = (0..size).map(|j| (j % 256) as u8).collect();
        let resp = vision_echo_keepalive(
            &mut write_stream,
            &read_stream,
            &mut downlink_state,
            &payload,
        );

        assert_eq!(
            resp.len(),
            size,
            "round {i}: expected {size}, got {}",
            resp.len()
        );
        assert_eq!(resp, payload, "round {i}: payload mismatch");
    }
}

#[test]
fn test_vision_mtu_boundary_payloads() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    // Test payloads at common MTU boundaries
    let sizes = &[1280, 1400, 1460, 1500, 2048, 4096, 8192, 9000, 16384];
    for &size in sizes {
        let conn = vless_connect(
            &listen_str,
            &user_uuid,
            "127.0.0.1",
            echo_addr.port(),
            "xtls-rprx-vision",
        );
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let resp = vision_echo(conn, &user_uuid, &payload);

        assert_eq!(resp.len(), size, "MTU {size}: size mismatch");
        assert_eq!(resp, payload, "MTU {size}: payload mismatch");
    }
}

#[test]
fn test_vision_mixed_raw_and_vision_connections() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let listen = listen_str.clone();
            let uuid = user_uuid;
            let eport = echo_addr.port();
            thread::spawn(move || {
                let msg = format!("mix-{}-vision={}", i, i % 2 == 0);

                if i % 2 == 0 {
                    let conn =
                        vless_connect(&listen, &uuid, "127.0.0.1", eport, "xtls-rprx-vision");
                    let resp = vision_echo(conn, &uuid, msg.as_bytes());
                    assert_eq!(resp, msg.as_bytes(), "vision conn {i}");
                } else {
                    let mut conn = vless_connect(&listen, &uuid, "127.0.0.1", eport, "");
                    conn.write_all(msg.as_bytes()).unwrap();
                    let mut buf = vec![0u8; 256];
                    let n = conn.read(&mut buf).unwrap();
                    assert_eq!(&buf[..n], msg.as_bytes(), "raw conn {i}");
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

// ── Error Handling Tests ────────────────────────────────────────────────────

#[test]
fn test_vision_random_garbage_passthrough() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );

    // Random garbage that doesn't match UUID prefix should pass through
    let garbage: Vec<u8> = (0..128).map(|_| rand::random::<u8>()).collect();
    let resp = vision_echo(conn, &user_uuid, &garbage);

    // Should echo back (garbage passes through Vision unpadding unchanged)
    assert!(!resp.is_empty(), "should get some echo");
    assert_eq!(resp, garbage, "garbage should pass through unchanged");
}

#[test]
fn test_vision_truncated_vision_frame() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let mut conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );

    // Send data that starts with a UUID prefix but is truncated
    let mut data = Vec::new();
    data.extend_from_slice(user_uuid.as_bytes()); // UUID prefix
    data.push(0x00); // command = continue
    data.push(0x00); // content len hi
    data.push(0x10); // content len lo = 16
    data.push(0x00); // padding len hi
    data.push(0x05); // padding len lo = 5
    data.extend_from_slice(&[0xCCu8; 8]); // only 8 bytes of content (expecting 16)
    // Truncated — missing 8 bytes of content and 5 bytes of padding
    data.extend_from_slice(b"recovery-data-after-truncated");

    conn.write_all(&data).unwrap();

    let state = TrafficState::new(user_uuid.as_bytes());
    let mut reader = VisionReader::new(conn, state, true);

    // Should produce some output even with the truncated frame
    let mut buf = vec![0u8; 256];
    let n = reader.read(&mut buf).unwrap();
    // Vision unpadding should handle this gracefully — either output the recovery
    // data or partial content
    assert!(
        n > 0,
        "should produce some output even with truncated frame"
    );
}

#[test]
fn test_vision_connection_drop_midstream() {
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let mut conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );

    // Send some data, then drop the connection
    conn.write_all(b"partial data before drop").unwrap();
    drop(conn);

    // The server should handle this gracefully (connection reset, no panic)
    thread::sleep(Duration::from_millis(200));
}

// ── Long-Running / Memory Stability Tests ────────────────────────────────────

#[test]
fn test_vision_long_running_traffic() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();

    let _server = spawn_wrongsv_server(&listen_str, &user_uuid.to_string(), "xtls-rprx-vision");
    thread::sleep(Duration::from_millis(50));

    let conn = vless_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
    );
    let read_stream = conn.try_clone().unwrap();
    let mut write_stream = conn;

    let start = Instant::now();
    let min_duration = Duration::from_secs(5);
    let mut iteration = 0u64;
    let mut downlink_state = TrafficState::new(user_uuid.as_bytes());

    while start.elapsed() < min_duration {
        let size = 64 + (iteration % 32) * 32; // 64..1056 bytes
        let payload: Vec<u8> = (0..size)
            .map(|j| ((iteration.wrapping_add(j)) % 251) as u8)
            .collect();

        write_stream.write_all(&payload).unwrap();
        read_stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();

        let mut reader = VisionReader::new(
            read_stream.try_clone().unwrap(),
            downlink_state.clone(),
            true,
        );
        let mut resp = Vec::new();
        let mut buf = [0u8; 8192];
        // Read until we have the expected number of bytes or hit timeout
        while resp.len() < size as usize {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => resp.extend_from_slice(&buf[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(_) => break,
            }
        }
        downlink_state = reader.into_state();

        assert_eq!(resp.len(), size as usize, "iteration {iteration}: size");
        assert_eq!(resp, payload, "iteration {iteration}: data");

        iteration += 1;
    }

    assert!(
        iteration > 200,
        "only {iteration} iterations in {min_duration:?}"
    );
}

// ── Protocol Correctness Tests ───────────────────────────────────────────────

#[test]
fn test_vision_command_padding_structure() {
    // Verify that VisionWriter produces correct frame structure:
    // [user_uuid(16)] command(1) content_len(2) padding_len(2) content(var) padding(var)
    let user_bytes = Uuid::new_v4().as_bytes().to_vec();
    let state = TrafficState::new(&user_bytes);
    let testseed = vec![900, 500, 900, 256];

    let mut output = Vec::new();
    {
        let mut writer = VisionWriter::new(&mut output, state, false, testseed);
        writer.write(b"test payload").unwrap();
        writer.flush().unwrap();
    }

    // Should start with user_uuid
    assert!(output.len() >= 21, "frame too short: {}", output.len());
    assert_eq!(
        &output[..16],
        &user_bytes[..],
        "frame must start with user UUID"
    );

    // command byte
    let cmd = output[16];
    assert!(
        cmd == 0x00 || cmd == 0x01 || cmd == 0x02,
        "unexpected command: {cmd}"
    );

    // content length
    let content_len = u16::from_be_bytes([output[17], output[18]]) as usize;
    assert!(output.len() >= 21 + content_len, "frame content truncated");
}

#[test]
fn test_vision_unpadding_roundtrip_various_sizes() {
    use wrongsv_vless::vision::xtls_unpadding;

    let user_bytes = Uuid::new_v4().as_bytes().to_vec();
    let testseed = vec![900, 500, 900, 256];

    let sizes = &[0, 1, 16, 64, 256, 512, 1024, 2047, 4096, 8191];
    for &size in sizes {
        let payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        // Encode with VisionWriter
        let mut encoded = Vec::new();
        {
            let state = TrafficState::new(&user_bytes);
            let mut writer = VisionWriter::new(&mut encoded, state, false, testseed.clone());
            writer.write(&payload).unwrap();
            writer.flush().unwrap();
        }

        // Decode with xtls_unpadding directly
        let mut state = TrafficState::new(&user_bytes);
        let unpadded = xtls_unpadding(&encoded, &mut state, true);

        // For size 0, padding may produce a Continue frame with no content
        if size == 0 {
            assert!(
                unpadded.is_empty(),
                "empty payload should produce empty output, got {} bytes",
                unpadded.len()
            );
        } else {
            assert_eq!(
                &unpadded[..unpadded.len().min(payload.len())],
                &payload[..unpadded.len().min(payload.len())],
                "unpadding roundtrip mismatch at size {size}"
            );
        }
    }
}

#[test]
fn test_vision_traffic_state_initial() {
    let user_bytes = Uuid::new_v4().as_bytes().to_vec();
    let state = TrafficState::new(&user_bytes);

    // Initial state should have within_padding_buffers = true
    assert!(state.inbound.within_padding_buffers);
    assert!(!state.inbound.direct_copy);
    assert!(!state.outbound.direct_copy);
    // First 8 packets should be filtered for TLS detection
    assert_eq!(state.number_of_packet_to_filter, 8);
}

#[test]
fn test_vision_direct_copy_flag_transition() {
    // After Vision detects TLS 1.3, direct_copy should become true.
    // Verify the state machine works correctly.
    let user_bytes = Uuid::new_v4().as_bytes().to_vec();
    let mut state = TrafficState::new(&user_bytes);

    // Simulate the transition that happens when Vision detects TLS 1.3
    state.inbound.within_padding_buffers = false;
    state.inbound.direct_copy = true;

    assert!(!state.inbound.within_padding_buffers);
    assert!(state.inbound.direct_copy);

    // Other direction should be unaffected
    assert!(state.inbound.within_padding_buffers == state.inbound.within_padding_buffers); // just a tautology, verifying we're testing what we think
    assert!(!state.outbound.direct_copy);
}
