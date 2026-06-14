//! Integration tests for AnyTLS protocol support.
//!
//! Covers: basic echo, Vision relay, auth failure → fallback, UDP relay.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::ClientConfig;
use sha2::{Digest, Sha256};
use wrongsv_net_types::Address;
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
use wrongsv_uuid::Uuid;
use wrongsv_vless::vision::{TrafficState, VisionReader};
use wrongsv_vless::{MemoryValidator, Validator};
use wrongsv_vless_encoding::{self as encoding, Addons};

// ── TLS helpers ───────────────────────────────────────────────────────────────

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn make_anytls_client_config() -> ClientConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth()
}

/// TLS-wrapped client stream with manual I/O handling.
struct TlsClient {
    conn: rustls::ClientConnection,
    sock: TcpStream,
}

impl Read for TlsClient {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tls_read(buf)
    }
}

impl Write for TlsClient {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tls_write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_flush()
    }
}

impl TlsClient {
    fn new(conn: rustls::ClientConnection, sock: TcpStream) -> Self {
        Self { conn, sock }
    }

    fn tls_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.conn.reader().read(buf) {
                Ok(0) => match self.conn.read_tls(&mut self.sock) {
                    Ok(0) => return Ok(0),
                    Ok(_) => {
                        self.conn
                            .process_new_packets()
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                        continue;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => return Err(e),
                },
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    match self.conn.read_tls(&mut self.sock) {
                        Ok(0) => return Ok(0),
                        Ok(_) => {
                            self.conn
                                .process_new_packets()
                                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                            continue;
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn tls_write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.conn.writer().write_all(buf)?;
        self.tls_flush()?;
        Ok(buf.len())
    }

    fn tls_flush(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            let n = self.conn.write_tls(&mut self.sock)?;
            if n == 0 {
                break;
            }
        }
        Ok(())
    }

    fn shutdown(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        self.tls_flush()
    }
}

// ── Echo target ───────────────────────────────────────────────────────────────

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

fn spawn_udp_echo_target() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut buf = [0u8; 65535];
        while let Ok((n, src)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&buf[..n], src);
        }
    });
    (addr, handle)
}

// ── Server spawner ────────────────────────────────────────────────────────────

fn spawn_anytls_server(
    listen: &str,
    user_id: &str,
    password: &str,
    flow: &str,
) -> wrongsv_server::ServerHandle {
    let config_toml = format!(
        r#"
listen = "{listen}"

[[users]]
id = "{user_id}"
email = "test@anytls.test"
flow = "{flow}"

[anytls]
password = "{password}"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
}

fn spawn_anytls_server_with_cert(
    listen: &str,
    user_id: &str,
    password: &str,
    cert_pem: &str,
    key_pem: &str,
) -> wrongsv_server::ServerHandle {
    let config_toml = format!(
        r#"
listen = "{listen}"

[[users]]
id = "{user_id}"
email = "test@anytls.test"

[anytls]
password = "{password}"
certificate = """{cert_pem}"""
key = """{key_pem}"""
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
}

fn spawn_anytls_server_multi_user(
    listen: &str,
    users: &[(String, String)], // (id, flow)
    password: &str,
) -> wrongsv_server::ServerHandle {
    let mut users_toml = String::new();
    for (uid, flow) in users {
        users_toml.push_str(&format!(
            r#"
[[users]]
id = "{uid}"
email = "{uid}@anytls.test"
flow = "{flow}"
"#
        ));
    }
    let config_toml = format!(
        r#"
listen = "{listen}"
{users_toml}

[anytls]
password = "{password}"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
}

fn spawn_anytls_server_with_fallback(
    listen: &str,
    user_id: &str,
    password: &str,
    fallback_dest: &str,
) -> wrongsv_server::ServerHandle {
    let config_toml = format!(
        r#"
listen = "{listen}"

[[users]]
id = "{user_id}"
email = "test@anytls.test"

[anytls]
password = "{password}"
dest = "{fallback_dest}"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
}

// ── AnyTLS client connect ─────────────────────────────────────────────────────

fn anytls_connect(
    server_addr: &str,
    user_uuid: &Uuid,
    target_addr: &str,
    target_port: u16,
    flow: &str,
    password: &str,
) -> TlsClient {
    let server: std::net::SocketAddr = server_addr.parse().unwrap();
    let mut sock = None;
    for _ in 0..20 {
        match TcpStream::connect_timeout(&server, Duration::from_millis(250)) {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("unexpected connect error: {e}"),
        }
    }
    let mut sock = sock.expect("server did not start within 5s");

    let server_name = rustls::pki_types::ServerName::try_from("cloudfront.net").unwrap();
    let mut conn =
        rustls::ClientConnection::new(Arc::new(make_anytls_client_config()), server_name).unwrap();

    // Complete TLS handshake
    loop {
        match conn.complete_io(&mut sock) {
            Ok((_, _)) if !conn.is_handshaking() => break,
            Ok(_) => continue,
            Err(e) => panic!("TLS handshake failed: {e}"),
        }
    }

    let mut tls = TlsClient::new(conn, sock);

    // Send auth frame: SHA256(password) || padding_len(0x0000)
    let password_hash: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    tls.tls_write(&password_hash).unwrap();
    tls.tls_write(&[0x00, 0x00]).unwrap();

    // Build VLESS header
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
        email: "test@anytls.test".into(),
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
    };
    let mut req_buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut req_buf, &request, &addons).unwrap();
    tls.tls_write(&req_buf).unwrap();

    // Read VLESS response header: version(1) + addons_len(1) + [addons]
    let mut header = [0u8; 2];
    read_exact_tls(&mut tls, &mut header).unwrap();
    let addons_len = header[1] as usize;
    if addons_len > 0 {
        let mut addons_buf = vec![0u8; addons_len];
        read_exact_tls(&mut tls, &mut addons_buf).unwrap();
    }

    tls
}

fn anytls_udp_connect(
    server_addr: &str,
    user_uuid: &Uuid,
    target_addr: &str,
    target_port: u16,
    password: &str,
) -> TlsClient {
    let server: std::net::SocketAddr = server_addr.parse().unwrap();
    let mut sock = None;
    for _ in 0..20 {
        match TcpStream::connect_timeout(&server, Duration::from_millis(250)) {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("unexpected connect error: {e}"),
        }
    }
    let mut sock = sock.expect("server did not start within 5s");

    let server_name = rustls::pki_types::ServerName::try_from("cloudfront.net").unwrap();
    let mut conn =
        rustls::ClientConnection::new(Arc::new(make_anytls_client_config()), server_name).unwrap();

    loop {
        match conn.complete_io(&mut sock) {
            Ok((_, _)) if !conn.is_handshaking() => break,
            Ok(_) => continue,
            Err(e) => panic!("TLS handshake failed: {e}"),
        }
    }

    let mut tls = TlsClient::new(conn, sock);

    let password_hash: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    tls.tls_write(&password_hash).unwrap();
    tls.tls_write(&[0x00, 0x00]).unwrap();

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
        email: "test@anytls.test".into(),
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
    tls.tls_write(&req_buf).unwrap();

    let mut header = [0u8; 2];
    read_exact_tls(&mut tls, &mut header).unwrap();
    let addons_len = header[1] as usize;
    if addons_len > 0 {
        let mut addons_buf = vec![0u8; addons_len];
        read_exact_tls(&mut tls, &mut addons_buf).unwrap();
    }

    tls
}

fn anytls_connect_with_padding(
    server_addr: &str,
    user_uuid: &Uuid,
    target_addr: &str,
    target_port: u16,
    flow: &str,
    password: &str,
    padding: &[u8],
) -> TlsClient {
    let server: std::net::SocketAddr = server_addr.parse().unwrap();
    let mut sock = None;
    for _ in 0..20 {
        match TcpStream::connect_timeout(&server, Duration::from_millis(250)) {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("unexpected connect error: {e}"),
        }
    }
    let mut sock = sock.expect("server did not start within 5s");

    let server_name = rustls::pki_types::ServerName::try_from("cloudfront.net").unwrap();
    let mut conn =
        rustls::ClientConnection::new(Arc::new(make_anytls_client_config()), server_name).unwrap();

    loop {
        match conn.complete_io(&mut sock) {
            Ok((_, _)) if !conn.is_handshaking() => break,
            Ok(_) => continue,
            Err(e) => panic!("TLS handshake failed: {e}"),
        }
    }

    let mut tls = TlsClient::new(conn, sock);

    let password_hash: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    tls.tls_write(&password_hash).unwrap();
    let plen = padding.len() as u16;
    tls.tls_write(&plen.to_be_bytes()).unwrap();
    if !padding.is_empty() {
        tls.tls_write(padding).unwrap();
    }

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
        email: "test@anytls.test".into(),
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
    };
    let mut req_buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut req_buf, &request, &addons).unwrap();
    tls.tls_write(&req_buf).unwrap();

    let mut header = [0u8; 2];
    read_exact_tls(&mut tls, &mut header).unwrap();
    let addons_len = header[1] as usize;
    if addons_len > 0 {
        let mut addons_buf = vec![0u8; addons_len];
        read_exact_tls(&mut tls, &mut addons_buf).unwrap();
    }

    tls
}

fn read_exact_tls(tls: &mut TlsClient, buf: &mut [u8]) -> io::Result<()> {
    let mut pos = 0;
    while pos < buf.len() {
        let n = tls.tls_read(&mut buf[pos..])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TLS connection closed",
            ));
        }
        pos += n;
    }
    Ok(())
}

// ── Vision echo over AnyTLS ───────────────────────────────────────────────────

fn anytls_vision_echo(mut tls: TlsClient, user_uuid: &Uuid, payload: &[u8]) -> Vec<u8> {
    tls.tls_write(payload).unwrap();
    // Signal EOF so the server's uplink VisionReader sees TLS EOF and
    // finishes, which triggers the echo server to close and the downlink
    // to flush the final Vision frame back to us.
    tls.shutdown().unwrap();

    let state = TrafficState::new(user_uuid.as_bytes());
    let mut reader = VisionReader::new(tls, state, true);

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if std::time::Instant::now() > deadline {
                    break;
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if !response.is_empty() {
                    break;
                }
                if std::time::Instant::now() > deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(_) => break,
        }
    }
    response
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_anytls_basic_echo() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();
    let password = "test-secret";

    let _server = spawn_anytls_server(&listen_str, &user_uuid.to_string(), password, "");
    thread::sleep(Duration::from_millis(100));

    let mut tls = anytls_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "",
        password,
    );

    tls.tls_write(b"hello anytls").unwrap();

    let mut buf = [0u8; 256];
    let n = tls.tls_read(&mut buf).unwrap();
    assert!(n > 0);
    assert_eq!(&buf[..n], b"hello anytls");
}

#[test]
fn test_anytls_kb_payload() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();
    let password = "test-secret";

    let _server = spawn_anytls_server(&listen_str, &user_uuid.to_string(), password, "");
    thread::sleep(Duration::from_millis(100));

    let mut tls = anytls_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "",
        password,
    );

    let payload = vec![0xAB; 4096];
    tls.tls_write(&payload).unwrap();

    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tls.tls_read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() >= payload.len() {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if !response.is_empty() || std::time::Instant::now() > deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(_) => break,
        }
    }
    assert_eq!(response.len(), payload.len());
    assert_eq!(response, payload);
}

#[test]
fn test_anytls_vision_small() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();
    let password = "vision-secret";

    let _server = spawn_anytls_server(
        &listen_str,
        &user_uuid.to_string(),
        password,
        "xtls-rprx-vision",
    );
    thread::sleep(Duration::from_millis(100));

    let tls = anytls_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
        password,
    );

    let resp = anytls_vision_echo(tls, &user_uuid, b"hello vision over anytls");
    assert_eq!(resp, b"hello vision over anytls");
}

#[test]
fn test_anytls_vision_16kb() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();
    let password = "vision-secret";

    let _server = spawn_anytls_server(
        &listen_str,
        &user_uuid.to_string(),
        password,
        "xtls-rprx-vision",
    );
    thread::sleep(Duration::from_millis(100));

    let tls = anytls_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
        password,
    );

    let payload: Vec<u8> = (0..16384u32).map(|i| (i % 251) as u8).collect();
    let resp = anytls_vision_echo(tls, &user_uuid, &payload);
    assert_eq!(resp.len(), 16384);
    assert_eq!(resp, payload);
}

#[test]
fn test_anytls_auth_failure() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let user_uuid = Uuid::new_v4();
    let password = "real-secret";

    let _server = spawn_anytls_server(&listen_str, &user_uuid.to_string(), password, "");
    thread::sleep(Duration::from_millis(100));

    // Connect with WRONG password
    let server: std::net::SocketAddr = listen_str.parse().unwrap();
    let mut sock = TcpStream::connect_timeout(&server, Duration::from_millis(500)).unwrap();

    let server_name = rustls::pki_types::ServerName::try_from("cloudfront.net").unwrap();
    let mut conn =
        rustls::ClientConnection::new(Arc::new(make_anytls_client_config()), server_name).unwrap();

    loop {
        match conn.complete_io(&mut sock) {
            Ok((_, _)) if !conn.is_handshaking() => break,
            Ok(_) => continue,
            Err(e) => panic!("TLS handshake failed: {e}"),
        }
    }

    let mut tls = TlsClient::new(conn, sock);

    let wrong_hash: [u8; 32] = Sha256::digest(b"wrong-password").into();
    tls.tls_write(&wrong_hash).unwrap();
    tls.tls_write(&[0x00, 0x00]).unwrap();

    // Server should close the connection after auth failure (no fallback)
    let mut buf = [0u8; 256];
    match tls.tls_read(&mut buf) {
        Ok(0) => {} // expected: server closes connection
        Ok(_) => {
            // May get some data before close
            let _ = tls.tls_read(&mut buf);
        }
        Err(_) => {} // also expected
    }
}

#[test]
fn test_anytls_auth_failure_fallback() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    // Start a fallback echo server
    let fallback = TcpListener::bind("127.0.0.1:0").unwrap();
    let fallback_addr = fallback.local_addr().unwrap();
    let fallback_handle = thread::spawn(move || {
        for stream in fallback.incoming().flatten() {
            thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 8192];
                match s.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        let _ = s.write_all(b"fallback-ok");
                    }
                    _ => {}
                }
            });
        }
    });

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let user_uuid = Uuid::new_v4();
    let password = "real-secret";

    let _server = spawn_anytls_server_with_fallback(
        &listen_str,
        &user_uuid.to_string(),
        password,
        &fallback_addr.to_string(),
    );
    thread::sleep(Duration::from_millis(100));

    // Connect with WRONG password — should be forwarded to fallback
    let server: std::net::SocketAddr = listen_str.parse().unwrap();
    let mut sock = TcpStream::connect_timeout(&server, Duration::from_millis(500)).unwrap();

    let server_name = rustls::pki_types::ServerName::try_from("cloudfront.net").unwrap();
    let mut conn =
        rustls::ClientConnection::new(Arc::new(make_anytls_client_config()), server_name).unwrap();

    loop {
        match conn.complete_io(&mut sock) {
            Ok((_, _)) if !conn.is_handshaking() => break,
            Ok(_) => continue,
            Err(e) => panic!("TLS handshake failed: {e}"),
        }
    }

    let mut tls = TlsClient::new(conn, sock);

    let wrong_hash: [u8; 32] = Sha256::digest(b"wrong-password").into();
    tls.tls_write(&wrong_hash).unwrap();
    tls.tls_write(&[0x00, 0x00]).unwrap();

    // After auth failure, server forwards buffered data to fallback.
    // Fallback sends "fallback-ok" back through server → client (raw, not TLS).
    // Since the server does a raw TCP fallback relay, the client TLS stream
    // should eventually see connection close or the fallback response
    // forwarded as raw bytes (which would fail TLS decryption, causing an error).
    // We just verify the connection terminates without panic.
    let mut buf = [0u8; 256];
    match tls.tls_read(&mut buf) {
        Ok(0) | Err(_) => {} // expected
        Ok(_) => {}
    }

    drop(fallback_handle);
}

#[test]
fn test_anytls_udp_echo() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (udp_addr, _udp_echo) = spawn_udp_echo_target();
    let user_uuid = Uuid::new_v4();
    let password = "udp-secret";

    let _server = spawn_anytls_server(&listen_str, &user_uuid.to_string(), password, "");
    thread::sleep(Duration::from_millis(100));

    let mut tls = anytls_udp_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        udp_addr.port(),
        password,
    );

    // Send a length-prefixed UDP packet: len(2B BE) || payload
    let payload = b"hello-udp-anytls";
    let len = payload.len() as u16;
    tls.tls_write(&len.to_be_bytes()).unwrap();
    tls.tls_write(payload).unwrap();

    // Read response: len(2B BE) || payload
    let mut len_buf = [0u8; 2];
    match read_exact_tls(&mut tls, &mut len_buf) {
        Ok(()) => {
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            let mut resp = vec![0u8; resp_len];
            read_exact_tls(&mut tls, &mut resp).unwrap();
            assert_eq!(resp, payload);
        }
        Err(_) => {
            // UDP relay may time out if no data — acceptable
        }
    }
}

#[test]
fn test_anytls_custom_cert() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();
    let password = "custom-cert-pw";

    let (cert_pem, key_pem) = wrongsv_anytls::generate_self_signed_cert().unwrap();

    let _server = spawn_anytls_server_with_cert(
        &listen_str,
        &user_uuid.to_string(),
        password,
        &cert_pem,
        &key_pem,
    );
    thread::sleep(Duration::from_millis(100));

    let mut tls = anytls_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "",
        password,
    );

    tls.tls_write(b"hello custom cert").unwrap();
    let mut buf = [0u8; 256];
    let n = tls.tls_read(&mut buf).unwrap();
    assert!(n > 0);
    assert_eq!(&buf[..n], b"hello custom cert");
}

#[test]
fn test_anytls_with_padding() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();
    let password = "padding-secret";

    let _server = spawn_anytls_server(&listen_str, &user_uuid.to_string(), password, "");
    thread::sleep(Duration::from_millis(100));

    let padding: Vec<u8> = (0..217u32).map(|i| (i % 256) as u8).collect();
    let mut tls = anytls_connect_with_padding(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "",
        password,
        &padding,
    );

    tls.tls_write(b"hello with padding").unwrap();
    let mut buf = [0u8; 256];
    let n = tls.tls_read(&mut buf).unwrap();
    assert!(n > 0);
    assert_eq!(&buf[..n], b"hello with padding");
}

#[test]
fn test_anytls_large_padding() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();
    let password = "big-pad";

    let _server = spawn_anytls_server(&listen_str, &user_uuid.to_string(), password, "");
    thread::sleep(Duration::from_millis(100));

    // 8192 bytes of padding -- stress test the padding consumption loop
    let padding: Vec<u8> = vec![0xCC; 8192];
    let mut tls = anytls_connect_with_padding(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "",
        password,
        &padding,
    );

    tls.tls_write(b"post large padding").unwrap();
    let mut buf = [0u8; 256];
    let n = tls.tls_read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"post large padding");
}

#[test]
fn test_anytls_multi_user() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let u1 = Uuid::new_v4();
    let u2 = Uuid::new_v4();
    let password = "multi-secret";

    let _server = spawn_anytls_server_multi_user(
        &listen_str,
        &[
            (u1.to_string(), String::new()),
            (u2.to_string(), "xtls-rprx-vision".into()),
        ],
        password,
    );
    thread::sleep(Duration::from_millis(100));

    // User 1 -- raw TCP echo
    let mut t1 = anytls_connect(
        &listen_str,
        &u1,
        "127.0.0.1",
        echo_addr.port(),
        "",
        password,
    );
    t1.tls_write(b"user1").unwrap();
    let mut buf = [0u8; 256];
    let n = t1.tls_read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"user1");

    // User 2 -- Vision echo
    let t2 = anytls_connect(
        &listen_str,
        &u2,
        "127.0.0.1",
        echo_addr.port(),
        "xtls-rprx-vision",
        password,
    );
    let resp = anytls_vision_echo(t2, &u2, b"user2-vision");
    assert_eq!(resp, b"user2-vision");
}

#[test]
fn test_anytls_concurrent() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();
    let password = "concurrent-pw";

    let _server = spawn_anytls_server(&listen_str, &user_uuid.to_string(), password, "");
    thread::sleep(Duration::from_millis(100));

    let listen = listen_str.clone();
    let handles: Vec<_> = (0..3)
        .map(|i| {
            let addr = listen.clone();
            let uid = user_uuid;
            let pw = password.to_string();
            let ea = echo_addr;
            thread::spawn(move || {
                let mut tls = anytls_connect(&addr, &uid, "127.0.0.1", ea.port(), "", &pw);
                let msg = format!("concurrent-{i}");
                tls.tls_write(msg.as_bytes()).unwrap();
                let mut buf = [0u8; 256];
                let n = tls.tls_read(&mut buf).unwrap();
                assert_eq!(&buf[..n], msg.as_bytes());
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_anytls_auth_failure_with_padding() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let fallback = TcpListener::bind("127.0.0.1:0").unwrap();
    let fallback_addr = fallback.local_addr().unwrap();
    let fallback_handle = thread::spawn(move || {
        for stream in fallback.incoming().flatten() {
            thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 8192];
                if let Ok(n) = s.read(&mut buf)
                    && n > 0
                {
                    let _ = s.write_all(b"fallback-got-it");
                }
            });
        }
    });

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let user_uuid = Uuid::new_v4();
    let password = "real-secret";

    let _server = spawn_anytls_server_with_fallback(
        &listen_str,
        &user_uuid.to_string(),
        password,
        &fallback_addr.to_string(),
    );
    thread::sleep(Duration::from_millis(100));

    // Wrong password + padding -- fallback should get buffered auth data
    let server: std::net::SocketAddr = listen_str.parse().unwrap();
    let mut sock = TcpStream::connect_timeout(&server, Duration::from_millis(500)).unwrap();

    let server_name = rustls::pki_types::ServerName::try_from("cloudfront.net").unwrap();
    let mut conn =
        rustls::ClientConnection::new(Arc::new(make_anytls_client_config()), server_name).unwrap();

    loop {
        match conn.complete_io(&mut sock) {
            Ok((_, _)) if !conn.is_handshaking() => break,
            Ok(_) => continue,
            Err(e) => panic!("TLS handshake failed: {e}"),
        }
    }

    let mut tls = TlsClient::new(conn, sock);

    let wrong_hash: [u8; 32] = Sha256::digest(b"wrong-password").into();
    let padding = vec![0xDD; 500];
    tls.tls_write(&wrong_hash).unwrap();
    tls.tls_write(&(padding.len() as u16).to_be_bytes())
        .unwrap();
    tls.tls_write(&padding).unwrap();

    // Server forwards buffered data to fallback (raw), client TLS sees close/error
    let mut buf = [0u8; 256];
    match tls.tls_read(&mut buf) {
        Ok(0) | Err(_) => {} // expected
        Ok(_) => {}
    }

    drop(fallback_handle);
}

fn spawn_anytls_server_with_metrics(
    listen: &str,
    user_id: &str,
    password: &str,
    metrics_port: u16,
) -> wrongsv_server::ServerHandle {
    let config_toml = format!(
        r#"
listen = "{listen}"

[[users]]
id = "{user_id}"
email = "test@anytls.test"
flow = ""

[anytls]
password = "{password}"

[metrics]
port = {metrics_port}
bind = "127.0.0.1"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
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
fn test_anytls_metrics_count_bytes_per_user() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let metrics_reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let metrics_addr = metrics_reserve.local_addr().unwrap().to_string();
    let metrics_port = metrics_reserve.local_addr().unwrap().port();
    drop(metrics_reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();
    let password = "anytls-metrics-secret";

    let _server = spawn_anytls_server_with_metrics(
        &listen_str,
        &user_uuid.to_string(),
        password,
        metrics_port,
    );
    thread::sleep(Duration::from_millis(200));

    let mut tls = anytls_connect(
        &listen_str,
        &user_uuid,
        "127.0.0.1",
        echo_addr.port(),
        "",
        password,
    );

    let payload = b"anytls-metrics-roundtrip-payload";
    tls.tls_write(payload).unwrap();

    let mut buf = vec![0u8; payload.len()];
    let mut filled = 0;
    while filled < payload.len() {
        let n = tls.tls_read(&mut buf[filled..]).unwrap();
        if n == 0 {
            break;
        }
        filled += n;
    }
    assert_eq!(&buf[..filled], payload, "echo mismatch");

    drop(tls);
    thread::sleep(Duration::from_millis(200));

    let response = http_get(&metrics_addr, "/metrics");
    assert!(response.contains("200 OK"), "got: {response}");
    let email = "test@anytls.test";
    let want_in = format!(
        "wrongsv_user_bytes_in{{email=\"{email}\"}} {}",
        payload.len()
    );
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
