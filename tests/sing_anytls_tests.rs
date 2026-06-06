//! Integration tests for sing-anytls session protocol compatibility.
//!
//! Tests the sing-anytls path: after TLS+auth, the client sends cmdSettings(0x04)
//! to initiate the sing-anytls session protocol instead of VLESS headers.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::ClientConfig;
use sha2::{Digest, Sha256};
use wrongsv_net_types::Address;
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
use wrongsv_uuid::Uuid;
use wrongsv_vless::{MemoryValidator, Validator};
use wrongsv_vless_encoding::{self as encoding, Addons};

// ── sing-anytls frame constants ─────────────────────────────────────────────

const CMD_SETTINGS: u8 = 4;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SYNACK: u8 = 7;
const CMD_SERVER_SETTINGS: u8 = 10;

// ── TLS helpers (copied from anytls_tests) ──────────────────────────────────

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
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn make_client_config() -> ClientConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth()
}

struct TlsClient {
    conn: rustls::ClientConnection,
    sock: TcpStream,
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
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => return Err(e),
                },
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    match self.conn.read_tls(&mut self.sock) {
                        Ok(0) => return Ok(0),
                        Ok(_) => {
                            self.conn
                                .process_new_packets()
                                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                            continue;
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
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
            self.conn.write_tls(&mut self.sock)?;
        }
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut pos = 0;
        while pos < buf.len() {
            let n = self.tls_read(&mut buf[pos..])?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TLS EOF"));
            }
            pos += n;
        }
        Ok(())
    }
}

// ── sing-anytls frame helpers ───────────────────────────────────────────────

fn write_sing_frame(tls: &mut TlsClient, cmd: u8, sid: u32, data: &[u8]) -> io::Result<()> {
    let data_len = data.len().min(65535) as u16;
    let header = [
        cmd,
        (sid >> 24) as u8,
        (sid >> 16) as u8,
        (sid >> 8) as u8,
        sid as u8,
        (data_len >> 8) as u8,
        data_len as u8,
    ];
    tls.tls_write(&header)?;
    if data_len > 0 {
        tls.tls_write(&data[..data_len as usize])?;
    }
    Ok(())
}

fn read_sing_frame(tls: &mut TlsClient) -> io::Result<(u8, u32, Vec<u8>)> {
    let mut hdr = [0u8; 7];
    tls.read_exact(&mut hdr)?;
    let cmd = hdr[0];
    let sid = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
    let data_len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
    let mut data = vec![0u8; data_len];
    if data_len > 0 {
        tls.read_exact(&mut data)?;
    }
    Ok((cmd, sid, data))
}

// ── Connect helper ──────────────────────────────────────────────────────────

fn sing_anytls_connect(server_addr: &str, password: &str) -> TlsClient {
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
        rustls::ClientConnection::new(Arc::new(make_client_config()), server_name).unwrap();

    loop {
        match conn.complete_io(&mut sock) {
            Ok((_, _)) if !conn.is_handshaking() => break,
            Ok(_) => continue,
            Err(e) => panic!("TLS handshake failed: {e}"),
        }
    }

    let mut tls = TlsClient::new(conn, sock);

    // Send AnyTLS auth frame: SHA256(password) + padding_len=0
    let password_hash: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    tls.tls_write(&password_hash).unwrap();
    tls.tls_write(&[0u8, 0u8]).unwrap(); // padding_len = 0

    tls
}

// ── Test helpers ───────────────────────────────────────────────────────────

fn spawn_echo_target() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            thread::spawn(move || {
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut buf = [0u8; 65536];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    (addr, handle)
}

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
email = "test@sing-anytls.test"
flow = "{flow}"

[anytls]
password = "{password}"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_sing_anytls_session_setup() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let user_uuid = Uuid::new_v4();
    let password = "sing-test-secret";

    let _server = spawn_anytls_server(&listen_str, &user_uuid.to_string(), password, "");
    thread::sleep(Duration::from_millis(100));

    let mut tls = sing_anytls_connect(&listen_str, password);

    // Send cmdSettings frame
    let settings_body = b"v=2\nclient=test/0.1\n";
    write_sing_frame(&mut tls, CMD_SETTINGS, 0, settings_body).unwrap();

    // Read cmdServerSettings response
    let (cmd, sid, data) = read_sing_frame(&mut tls).unwrap();
    assert_eq!(cmd, CMD_SERVER_SETTINGS);
    assert_eq!(sid, 0);
    let body = String::from_utf8_lossy(&data);
    assert!(
        body.contains("v=2"),
        "expected v=2 in server settings, got: {body}"
    );
}

#[test]
fn test_sing_anytls_stream_echo() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();
    let password = "sing-echo-secret";

    let _server = spawn_anytls_server(&listen_str, &user_uuid.to_string(), password, "");
    thread::sleep(Duration::from_millis(100));

    let mut tls = sing_anytls_connect(&listen_str, password);
    tls.sock
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Settings handshake
    write_sing_frame(&mut tls, CMD_SETTINGS, 0, b"v=2\nclient=test/0.1\n").unwrap();
    let (cmd, _, _) = read_sing_frame(&mut tls).unwrap();
    assert_eq!(cmd, CMD_SERVER_SETTINGS);

    // Open stream with SYN (sid=1)
    let sid = 1u32;
    write_sing_frame(&mut tls, CMD_SYN, sid, &[]).unwrap();

    // Build and send VLESS header as first PSH on this stream
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
        email: "test@sing-anytls.test".into(),
        level: 0,
    };
    validator.add(user).unwrap();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(echo_addr.port()),
        user: validator.get(user_uuid.as_bytes()).unwrap(),
    };
    let addons = Addons {
        flow: String::new(),
        ..Default::default()
    };
    let mut req_buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut req_buf, &request, &addons).unwrap();
    write_sing_frame(&mut tls, CMD_PSH, sid, &req_buf).unwrap();

    // Read SYNACK + VLESS response
    let (cmd, r_sid, _synack_data) = read_sing_frame(&mut tls).unwrap();
    assert_eq!(cmd, CMD_SYNACK);
    assert_eq!(r_sid, sid);

    // Read VLESS response header (first PSH after SYNACK)
    let (cmd, r_sid, resp) = read_sing_frame(&mut tls).unwrap();
    assert_eq!(cmd, CMD_PSH);
    assert_eq!(r_sid, sid);
    // VLESS response starts with version=0, addons_len
    assert!(resp.len() >= 2);

    // Send echo payload
    write_sing_frame(&mut tls, CMD_PSH, sid, b"hello sing-anytls").unwrap();

    // Send FIN (half-close our write side to signal EOF)
    write_sing_frame(&mut tls, CMD_FIN, sid, &[]).unwrap();

    // Read echo response
    let mut response = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match read_sing_frame(&mut tls) {
            Ok((CMD_PSH, r_sid, data)) if r_sid == sid => {
                response.extend_from_slice(&data);
                if !data.is_empty() {
                    // Got data, keep reading
                }
            }
            Ok((CMD_FIN, r_sid, _)) if r_sid == sid => {
                break;
            }
            Ok((_, _, _)) => {}
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if std::time::Instant::now() > deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }

    assert!(
        response
            .windows(b"hello sing-anytls".len())
            .any(|w| w == b"hello sing-anytls"),
        "expected echo response to contain 'hello sing-anytls', got {} bytes",
        response.len()
    );
}

#[test]
fn test_sing_anytls_socks5_echo() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen_str = reserve.local_addr().unwrap().to_string();
    drop(reserve);

    let (echo_addr, _echo) = spawn_echo_target();
    let user_uuid = Uuid::new_v4();
    let password = "sing-socks5-secret";

    let _server = spawn_anytls_server(&listen_str, &user_uuid.to_string(), password, "");
    thread::sleep(Duration::from_millis(100));

    let mut tls = sing_anytls_connect(&listen_str, password);
    tls.sock
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Settings handshake
    write_sing_frame(&mut tls, CMD_SETTINGS, 0, b"v=2\nclient=test/0.1\n").unwrap();
    let (cmd, _, _) = read_sing_frame(&mut tls).unwrap();
    assert_eq!(cmd, CMD_SERVER_SETTINGS);

    // Open stream with SYN
    let sid = 1u32;
    write_sing_frame(&mut tls, CMD_SYN, sid, &[]).unwrap();

    // Send SOCKS5 address as first PSH (domain type=3, "127.0.0.1":echo_port)
    // Use IPv4 (type=1) for the echo target
    let echo_port = echo_addr.port();
    let socks_addr = vec![
        0x01u8,
        127,
        0,
        0,
        1,
        (echo_port >> 8) as u8,
        echo_port as u8,
    ];
    write_sing_frame(&mut tls, CMD_PSH, sid, &socks_addr).unwrap();

    // Read SYNACK
    let (cmd, r_sid, _) = read_sing_frame(&mut tls).unwrap();
    assert_eq!(cmd, CMD_SYNACK);
    assert_eq!(r_sid, sid);

    // Send echo payload
    write_sing_frame(&mut tls, CMD_PSH, sid, b"hello socks5").unwrap();

    // Send FIN
    write_sing_frame(&mut tls, CMD_FIN, sid, &[]).unwrap();

    // Read echo response
    let mut response = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match read_sing_frame(&mut tls) {
            Ok((CMD_PSH, r_sid, data)) if r_sid == sid => {
                response.extend_from_slice(&data);
            }
            Ok((CMD_FIN, r_sid, _)) if r_sid == sid => {
                break;
            }
            Ok((_, _, _)) => {}
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if std::time::Instant::now() > deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }

    assert!(
        response
            .windows(b"hello socks5".len())
            .any(|w| w == b"hello socks5"),
        "expected echo response to contain 'hello socks5', got {} bytes",
        response.len()
    );
}
