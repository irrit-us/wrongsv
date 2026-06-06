use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha224};

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

struct TlsClient {
    conn: rustls::ClientConnection,
    sock: TcpStream,
}

impl TlsClient {
    fn connect(addr: &str) -> Self {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
        let sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut client = Self { conn, sock };
        while client.conn.is_handshaking() {
            client.conn.complete_io(&mut client.sock).unwrap();
        }
        client
    }

    fn shutdown(&mut self) {
        self.conn.send_close_notify();
        self.flush().unwrap();
    }
}

impl Read for TlsClient {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.conn.reader().read(buf) {
                Ok(0) => {
                    if !self.read_tls_record()? {
                        return Ok(0);
                    }
                }
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if !self.read_tls_record()? {
                        return Ok(0);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl TlsClient {
    fn read_tls_record(&mut self) -> io::Result<bool> {
        match self.conn.read_tls(&mut self.sock) {
            Ok(0) => Ok(false),
            Ok(_) => {
                self.conn
                    .process_new_packets()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(true)
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }
}

impl Write for TlsClient {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.conn.writer().write_all(buf)?;
        self.flush()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            let n = self.conn.write_tls(&mut self.sock)?;
            if n == 0 {
                break;
            }
        }
        Ok(())
    }
}

fn reserve_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn spawn_echo_target() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut buf = [0u8; 4096];
            if let Ok(n) = stream.read(&mut buf)
                && n > 0
            {
                let _ = stream.write_all(&buf[..n]);
            }
        }
    });
    addr
}

fn spawn_fallback_target() -> (std::net::SocketAddr, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut data = Vec::new();
            let mut byte = [0u8; 1];
            while !data.ends_with(b"\r\n\r\n") {
                if stream.read_exact(&mut byte).is_err() {
                    return;
                }
                data.push(byte[0]);
                if data.len() > 8192 {
                    return;
                }
            }
            let _ = tx.send(String::from_utf8(data).unwrap());
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nfallback");
        }
    });
    (addr, rx)
}

fn spawn_trojan_server(listen: &str, body: &str) -> wrongsv_server::ServerHandle {
    let config_toml = format!(
        r#"
listen = "{listen}"

[trojan]
{body}
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
}

fn sha224_hex(password: &str) -> String {
    Sha224::digest(password.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn write_trojan_connect(
    client: &mut TlsClient,
    password: &str,
    host: &str,
    port: u16,
    payload: &[u8],
) {
    let mut request = sha224_hex(password).into_bytes();
    request.extend_from_slice(b"\r\n");
    request.push(0x01);
    request.push(0x03);
    request.push(host.len() as u8);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(payload);
    client.write_all(&request).unwrap();
}

#[test]
fn test_trojan_tcp_echo() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let listen = reserve_addr();
    let echo_addr = spawn_echo_target();
    let _server = spawn_trojan_server(&listen, r#"password = "secret""#);
    thread::sleep(Duration::from_millis(100));

    let mut client = TlsClient::connect(&listen);
    write_trojan_connect(
        &mut client,
        "secret",
        "localhost",
        echo_addr.port(),
        b"hello trojan",
    );

    let mut response = [0u8; 12];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"hello trojan");
    client.shutdown();
}

#[test]
fn test_trojan_user_password_echo() {
    let listen = reserve_addr();
    let echo_addr = spawn_echo_target();
    let _server = spawn_trojan_server(
        &listen,
        r#"
[[trojan.users]]
password = "secret-a"
email = "a@example.com"

[[trojan.users]]
password = "secret-b"
"#,
    );
    thread::sleep(Duration::from_millis(100));

    let mut client = TlsClient::connect(&listen);
    write_trojan_connect(
        &mut client,
        "secret-b",
        "localhost",
        echo_addr.port(),
        b"multi user",
    );

    let mut response = [0u8; 10];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"multi user");
    client.shutdown();
}

#[test]
fn test_trojan_invalid_probe_plaintext_fallback() {
    let listen = reserve_addr();
    let (fallback_addr, captured) = spawn_fallback_target();
    let _server = spawn_trojan_server(
        &listen,
        &format!(
            r#"
password = "secret"
dest = "{fallback_addr}"
"#
        ),
    );
    thread::sleep(Duration::from_millis(100));

    let mut client = TlsClient::connect(&listen);
    client
        .write_all(b"GET /probe HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .unwrap();

    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with("fallback"));

    let forwarded = captured.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        forwarded,
        "GET /probe HTTP/1.1\r\nHost: example.test\r\n\r\n"
    );
}

#[test]
fn test_trojan_rejects_bad_password_without_fallback() {
    let listen = reserve_addr();
    let echo_addr = spawn_echo_target();
    let _server = spawn_trojan_server(&listen, r#"password = "secret""#);
    thread::sleep(Duration::from_millis(100));

    let mut client = TlsClient::connect(&listen);
    write_trojan_connect(
        &mut client,
        "wrong",
        "localhost",
        echo_addr.port(),
        b"bad auth",
    );
    client.flush().unwrap();
    let _ = client.sock.shutdown(Shutdown::Write);

    let mut response = [0u8; 1];
    let result = client.read(&mut response);
    assert!(result.is_err() || result.unwrap() == 0);
}
