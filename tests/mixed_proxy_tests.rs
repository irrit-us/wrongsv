use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use base64::Engine;

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

fn spawn_mixed_server(
    listen: &str,
    credentials: Option<(&str, &str)>,
) -> wrongsv_server::ServerHandle {
    let auth = credentials
        .map(|(username, password)| {
            format!("username = \"{username}\"\npassword = \"{password}\"\n")
        })
        .unwrap_or_default();
    let config_toml = format!(
        r#"
listen = "{listen}"

[mixed]
{auth}
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
}

fn write_socks5_domain_connect(stream: &mut TcpStream, host: &str, port: u16) {
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).unwrap();
}

fn read_socks5_reply(stream: &mut TcpStream) -> u8 {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).unwrap();
    match header[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).unwrap();
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).unwrap();
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).unwrap();
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).unwrap();
        }
        other => panic!("unexpected SOCKS address type {other}"),
    }
    header[1]
}

fn read_http_head(stream: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut byte = [0u8; 1];
    while !data.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        data.push(byte[0]);
        assert!(data.len() < 8192);
    }
    String::from_utf8(data).unwrap()
}

#[test]
fn test_mixed_socks5_no_auth_echo() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let listen = reserve_addr();
    let echo_addr = spawn_echo_target();
    let _server = spawn_mixed_server(&listen, None);
    thread::sleep(Duration::from_millis(100));

    let mut stream = TcpStream::connect(&listen).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).unwrap();
    assert_eq!(method, [0x05, 0x00]);

    write_socks5_domain_connect(&mut stream, "localhost", echo_addr.port());
    assert_eq!(read_socks5_reply(&mut stream), 0x00);

    stream.write_all(b"hello socks").unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = [0u8; 11];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"hello socks");
}

#[test]
fn test_mixed_socks5_userpass_auth_echo() {
    let listen = reserve_addr();
    let echo_addr = spawn_echo_target();
    let _server = spawn_mixed_server(&listen, Some(("admin", "secret")));
    thread::sleep(Duration::from_millis(100));

    let mut stream = TcpStream::connect(&listen).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&[0x05, 0x01, 0x02]).unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).unwrap();
    assert_eq!(method, [0x05, 0x02]);

    stream
        .write_all(&[
            0x01, 0x05, b'a', b'd', b'm', b'i', b'n', 0x06, b's', b'e', b'c', b'r', b'e', b't',
        ])
        .unwrap();
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).unwrap();
    assert_eq!(auth, [0x01, 0x00]);

    write_socks5_domain_connect(&mut stream, "localhost", echo_addr.port());
    assert_eq!(read_socks5_reply(&mut stream), 0x00);

    stream.write_all(b"auth socks").unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = [0u8; 10];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"auth socks");
}

#[test]
fn test_mixed_http_connect_echo_with_initial_data() {
    let listen = reserve_addr();
    let echo_addr = spawn_echo_target();
    let _server = spawn_mixed_server(&listen, None);
    thread::sleep(Duration::from_millis(100));

    let mut stream = TcpStream::connect(&listen).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\nhello http",
        echo_addr.port(),
        echo_addr.port()
    )
    .unwrap();
    stream.shutdown(Shutdown::Write).unwrap();

    let response_head = read_http_head(&mut stream);
    assert!(response_head.starts_with("HTTP/1.1 200 Connection Established"));

    let mut response = [0u8; 10];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"hello http");
}

#[test]
fn test_mixed_http_basic_auth_echo() {
    let listen = reserve_addr();
    let echo_addr = spawn_echo_target();
    let _server = spawn_mixed_server(&listen, Some(("admin", "secret")));
    thread::sleep(Duration::from_millis(100));

    let mut stream = TcpStream::connect(&listen).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let token = base64::engine::general_purpose::STANDARD.encode("admin:secret");
    write!(
        stream,
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nProxy-Authorization: Basic {}\r\n\r\nhello auth",
        echo_addr.port(),
        echo_addr.port(),
        token
    )
    .unwrap();
    stream.shutdown(Shutdown::Write).unwrap();

    let response_head = read_http_head(&mut stream);
    assert!(response_head.starts_with("HTTP/1.1 200 Connection Established"));

    let mut response = [0u8; 10];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"hello auth");
}

#[test]
fn test_mixed_http_basic_auth_required() {
    let listen = reserve_addr();
    let echo_addr = spawn_echo_target();
    let _server = spawn_mixed_server(&listen, Some(("admin", "secret")));
    thread::sleep(Duration::from_millis(100));

    let mut stream = TcpStream::connect(&listen).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        echo_addr.port(),
        echo_addr.port()
    )
    .unwrap();

    let response_head = read_http_head(&mut stream);
    assert!(response_head.starts_with("HTTP/1.1 407 Proxy Authentication Required"));
    assert!(response_head.contains("Proxy-Authenticate: Basic realm=\"wrongsv\""));
}
