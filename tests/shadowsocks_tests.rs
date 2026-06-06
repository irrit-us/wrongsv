use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use base64::Engine;
use wrongsv_net_types::{Address, Port};

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

fn spawn_udp_echo_target() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    thread::spawn(move || {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0u8; 4096];
        if let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&buf[..n], peer);
        }
    });
    addr
}

fn spawn_shadowsocks_server(
    listen: &str,
    method: &str,
    password: &str,
) -> wrongsv_server::ServerHandle {
    let config_toml = format!(
        r#"
listen = "{listen}"

[shadowsocks]
method = "{method}"
password = "{password}"
udp = true
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
}

fn aead_2022_password(key_len: usize) -> String {
    base64::engine::general_purpose::STANDARD.encode(vec![0x37; key_len])
}

#[test]
fn test_shadowsocks_aead_tcp_echo() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let listen = reserve_addr();
    let echo_addr = spawn_echo_target();
    let method = "chacha20-ietf-poly1305";
    let password = "shadowsocks-test-password";
    let _server = spawn_shadowsocks_server(&listen, method, password);
    thread::sleep(Duration::from_millis(100));

    let ss_config = wrongsv_shadowsocks::ServerConfig::new(method, password).unwrap();
    let stream = TcpStream::connect(&listen).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut request = Vec::new();
    wrongsv_shadowsocks::write_request_header(
        &mut request,
        &Address::Domain("localhost".into()),
        Port(echo_addr.port()),
    );
    request.extend_from_slice(b"hello shadowsocks");

    {
        let writer_stream = stream.try_clone().unwrap();
        let mut writer =
            wrongsv_shadowsocks::ShadowsocksWriter::new(writer_stream, &ss_config).unwrap();
        writer.write_chunk(&request).unwrap();
        writer.get_mut().shutdown(Shutdown::Write).unwrap();
    }

    let mut reader = wrongsv_shadowsocks::ShadowsocksReader::new(stream, &ss_config).unwrap();
    let response = reader.read_chunk().unwrap();

    assert_eq!(response, b"hello shadowsocks");
}

#[test]
fn test_shadowsocks_aead_udp_echo() {
    let listen = reserve_addr();
    let echo_addr = spawn_udp_echo_target();
    let method = "chacha20-ietf-poly1305";
    let password = "shadowsocks-test-password";
    let _server = spawn_shadowsocks_server(&listen, method, password);
    thread::sleep(Duration::from_millis(200));

    let ss_config = wrongsv_shadowsocks::ServerConfig::new(method, password).unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut plaintext = Vec::new();
    wrongsv_shadowsocks::write_request_header(
        &mut plaintext,
        &Address::IPv4([127, 0, 0, 1]),
        Port(echo_addr.port()),
    );
    plaintext.extend_from_slice(b"hello udp");
    let packet = wrongsv_shadowsocks::encrypt_udp_packet(&plaintext, &ss_config).unwrap();
    client.send_to(&packet, &listen).unwrap();

    let mut response_packet = [0u8; 65535];
    let (n, _) = client.recv_from(&mut response_packet).unwrap();
    let response_plaintext =
        wrongsv_shadowsocks::decrypt_udp_packet(&response_packet[..n], &ss_config).unwrap();
    let (_address, port, consumed) =
        wrongsv_shadowsocks::parse_request_header(&response_plaintext).unwrap();

    assert_eq!(port, Port(echo_addr.port()));
    assert_eq!(&response_plaintext[consumed..], b"hello udp");
}

#[test]
fn test_shadowsocks_aead_2022_tcp_echo() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    for (method, key_len) in [
        ("2022-blake3-aes-128-gcm", 16usize),
        ("2022-blake3-aes-256-gcm", 32usize),
    ] {
        let listen = reserve_addr();
        let echo_addr = spawn_echo_target();
        let password = aead_2022_password(key_len);
        let _server = spawn_shadowsocks_server(&listen, method, &password);
        thread::sleep(Duration::from_millis(100));

        let ss_config = wrongsv_shadowsocks::ServerConfig::new(method, password).unwrap();
        let stream = TcpStream::connect(&listen).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let request_salt = {
            let writer_stream = stream.try_clone().unwrap();
            let (mut writer, request_salt) = wrongsv_shadowsocks::ShadowsocksWriter::new_request(
                writer_stream,
                &ss_config,
                &Address::Domain("localhost".into()),
                Port(echo_addr.port()),
                b"hello shadowsocks 2022",
            )
            .unwrap();
            writer.get_mut().shutdown(Shutdown::Write).unwrap();
            request_salt
        };

        let mut reader = wrongsv_shadowsocks::ShadowsocksReader::new_response(
            stream,
            &ss_config,
            Some(&request_salt),
        )
        .unwrap();
        let response = reader.read_chunk().unwrap();

        assert_eq!(response, b"hello shadowsocks 2022");
    }
}
