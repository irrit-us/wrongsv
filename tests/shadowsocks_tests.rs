use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

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
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
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
