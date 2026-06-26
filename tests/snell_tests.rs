use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use wrongsv_snell::{COMMAND_TUNNEL, SnellConfig, SnellReader, SnellVersion, SnellWriter};

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

fn spawn_snell_server(listen: &str, psk: &str) -> wrongsv_server::ServerHandle {
    let config_toml = format!(
        r#"
listen = "{listen}"

[snell]
psk = "{psk}"
version = 1
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
}

#[test]
fn test_snell_v1_tcp_echo() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let listen = reserve_addr();
    let echo_addr = spawn_echo_target();
    let psk = "snell-test-password";
    let _server = spawn_snell_server(&listen, psk);
    thread::sleep(Duration::from_millis(100));

    let config = SnellConfig::new(psk.as_bytes().to_vec(), 1).unwrap();
    let stream = TcpStream::connect(&listen).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let writer_stream = stream.try_clone().unwrap();
    let mut writer = SnellWriter::new(writer_stream, &config).unwrap();
    writer
        .write_chunk(
            &wrongsv_snell::encode_connect_header("localhost", echo_addr.port(), SnellVersion::V1)
                .unwrap(),
        )
        .unwrap();

    let mut reader = SnellReader::new(stream, &config).unwrap();
    let response = reader.read_chunk().unwrap();
    assert_eq!(response, [COMMAND_TUNNEL]);

    writer.write_chunk(b"hello snell").unwrap();
    writer.get_mut().shutdown(Shutdown::Write).unwrap();
    assert_eq!(reader.read_chunk().unwrap(), b"hello snell");
}
