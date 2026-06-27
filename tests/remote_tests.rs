use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use wrongsv_net_types::{Address, Port};

#[test]
fn test_remote_shadowsocks_end_to_end() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let server_addr = "49.51.169.133:10443";
    let method = "chacha20-ietf-poly1305";
    let password = "shadowsocks-password";

    let ss_config = wrongsv_shadowsocks::ServerConfig::new(method, password).unwrap();

    // Connect to the remote wrongsv server running on tencentde
    let stream =
        TcpStream::connect(server_addr).expect("Failed to connect to remote wrongsv server");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let mut request = Vec::new();
    // Ask remote server to proxy to httpbin.org:80
    wrongsv_shadowsocks::write_request_header(
        &mut request,
        &Address::Domain("httpbin.org".into()),
        Port(80),
    );
    // Send a standard HTTP GET request
    request
        .extend_from_slice(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n");

    let writer_stream = stream.try_clone().unwrap();
    let mut writer =
        wrongsv_shadowsocks::ShadowsocksWriter::new(writer_stream, &ss_config).unwrap();
    writer.write_chunk(&request).unwrap();
    writer.get_mut().shutdown(Shutdown::Write).unwrap();

    let mut reader = wrongsv_shadowsocks::ShadowsocksReader::new(stream, &ss_config).unwrap();
    let mut response = Vec::new();
    while let Ok(chunk) = reader.read_chunk() {
        if chunk.is_empty() {
            break;
        }
        response.extend_from_slice(&chunk);
    }

    let resp_text = String::from_utf8_lossy(&response);
    println!("Response from httpbin.org:\n{}", resp_text);
    assert!(resp_text.contains("HTTP/"));
}
