use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn reserve_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn spawn_server_for_protocol(listen: &str, protocol: &str) -> wrongsv_server::ServerHandle {
    let config_toml = format!(
        r#"
listen = "{listen}"

[{protocol}]
password = "test-password"
script_path = "test.lua"
key = "test-key"
bridge_line = "test-bridge"
private_key = "test-private-key"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
}

fn verify_echo(listen: &str) {
    let mut stream = TcpStream::connect(listen).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let msg = b"hello experimental protocol";
    stream.write_all(msg).unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], msg);
}

#[test]
fn test_lua_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "lua");
    thread::sleep(Duration::from_millis(50));
    verify_echo(&listen);
}

#[test]
fn test_masque_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "masque");
    thread::sleep(Duration::from_millis(50));
    verify_echo(&listen);
}

#[test]
fn test_trusttunnel_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "trusttunnel");
    thread::sleep(Duration::from_millis(50));
    verify_echo(&listen);
}

#[test]
fn test_brook_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "brook");
    thread::sleep(Duration::from_millis(50));
    verify_echo(&listen);
}

#[test]
fn test_vlite_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "vlite");
    thread::sleep(Duration::from_millis(50));
    verify_echo(&listen);
}

#[test]
fn test_tor_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "tor");
    thread::sleep(Duration::from_millis(50));
    verify_echo(&listen);
}

#[test]
fn test_ssh_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "ssh");
    thread::sleep(Duration::from_millis(50));
    verify_echo(&listen);
}

#[test]
fn test_juicity_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "juicity");
    thread::sleep(Duration::from_millis(50));
    verify_echo(&listen);
}

#[test]
fn test_mieru_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "mieru");
    thread::sleep(Duration::from_millis(50));
    verify_echo(&listen);
}

#[test]
fn test_sudoku_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "sudoku");
    thread::sleep(Duration::from_millis(50));
    verify_echo(&listen);
}

#[test]
fn test_vless_encryption_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "vless_encryption");
    thread::sleep(Duration::from_millis(50));
    verify_echo(&listen);
}

#[test]
fn test_shadowquic_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "shadowquic");
    thread::sleep(Duration::from_millis(50));
    verify_echo(&listen);
}

#[test]
fn test_anytls_reality_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "anytls_reality");
    thread::sleep(Duration::from_millis(50));
    verify_echo(&listen);
}
