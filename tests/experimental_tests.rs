use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit},
};
use md5::{Digest, Md5};
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
fn test_trusttunnel_real_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "trusttunnel");
    thread::sleep(Duration::from_millis(50));

    let mut stream = TcpStream::connect(&listen).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Derive key
    let mut key_bytes = [0u8; 16];
    let key_src = b"test-key";
    for (i, &byte) in key_src.iter().enumerate() {
        key_bytes[i % 16] ^= byte;
    }
    let cipher = Aes128Gcm::new_from_slice(&key_bytes).unwrap();
    let nonce = [0u8; 12];

    // Encrypt message and send
    let msg = b"hello trusttunnel";
    let ciphertext = cipher.encrypt((&nonce).into(), msg.as_slice()).unwrap();
    stream.write_all(ciphertext.as_slice()).unwrap();

    // Read response and decrypt
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).unwrap();
    let decrypted = cipher.decrypt((&nonce).into(), &buf[..n]).unwrap();
    assert_eq!(decrypted, msg);
}

#[test]
fn test_brook_real_proxy_echo() {
    // Start local echo target
    let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut s, _)) = target_listener.accept() {
            let mut buf = [0u8; 100];
            if let Ok(n) = s.read(&mut buf) {
                s.write_all(&buf[..n]).unwrap();
            }
        }
    });

    // Start Brook server
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "brook");
    thread::sleep(Duration::from_millis(50));

    // Connect client
    let mut stream = TcpStream::connect(&listen).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Send 16-byte MD5 hash of "test-password"
    let mut hasher = Md5::new();
    hasher.update(b"test-password");
    let pass_hash = hasher.finalize();
    stream.write_all(pass_hash.as_slice()).unwrap();

    // Send command: 0x01 (CONNECT)
    stream.write_all(&[0x01]).unwrap();

    // Send address type: 0x01 (IPv4)
    stream.write_all(&[0x01]).unwrap();

    // Send IPv4: 127.0.0.1 (4 bytes)
    stream.write_all(&[127, 0, 0, 1]).unwrap();

    // Send Port (2 bytes BE)
    stream.write_all(&target_addr.port().to_be_bytes()).unwrap();

    // Read success byte
    let mut status = [0u8; 1];
    stream.read_exact(&mut status).unwrap();
    assert_eq!(status[0], 0x00);

    // Send data and assert echoed
    let msg = b"hello real brook protocol";
    stream.write_all(msg).unwrap();
    let mut buf = [0u8; 100];
    let n = stream.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], msg);
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
fn test_sudoku_real_echo() {
    let listen = reserve_addr();
    let _server = spawn_server_for_protocol(&listen, "sudoku");
    thread::sleep(Duration::from_millis(50));

    let mut stream = TcpStream::connect(&listen).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Client obfuscates data by transposing 3x3 grid
    let mut chunk = b"123456789".to_vec();
    // Transpose
    let c1 = chunk[1];
    let c2 = chunk[2];
    let c3 = chunk[3];
    let c5 = chunk[5];
    let c6 = chunk[6];
    let c7 = chunk[7];
    chunk[1] = c3;
    chunk[3] = c1;
    chunk[2] = c6;
    chunk[6] = c2;
    chunk[5] = c7;
    chunk[7] = c5;

    stream.write_all(&chunk).unwrap();

    // Read and transpose back
    let mut response = [0u8; 9];
    stream.read_exact(&mut response).unwrap();
    let c1 = response[1];
    let c2 = response[2];
    let c3 = response[3];
    let c5 = response[5];
    let c6 = response[6];
    let c7 = response[7];
    response[1] = c3;
    response[3] = c1;
    response[2] = c6;
    response[6] = c2;
    response[5] = c7;
    response[7] = c5;

    assert_eq!(&response, b"123456789");
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
