use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use wrongsv_net_types::Address;
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
use wrongsv_uuid::Uuid;
use wrongsv_vless::{MemoryValidator, Validator};
use wrongsv_vless_encoding::{self as encoding, Addons};

const TEST_UUID: &str = "12345678-1234-1234-1234-123456789abc";

fn reserve_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn spawn_raw_vless_server(listen: &str) -> wrongsv_server::ServerHandle {
    let config_toml = format!(
        r#"
listen = "{listen}"

[[users]]
id = "{TEST_UUID}"
email = "fragment@test"
"#
    );
    let config: wrongsv_server::Config = toml::from_str(&config_toml).unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
}

fn spawn_echo_target() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    addr
}

fn encode_vless_tcp_header(target_port: u16) -> Vec<u8> {
    let uuid = Uuid::parse_string(TEST_UUID).unwrap();
    let validator = MemoryValidator::new();
    validator
        .add(MemoryUser {
            account: MemoryAccount {
                id: ID::new(uuid),
                flow: String::new(),
                encryption: String::new(),
                udp: true,
                xor_mode: 0,
                seconds: 0,
                padding: String::new(),
                testpre: 0,
                testseed: vec![],
            },
            email: "fragment@test".into(),
            level: 0,
        })
        .unwrap();
    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(target_port),
        user: validator.get(uuid.as_bytes()).unwrap(),
    };
    let mut out = bytes::BytesMut::new();
    encoding::encode_request_header(&mut out, &request, &Addons::default()).unwrap();
    out.to_vec()
}

#[test]
fn raw_vless_accepts_fragmented_request_header() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let listen = reserve_addr();
    let target = spawn_echo_target();
    let _server = spawn_raw_vless_server(&listen);
    thread::sleep(Duration::from_millis(100));

    let mut stream = TcpStream::connect(&listen).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let header = encode_vless_tcp_header(target.port());
    for byte in header {
        stream.write_all(&[byte]).unwrap();
        stream.flush().unwrap();
    }

    let mut response_header = [0u8; 2];
    stream.read_exact(&mut response_header).unwrap();
    assert_eq!(response_header, [0, 0]);

    stream.write_all(b"fragment-ok").unwrap();
    let mut echoed = [0u8; 11];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"fragment-ok");
}
