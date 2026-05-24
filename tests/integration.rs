use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use wrongsv_net_types::Address;
use wrongsv_protocol::{MemoryAccount, MemoryUser, RequestCommand, RequestHeader, ID};
use wrongsv_uuid::Uuid;
use wrongsv_vless::{MemoryValidator, Validator};
use wrongsv_vless_encoding::{self as encoding, Addons};

fn make_test_user() -> (Uuid, MemoryUser) {
    let uuid = Uuid::new_v4();
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(uuid),
            flow: String::new(),
            encryption: String::new(),
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "test@example.com".into(),
        level: 0,
    };
    (uuid, user)
}

fn make_test_validator() -> (Arc<MemoryValidator>, Uuid) {
    let (uuid, user) = make_test_user();
    let v = Arc::new(MemoryValidator::new());
    v.add(user).unwrap();
    (v, uuid)
}

#[test]
fn test_vless_handshake_encode_decode() {
    let (validator, uuid) = make_test_validator();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(8080),
        user: validator.get(uuid.as_bytes()).unwrap(),
    };

    let addons = Addons {
        flow: String::new(),
    };

    let mut buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut buf, &request, &addons).unwrap();

    let mut cursor = std::io::Cursor::new(buf.as_ref());
    let v = validator.clone();
    let decoded = encoding::decode_request_header(&mut cursor, move |id| v.get(id)).unwrap();

    assert_eq!(decoded.header.version, request.version);
    assert_eq!(decoded.header.command, request.command);
    assert_eq!(decoded.header.address.to_string(), request.address.to_string());
    assert_eq!(decoded.header.port, request.port);
    assert_eq!(decoded.header.user.email, request.user.email);
    assert_eq!(decoded.addons.flow, "");
}

#[test]
fn test_vless_handshake_with_vision_flow() {
    let uuid = Uuid::new_v4();
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(uuid),
            flow: "xtls-rprx-vision".into(),
            encryption: String::new(),
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "vision@example.com".into(),
        level: 0,
    };
    let validator = Arc::new(MemoryValidator::new());
    validator.add(user).unwrap();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("example.com"),
        port: wrongsv_net_types::Port(443),
        user: validator.get(uuid.as_bytes()).unwrap(),
    };

    let addons = Addons {
        flow: "xtls-rprx-vision".into(),
    };

    let mut buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut buf, &request, &addons).unwrap();

    let mut cursor = std::io::Cursor::new(buf.as_ref());
    let v = validator.clone();
    let decoded = encoding::decode_request_header(&mut cursor, move |id| v.get(id)).unwrap();

    assert_eq!(decoded.addons.flow, "xtls-rprx-vision");
    assert_eq!(decoded.header.user.account.flow, "xtls-rprx-vision");
}

#[test]
fn test_response_header_roundtrip() {
    let (validator, uuid) = make_test_validator();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("10.0.0.1"),
        port: wrongsv_net_types::Port(80),
        user: validator.get(uuid.as_bytes()).unwrap(),
    };

    let addons = Addons {
        flow: String::new(),
    };

    let mut buf = bytes::BytesMut::new();
    encoding::encode_response_header(&mut buf, &request, &addons).unwrap();

    let mut cursor = std::io::Cursor::new(buf.as_ref());
    let decoded = encoding::decode_response_header(&mut cursor, &request).unwrap();

    assert_eq!(decoded.flow, "");
}

#[test]
fn test_end_to_end_echo() {
    // Start an echo server as the "target"
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    thread::spawn(move || {
        for stream in echo.incoming().flatten() {
            thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let (validator, uuid) = make_test_validator();

    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(echo_addr.port()),
        user: validator.get(uuid.as_bytes()).unwrap(),
    };

    let addons = Addons {
        flow: String::new(),
    };

    let mut req_buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut req_buf, &request, &addons).unwrap();

    let mut conn = TcpStream::connect_timeout(&echo_addr, Duration::from_secs(2)).unwrap();
    conn.write_all(&req_buf).unwrap();

    let mut resp = vec![0u8; 128];
    let n = conn.read(&mut resp).unwrap();
    assert!(n > 0, "expected echo response, got nothing");
}

#[test]
fn test_vision_padding_roundtrip_integration() {
    use wrongsv_vless::vision::{TrafficState, VisionReader, VisionWriter};

    let user_uuid = Uuid::new_v4();
    let user_sent_id = user_uuid.as_bytes();

    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";

    let mut write_buf = Vec::new();
    {
        let state = TrafficState::new(user_sent_id);
        let mut writer = VisionWriter::new(&mut write_buf, state, false, vec![900, 500, 900, 256]);
        writer.write(data).unwrap();
        writer.flush().unwrap();
    }

    assert!(!write_buf.is_empty());

    let mut read_buf = vec![0u8; data.len() + 1024];
    let state = TrafficState::new(user_sent_id);
    let mut reader = VisionReader::new(&write_buf[..], state, true);
    let n = reader.read(&mut read_buf).unwrap();

    assert_eq!(&read_buf[..n], &data[..]);
}

#[test]
fn test_invalid_user_rejected() {
    let validator = Arc::new(MemoryValidator::new());

    let uuid = Uuid::new_v4();
    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse("127.0.0.1"),
        port: wrongsv_net_types::Port(8080),
        user: MemoryUser {
            account: MemoryAccount {
                id: ID::new(uuid),
                flow: String::new(),
                encryption: String::new(),
                xor_mode: 0,
                seconds: 0,
                padding: String::new(),
                testpre: 0,
                testseed: vec![],
            },
            email: "unknown@example.com".into(),
            level: 0,
        },
    };

    let addons = Addons {
        flow: String::new(),
    };

    let mut buf = bytes::BytesMut::new();
    encoding::encode_request_header(&mut buf, &request, &addons).unwrap();

    let mut cursor = std::io::Cursor::new(buf.as_ref());
    let v = validator.clone();
    let result = encoding::decode_request_header(&mut cursor, move |id| v.get(id));

    assert!(result.is_err(), "should reject unknown user");
}
