//! HTTPUpgrade carrier integration tests.
//!
//! HTTPUpgrade performs an HTTP/1.1 `Upgrade: websocket` handshake and then
//! carries raw VLESS bytes directly, without WebSocket frames.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use wrongsv_protocol::RequestCommand;
use wrongsv_vless_encoding as encoding;
use wrongsv_vless_encoding::{LengthPacketReader, LengthPacketWriter};

mod common;
use common::{
    init_logging, pick_port, spawn_httpupgrade_server, spawn_tcp_echo_target, spawn_udp_echo_target,
};

const TEST_UUID: &str = "41309a00-3cbe-43a2-80e7-76c8a4fe65be";
const PACKETADDR_MAGIC_DOMAIN: &str = "sp.packet-addr.v2fly.arpa";

fn httpupgrade_connect(port: u16, path: &str) -> TcpStream {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: keep-alive, Upgrade\r\n\
         \r\n"
    );
    stream.write_all(req.as_bytes()).unwrap();

    let mut buf = vec![0u8; 4096];
    let mut total = 0;
    loop {
        let n = stream.read(&mut buf[total..]).unwrap();
        assert!(n > 0, "server closed before HTTPUpgrade response");
        total += n;
        buf.truncate(total);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        assert!(total < 4096, "HTTPUpgrade response too large");
        buf.resize(4096, 0);
    }

    let resp = String::from_utf8_lossy(&buf[..total]);
    assert!(
        resp.starts_with("HTTP/1.1 101 "),
        "expected HTTP 101, got: {resp}"
    );
    assert!(
        resp.contains("Upgrade: websocket"),
        "missing upgrade header"
    );
    stream
}

fn encode_vless_request(
    uuid: &str,
    target_addr: &str,
    target_port: u16,
    command: RequestCommand,
) -> Vec<u8> {
    use wrongsv_net_types::{Address, Port};
    use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestHeader};
    use wrongsv_uuid::Uuid;
    use wrongsv_vless_encoding::Addons;

    let uuid = Uuid::parse_string(uuid).unwrap();
    let user = MemoryUser {
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
        email: "test@httpupgrade.test".into(),
        level: 0,
    };

    let request = RequestHeader {
        version: 0,
        command,
        address: Address::parse(target_addr),
        port: Port(target_port),
        user,
    };

    let mut buf = bytes::BytesMut::new();
    encoding::encode_request_header(
        &mut buf,
        &request,
        &Addons {
            flow: String::new(),
        },
    )
    .unwrap();
    buf.to_vec()
}

fn read_vless_response_header(stream: &mut TcpStream) {
    let mut version = [0u8; 1];
    stream.read_exact(&mut version).unwrap();
    assert_eq!(version[0], 0, "response version mismatch");

    let mut addons_len = [0u8; 1];
    stream.read_exact(&mut addons_len).unwrap();
    let addons_len = addons_len[0] as usize;
    if addons_len > 0 {
        let mut addons = vec![0u8; addons_len];
        stream.read_exact(&mut addons).unwrap();
    }
}

fn read_exact_before_deadline(stream: &mut TcpStream, len: usize) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut out = vec![0u8; len];
    let mut pos = 0;
    while pos < len && Instant::now() < deadline {
        match stream.read(&mut out[pos..]) {
            Ok(0) => break,
            Ok(n) => pos += n,
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => panic!("read failed: {e}"),
        }
    }
    out.truncate(pos);
    out
}

fn encode_packetaddr_datagram(target: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(1 + 16 + 2 + payload.len());
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            packet.push(0x01);
            packet.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            packet.push(0x02);
            packet.extend_from_slice(&ip.octets());
        }
    }
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn decode_packetaddr_datagram(packet: &[u8]) -> (std::net::SocketAddr, Vec<u8>) {
    let mut pos = 1;
    let ip = match packet[0] {
        0x01 => {
            let mut raw = [0u8; 4];
            raw.copy_from_slice(&packet[pos..pos + 4]);
            pos += 4;
            std::net::IpAddr::V4(raw.into())
        }
        0x02 => {
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&packet[pos..pos + 16]);
            pos += 16;
            std::net::IpAddr::V6(raw.into())
        }
        other => panic!("unexpected packetaddr type: {other:#04x}"),
    };
    let port = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    pos += 2;
    (std::net::SocketAddr::new(ip, port), packet[pos..].to_vec())
}

#[test]
fn test_httpupgrade_tcp_echo() {
    init_logging();
    let server_port = pick_port();
    let echo_addr = spawn_tcp_echo_target();
    let _server = spawn_httpupgrade_server(server_port, TEST_UUID, "", "/up");

    let mut stream = httpupgrade_connect(server_port, "/up");
    let payload = b"hello-over-httpupgrade";
    let mut vless_req = encode_vless_request(
        TEST_UUID,
        "127.0.0.1",
        echo_addr.port(),
        RequestCommand::Tcp,
    );
    vless_req.extend_from_slice(payload);
    stream.write_all(&vless_req).unwrap();

    read_vless_response_header(&mut stream);
    let echoed = read_exact_before_deadline(&mut stream, payload.len());
    assert_eq!(echoed, payload);
}

#[test]
fn test_httpupgrade_udp_echo() {
    init_logging();
    let server_port = pick_port();
    let echo_addr = spawn_udp_echo_target();
    let _server = spawn_httpupgrade_server(server_port, TEST_UUID, "", "/up");

    let mut stream = httpupgrade_connect(server_port, "/up");
    let vless_req = encode_vless_request(
        TEST_UUID,
        "127.0.0.1",
        echo_addr.port(),
        RequestCommand::Udp,
    );
    stream.write_all(&vless_req).unwrap();
    read_vless_response_header(&mut stream);

    let payload = b"httpupgrade-udp";
    LengthPacketWriter::new(&mut stream)
        .write_packet(payload)
        .unwrap();
    let response = LengthPacketReader::new(&mut stream).read_packet().unwrap();
    assert_eq!(response.as_ref(), payload);
}

#[test]
fn test_httpupgrade_packetaddr_udp_echo() {
    init_logging();
    let server_port = pick_port();
    let echo_addr = spawn_udp_echo_target();
    let _server = spawn_httpupgrade_server(server_port, TEST_UUID, "", "/up");

    let mut stream = httpupgrade_connect(server_port, "/up");
    let vless_req =
        encode_vless_request(TEST_UUID, PACKETADDR_MAGIC_DOMAIN, 0, RequestCommand::Udp);
    stream.write_all(&vless_req).unwrap();
    read_vless_response_header(&mut stream);

    let payload = b"httpupgrade-packetaddr";
    let packet = encode_packetaddr_datagram(echo_addr, payload);
    LengthPacketWriter::new(&mut stream)
        .write_packet(&packet)
        .unwrap();

    let response = LengthPacketReader::new(&mut stream).read_packet().unwrap();
    let (response_addr, response_payload) = decode_packetaddr_datagram(&response);
    assert_eq!(response_addr, echo_addr);
    assert_eq!(response_payload, payload);
}
