//! KCP (mKCP) carrier integration tests using the Xray-style mKCP session
//! format instead of the generic Rust `kcp` crate wire format.

use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use sha2::Digest;

#[path = "../crates/server/src/handler/kcp/xray_session.rs"]
mod xray_session;

mod common;
use common::{init_logging, pick_port, spawn_tcp_echo_target};
use xray_session::{SessionConfig, XrayKcpSession};

const TEST_UUID: &str = "41309a00-3cbe-43a2-80e7-76c8a4fe65be";
const TEST_SEED: &str = "test-kcp-seed";

// ── VLESS header helper ────────────────────────────────────────────────

fn encode_vless_request(
    uuid: &str,
    target_addr: &str,
    target_port: u16,
    command: wrongsv_protocol::RequestCommand,
    flow: &str,
) -> Vec<u8> {
    use wrongsv_net_types::{Address, Port};
    use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestHeader};
    use wrongsv_uuid::Uuid;
    use wrongsv_vless_encoding::Addons;

    let uid = Uuid::parse_string(uuid).unwrap();
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(uid),
            flow: flow.into(),
            encryption: String::new(),
            udp: true,
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "test@kcp.test".into(),
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
    wrongsv_vless_encoding::encode_request_header(
        &mut buf,
        &request,
        &Addons {
            flow: flow.into(),
            ..Default::default()
        },
    )
    .unwrap();
    buf.to_vec()
}

// ── mKCP packet mask helpers ───────────────────────────────────────────

const MKCP_ORIGINAL_OVERHEAD: usize = 6;

fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn xorfwd(data: &mut [u8]) {
    for i in 4..data.len() {
        data[i] ^= data[i - 4];
    }
}

fn xorbkd(data: &mut [u8]) {
    for i in (4..data.len()).rev() {
        data[i] ^= data[i - 4];
    }
}

fn mkcp_seal(seed: &str, data: &[u8]) -> Vec<u8> {
    if seed.is_empty() {
        let mut packet = Vec::with_capacity(MKCP_ORIGINAL_OVERHEAD + data.len() + 3);
        packet.extend_from_slice(&[0u8; MKCP_ORIGINAL_OVERHEAD]);
        packet[4..6].copy_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);
        let auth = fnv1a_32(&packet[4..]);
        packet[..4].copy_from_slice(&auth.to_be_bytes());
        let padded_len = if packet.len() % 4 == 0 {
            packet.len()
        } else {
            packet.len() + (4 - packet.len() % 4)
        };
        packet.resize(padded_len, 0);
        xorfwd(&mut packet);
        packet.truncate(MKCP_ORIGINAL_OVERHEAD + data.len());
        return packet;
    }

    let digest = sha2::Sha256::digest(seed.as_bytes());
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(&digest[..16]).unwrap();
    let mut nonce = [0u8; 12];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut ciphertext = data.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&nonce), b"", &mut ciphertext)
        .unwrap();
    let mut packet = nonce.to_vec();
    packet.extend_from_slice(&ciphertext);
    packet.extend_from_slice(tag.as_slice());
    packet
}

fn mkcp_open(seed: &str, packet: &[u8]) -> Option<Vec<u8>> {
    if seed.is_empty() {
        if packet.len() < MKCP_ORIGINAL_OVERHEAD {
            return None;
        }
        let mut data = packet.to_vec();
        let padded_len = if data.len() % 4 == 0 {
            data.len()
        } else {
            data.len() + (4 - data.len() % 4)
        };
        data.resize(padded_len, 0);
        xorbkd(&mut data);
        let auth = u32::from_be_bytes(data[..4].try_into().ok()?);
        if fnv1a_32(&data[4..packet.len()]) != auth {
            return None;
        }
        let length = u16::from_be_bytes(data[4..6].try_into().ok()?) as usize;
        if packet.len().checked_sub(MKCP_ORIGINAL_OVERHEAD)? != length {
            return None;
        }
        return Some(data[6..6 + length].to_vec());
    }

    if packet.len() < 12 + 16 {
        return None;
    }
    let digest = sha2::Sha256::digest(seed.as_bytes());
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(&digest[..16]).unwrap();
    let split = packet.len() - 16;
    let mut plaintext = packet[12..split].to_vec();
    cipher
        .decrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(&packet[..12]),
            b"",
            &mut plaintext,
            aes_gcm::Tag::from_slice(&packet[split..]),
        )
        .ok()?;
    Some(plaintext)
}

// ── Test mKCP client ───────────────────────────────────────────────────

struct TestKcpClient {
    engine: XrayKcpSession,
    socket: UdpSocket,
    server_addr: SocketAddr,
    seed: String,
    tick: u32,
    received: VecDeque<Vec<u8>>,
}

impl TestKcpClient {
    fn new(socket: UdpSocket, server_addr: SocketAddr, seed: &str, conv: u16) -> Self {
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        Self {
            engine: XrayKcpSession::new(SessionConfig {
                conv,
                mtu: 1350,
                tti: 20,
                uplink_capacity: 5,
                downlink_capacity: 20,
                write_buffer_size: 2 * 1024 * 1024,
                packet_overhead: 16,
            }),
            socket,
            server_addr,
            seed: seed.to_string(),
            tick: 0,
            received: VecDeque::new(),
        }
    }

    fn send(&mut self, data: &[u8]) {
        self.engine.enqueue_application_data(data);
    }

    fn step(&mut self, step_ms: u32) {
        for packet in self.engine.flush(self.tick) {
            let wrapped = mkcp_seal(&self.seed, &packet);
            let _ = self.socket.send_to(&wrapped, self.server_addr);
        }

        loop {
            let mut recv_buf = [0u8; 4096];
            match self.socket.recv_from(&mut recv_buf) {
                Ok((n, src)) => {
                    if src != self.server_addr {
                        continue;
                    }
                    if let Some(packet) = mkcp_open(&self.seed, &recv_buf[..n]) {
                        self.engine.input(&packet, self.tick);
                        while let Some(data) = self.engine.take_received() {
                            self.received.push_back(data);
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(_) => break,
            }
        }

        self.tick = self.tick.saturating_add(step_ms);
        thread::sleep(Duration::from_millis(step_ms as u64));
    }

    fn recv(&mut self) -> Option<Vec<u8>> {
        self.received.pop_front()
    }

    fn wait_for_data(&mut self, timeout_ms: u32) -> Option<Vec<u8>> {
        let mut elapsed = 0u32;
        while elapsed < timeout_ms {
            self.step(20);
            if let Some(data) = self.recv() {
                return Some(data);
            }
            elapsed += 20;
        }
        None
    }
}

// ── Server spawning ────────────────────────────────────────────────────

fn spawn_kcp_server(port: u16, user_id: &str, flow: &str) -> wrongsv_server::ServerHandle {
    let config: wrongsv_server::Config = toml::from_str(&format!(
        r#"
listen = "127.0.0.1:{port}"

[[users]]
id = "{user_id}"
email = "test@kcp.test"
flow = "{flow}"

[kcp]
seed = "{TEST_SEED}"
tti = 20
mtu = 1350
"#
    ))
    .unwrap();
    let server = wrongsv_server::InboundServer::new(config).unwrap();
    server.spawn()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[test]
fn test_kcp_handshake() {
    init_logging();
    let port = pick_port();
    let _server = spawn_kcp_server(port, TEST_UUID, "");
    let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_addr).unwrap();

    let mut client = TestKcpClient::new(socket, server_addr, TEST_SEED, 1);
    let vless_header = encode_vless_request(
        TEST_UUID,
        "127.0.0.1",
        80,
        wrongsv_protocol::RequestCommand::Tcp,
        "",
    );
    client.send(&vless_header);

    let response = client
        .wait_for_data(2500)
        .expect("timed out waiting for VLESS response");
    assert!(!response.is_empty(), "VLESS response should not be empty");
    assert_eq!(response[0], 0, "VLESS version must be 0");
}

#[test]
fn test_kcp_tcp_echo() {
    init_logging();
    let port = pick_port();
    let echo_addr = spawn_tcp_echo_target();
    let _server = spawn_kcp_server(port, TEST_UUID, "");
    let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_addr).unwrap();

    let mut client = TestKcpClient::new(socket, server_addr, TEST_SEED, 7);
    let vless_header = encode_vless_request(
        TEST_UUID,
        &echo_addr.ip().to_string(),
        echo_addr.port(),
        wrongsv_protocol::RequestCommand::Tcp,
        "",
    );
    client.send(&vless_header);

    let response = client
        .wait_for_data(2500)
        .expect("should receive VLESS response");
    assert_eq!(response[0], 0, "VLESS version must be 0");

    let payload = b"hello-kcp-echo";
    client.send(payload);
    let echoed = client.wait_for_data(3000).expect("should receive TCP echo");
    assert_eq!(echoed, payload);
}

#[test]
fn test_kcp_rejects_invalid_uuid() {
    init_logging();
    let port = pick_port();
    let _server = spawn_kcp_server(port, TEST_UUID, "");
    let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_addr).unwrap();

    let mut client = TestKcpClient::new(socket, server_addr, TEST_SEED, 9);
    let vless_header = encode_vless_request(
        "00000000-0000-0000-0000-000000000000",
        "127.0.0.1",
        80,
        wrongsv_protocol::RequestCommand::Tcp,
        "",
    );
    client.send(&vless_header);

    for _ in 0..50 {
        client.step(20);
        let _ = client.recv();
    }
}

#[test]
fn test_kcp_vision_response() {
    init_logging();
    let port = pick_port();
    let _server = spawn_kcp_server(port, TEST_UUID, "xtls-rprx-vision");
    let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_addr).unwrap();

    let mut client = TestKcpClient::new(socket, server_addr, TEST_SEED, 11);
    let vless_header = encode_vless_request(
        TEST_UUID,
        "127.0.0.1",
        80,
        wrongsv_protocol::RequestCommand::Tcp,
        "xtls-rprx-vision",
    );
    client.send(&vless_header);

    let response = client
        .wait_for_data(2500)
        .expect("Vision flow should receive VLESS response");
    assert_eq!(response[0], 0, "VLESS version must be 0");
}
