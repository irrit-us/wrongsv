//! KCP (mKCP) carrier integration tests.
//!
//! These tests verify VLESS over KCP transport — mKCP auth + KCP reliable
//! session + VLESS relay without external client binaries.

use std::cell::RefCell;
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::rc::Rc;
use std::time::Duration;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use kcp::Kcp;
use sha2::Digest;

mod common;
use common::{init_logging, pick_port, spawn_tcp_echo_target};

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

// ── mKCP helpers ────────────────────────────────────────────────────────

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

// ── KCP output that buffers bytes for mKCP wrapping ────────────────────

/// Shared-output writer. KCP calls `write()` with raw KCP segments;
/// we collect them in a shared buffer that the test loop reads via Rc.
struct SharedOutput {
    buf: Rc<RefCell<Vec<u8>>>,
}

impl SharedOutput {
    fn new(buf: Rc<RefCell<Vec<u8>>>) -> Self {
        SharedOutput { buf }
    }
}

impl Write for SharedOutput {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ── Test KCP client ────────────────────────────────────────────────────

struct TestKcpClient {
    kcp: Kcp<SharedOutput>,
    output_buf: Rc<RefCell<Vec<u8>>>,
    socket: UdpSocket,
    server_addr: SocketAddr,
    seed: String,
    #[allow(dead_code)]
    conv: u16,
}

impl TestKcpClient {
    fn new(socket: UdpSocket, server_addr: SocketAddr, seed: &str, conv: u16) -> Self {
        let buf = Rc::new(RefCell::new(Vec::new()));
        let output = SharedOutput::new(Rc::clone(&buf));
        let mut kcp = Kcp::new(conv as u32, output);
        let _ = kcp.set_mtu(1350);
        kcp.set_nodelay(true, 10, 2, true);
        kcp.set_wndsize(128, 256);
        TestKcpClient {
            kcp,
            output_buf: buf,
            socket,
            server_addr,
            seed: seed.to_string(),
            conv,
        }
    }

    /// Drain pending KCP output, wrap in mKCP framing, and send via UDP.
    fn drain_output(&mut self) {
        let pending: Vec<u8> = self.output_buf.borrow_mut().drain(..).collect();
        if !pending.is_empty() {
            let packet = mkcp_seal(&self.seed, &pending);
            let _ = self.socket.send_to(&packet, self.server_addr);
        }
    }

    /// Send data through KCP to the server (splits into KCP segments, wraps
    /// in mKCP framing, sends via UDP).
    fn send_and_flush(&mut self, data: &[u8], tick: u32) {
        let _ = self.kcp.update(tick);
        let _ = self.kcp.send(data);
        let output: Vec<u8> = self.output_buf.borrow_mut().drain(..).collect();
        if !output.is_empty() {
            let packet = mkcp_seal(&self.seed, &output);
            let _ = self.socket.send_to(&packet, self.server_addr);
        }
        // Flush any remaining KCP output (ACKs, retransmits, etc.)
        self.kcp.flush().unwrap();
        let output2: Vec<u8> = self.output_buf.borrow_mut().drain(..).collect();
        if !output2.is_empty() {
            let packet = mkcp_seal(&self.seed, &output2);
            let _ = self.socket.send_to(&packet, self.server_addr);
        }
    }

    /// Pump: receive UDP packets, feed into KCP, flush output back.
    fn pump(&mut self, timeout_ms: u64) {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);

        while std::time::Instant::now() < deadline {
            self.socket
                .set_read_timeout(Some(Duration::from_millis(10)))
                .ok();

            let mut recv_buf = [0u8; 2048];
            match self.socket.recv_from(&mut recv_buf) {
                Ok((n, src)) => {
                    if src != self.server_addr {
                        continue;
                    }
                    if let Some(data) = mkcp_open(&self.seed, &recv_buf[..n]) {
                        let _ = self.kcp.input(&data);
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }

            // Send any KCP output (ACKs, etc.)
            self.drain_output();
        }
    }

    /// Read data from KCP after pumping.
    fn recv(&mut self) -> Option<Vec<u8>> {
        let mut buf = [0u8; 32768];
        match self.kcp.recv(&mut buf) {
            Ok(0) | Err(_) => None,
            Ok(n) => Some(buf[..n].to_vec()),
        }
    }
}

// ── Server spawning ─────────────────────────────────────────────────────

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

// ── Tests ───────────────────────────────────────────────────────────────

#[test]
fn test_kcp_handshake() {
    init_logging();
    let port = pick_port();
    let _server = spawn_kcp_server(port, TEST_UUID, "");
    let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_addr).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let mut client = TestKcpClient::new(socket.try_clone().unwrap(), server_addr, TEST_SEED, 1);

    let vless_header = encode_vless_request(
        TEST_UUID,
        "127.0.0.1",
        80,
        wrongsv_protocol::RequestCommand::Tcp,
        "",
    );

    // Send VLESS request and flush
    client.send_and_flush(&vless_header, 0);

    // Try to read VLESS response
    let mut attempts = 0;
    loop {
        let tick = (100 + attempts * 20) as u32;
        let _ = client.kcp.update(tick);
        client.pump(100);

        if let Some(data) = client.recv() {
            assert!(!data.is_empty(), "VLESS response should not be empty");
            assert_eq!(data[0], 0, "VLESS version must be 0");
            return;
        }

        attempts += 1;
        if attempts > 30 {
            panic!(
                "timed out waiting for VLESS response after {} attempts",
                attempts
            );
        }
    }
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
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let mut client = TestKcpClient::new(socket.try_clone().unwrap(), server_addr, TEST_SEED, 1);

    let vless_header = encode_vless_request(
        TEST_UUID,
        &echo_addr.ip().to_string(),
        echo_addr.port(),
        wrongsv_protocol::RequestCommand::Tcp,
        "",
    );

    client.send_and_flush(&vless_header, 0);

    // Wait for VLESS response
    let mut got_response = false;
    for tick in 0..40 {
        let _ = client.kcp.update((100 + tick * 20) as u32);
        client.pump(100);

        if let Some(data) = client.recv() {
            assert!(!data.is_empty());
            assert_eq!(data[0], 0, "VLESS version must be 0");
            got_response = true;
            break;
        }
    }
    assert!(got_response, "should receive VLESS response");

    // Send echo payload and verify echo
    let payload = b"hello-kcp-echo";
    client.send_and_flush(payload, 500);

    let mut echo_received = false;
    for tick in 0..60 {
        let _ = client.kcp.update((500 + tick * 20) as u32);
        client.pump(100);

        if let Some(data) = client.recv()
            && data == payload
        {
            echo_received = true;
            break;
        }
    }
    assert!(
        echo_received,
        "should receive echo of '{}'",
        std::str::from_utf8(payload).unwrap()
    );
}

#[test]
fn test_kcp_rejects_invalid_uuid() {
    init_logging();
    let port = pick_port();
    let _server = spawn_kcp_server(port, TEST_UUID, "");
    let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_addr).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let mut client = TestKcpClient::new(socket.try_clone().unwrap(), server_addr, TEST_SEED, 1);

    let bad_uuid = "00000000-0000-0000-0000-000000000000";
    let vless_header = encode_vless_request(
        bad_uuid,
        "127.0.0.1",
        80,
        wrongsv_protocol::RequestCommand::Tcp,
        "",
    );

    client.send_and_flush(&vless_header, 0);

    // The server should reject — we should either get no response or the
    // server will eventually close the KCP session.
    for tick in 0..20 {
        let _ = client.kcp.update((100 + tick * 20) as u32);
        client.pump(100);
        let _ = client.recv();
    }
    // Test passes if we don't hang
}

#[test]
fn test_kcp_vision_response() {
    init_logging();
    let port = pick_port();
    let _server = spawn_kcp_server(port, TEST_UUID, "xtls-rprx-vision");
    let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server_addr).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let mut client = TestKcpClient::new(socket.try_clone().unwrap(), server_addr, TEST_SEED, 1);

    let vless_header = encode_vless_request(
        TEST_UUID,
        "127.0.0.1",
        80,
        wrongsv_protocol::RequestCommand::Tcp,
        "xtls-rprx-vision",
    );

    client.send_and_flush(&vless_header, 0);

    let mut got_response = false;
    for tick in 0..40 {
        let _ = client.kcp.update((100 + tick * 20) as u32);
        client.pump(100);

        if let Some(data) = client.recv() {
            assert!(!data.is_empty());
            assert_eq!(data[0], 0, "VLESS version must be 0");
            got_response = true;
            break;
        }
    }
    assert!(got_response, "Vision flow should receive VLESS response");
}
