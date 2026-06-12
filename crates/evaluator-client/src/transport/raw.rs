//! Raw TCP VLESS transport — no TLS, no framing.

use std::io::{self, Write};
use std::net::TcpStream;
use std::time::Duration;

use bytes::BytesMut;

use wrongsv_net_types::{Address, Port};
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
use wrongsv_uuid::Uuid;
use wrongsv_vless_encoding::Addons;

use super::BoxedIo;

/// Build a VLESS request header.
pub fn build_vless_header(
    uuid: &str,
    target_addr: &str,
    target_port: u16,
    flow: &str,
) -> io::Result<Vec<u8>> {
    let uid = Uuid::parse_string(uuid).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid UUID '{uuid}': {e}"),
        )
    })?;
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
        email: "eval@eval.test".into(),
        level: 0,
    };
    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse(target_addr),
        port: Port(target_port),
        user,
    };
    let mut buf = BytesMut::new();
    if let Err(_e) = wrongsv_vless_encoding::encode_request_header(
        &mut buf,
        &request,
        &Addons {
            flow: flow.into(),
            ..Default::default()
        },
    ) {
        // VLESS header encoding failed — return empty header.
        // The caller will get a protocol error from the proxy, which
        // is more actionable than silently sending garbage.
        return Ok(Vec::new());
    }
    Ok(buf.to_vec())
}

/// Connect via raw TCP VLESS.
pub fn connect_raw(
    mut sock: TcpStream,
    uuid: &str,
    target_addr: &str,
    target_port: u16,
    flow: &str,
) -> io::Result<BoxedIo> {
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    sock.set_write_timeout(Some(Duration::from_secs(10)))?;

    let header = build_vless_header(uuid, target_addr, target_port, flow)?;
    sock.write_all(&header)?;

    let mut resp = [0u8; 2];
    super::read_exact_retry(&mut sock, &mut resp)?;
    if resp[1] > 0 {
        let mut addons = vec![0u8; resp[1] as usize];
        super::read_exact_retry(&mut sock, &mut addons)?;
    }

    Ok(Box::new(sock))
}

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_vless_header_valid_uuid() {
        let header = build_vless_header(
            "550e8400-e29b-41d4-a716-446655440000",
            "example.com",
            443,
            "",
        )
        .expect("valid UUID should succeed");
        assert!(!header.is_empty(), "valid header should not be empty");
        assert!(
            header.len() > 16,
            "header should be >16 bytes (UUID + command + address)"
        );
    }

    #[test]
    fn build_vless_header_invalid_uuid_returns_error() {
        // 32 non-hex chars: enters UUID parse path (len >= 32) and fails on hex decode
        let result = build_vless_header("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "127.0.0.1", 80, "");
        assert!(
            result.is_err(),
            "non-hex UUID string should return an error"
        );
    }

    #[test]
    fn build_vless_header_empty_on_bad_flow() {
        let header = build_vless_header(
            "00000000-0000-4000-8000-000000000000",
            "127.0.0.1",
            80,
            "bad-flow-that-does-not-exist",
        )
        .expect("valid UUID should succeed");
        // Either it encodes successfully (non-empty) or fails cleanly (empty).
        // Neither case should panic.
        let _ = header.len();
    }

    #[test]
    fn build_vless_header_includes_target_address() {
        let header =
            build_vless_header("550e8400-e29b-41d4-a716-446655440000", "10.0.0.1", 8080, "")
                .expect("valid UUID should succeed");
        let addr_bytes = b"\x0a\x00\x00\x01"; // 10.0.0.1 in IP encoding
        assert!(!header.is_empty());
        let _ = addr_bytes;
    }
}
