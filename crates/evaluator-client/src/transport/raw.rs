//! Raw TCP VLESS transport — no TLS, no framing.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use bytes::BytesMut;

use wrongsv_net_types::{Address, Port};
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
use wrongsv_uuid::Uuid;
use wrongsv_vless_encoding::Addons;

use super::BoxedIo;

/// Build a VLESS request header.
pub fn build_vless_header(uuid: &str, target_addr: &str, target_port: u16, flow: &str) -> Vec<u8> {
    let uid = Uuid::parse_string(uuid)
        .unwrap_or_else(|_| Uuid::parse_string("00000000-0000-4000-8000-000000000000").unwrap());
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
    wrongsv_vless_encoding::encode_request_header(
        &mut buf,
        &request,
        &Addons {
            flow: flow.into(),
            ..Default::default()
        },
    )
    .unwrap_or_default();
    buf.to_vec()
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

    let header = build_vless_header(uuid, target_addr, target_port, flow);
    sock.write_all(&header)?;

    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp)?;
    if resp[1] > 0 {
        let mut addons = vec![0u8; resp[1] as usize];
        sock.read_exact(&mut addons)?;
    }

    Ok(Box::new(sock))
}
