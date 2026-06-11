//! AnyTLS transport: TLS + SHA256 password auth + VLESS.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::tls_common;
use super::BoxedIo;

const ANYTLS_PASSWORD: &str = "eval-anytls-pass";

pub fn connect_anytls(
    sock: TcpStream,
    uuid: &str,
    target_addr: &str,
    target_port: u16,
    flow: &str,
) -> io::Result<BoxedIo> {
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    // tls_handshake_sync also sets write_timeout
    let mut tls = tls_common::tls_handshake_sync(sock, "cloudfront.net")?;

    // Send auth frame: SHA256(password) || padding_len(0x0000)
    let password_hash: [u8; 32] = Sha256::digest(ANYTLS_PASSWORD.as_bytes()).into();
    tls.write_all(&password_hash)?;
    tls.write_all(&[0x00, 0x00])?;

    // Send VLESS header
    let header = super::raw::build_vless_header(uuid, target_addr, target_port, flow);
    tls.write_all(&header)?;

    // Read VLESS response
    let mut resp = [0u8; 2];
    tls.read_exact(&mut resp)?;
    if resp[1] > 0 {
        let mut addons = vec![0u8; resp[1] as usize];
        tls.read_exact(&mut addons)?;
    }

    Ok(Box::new(tls))
}
