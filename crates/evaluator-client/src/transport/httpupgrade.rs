//! HTTPUpgrade transport: HTTP 101 upgrade, then raw VLESS bytes (no WS frames).

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;

use super::tls_common;
use super::BoxedIo;

/// Perform the HTTPUpgrade handshake.
fn http_upgrade_handshake(stream: &mut dyn ReadWrite, path: &str) -> io::Result<()> {
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: keep-alive, Upgrade\r\n\
         \r\n"
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut buf = vec![0u8; 4096];
    let mut total = 0;
    loop {
        let n = stream.read(&mut buf[total..])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTPUpgrade: connection closed",
            ));
        }
        total += n;
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if total >= 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTPUpgrade response too large",
            ));
        }
        buf.resize(4096, 0);
    }

    let resp = String::from_utf8_lossy(&buf[..total]);
    if !resp.starts_with("HTTP/1.1 101 ") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("expected HTTP 101, got: {resp}"),
        ));
    }
    Ok(())
}

/// Connect via HTTPUpgrade (with optional TLS).
pub fn connect_httpupgrade(
    sock: TcpStream,
    uuid: &str,
    target_addr: &str,
    target_port: u16,
    flow: &str,
    tls_config: Option<Arc<ClientConfig>>,
) -> io::Result<BoxedIo> {
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    sock.set_write_timeout(Some(Duration::from_secs(10)))?;

    if tls_config.is_some() {
        let mut tls = tls_common::tls_handshake_sync(sock, "cloudfront.net")?;
        http_upgrade_handshake(&mut tls, "/eval")?;

        let header = super::raw::build_vless_header(uuid, target_addr, target_port, flow);
        tls.write_all(&header)?;

        let mut resp = [0u8; 2];
        tls.read_exact(&mut resp)?;
        if resp[1] > 0 {
            let mut addons = vec![0u8; resp[1] as usize];
            tls.read_exact(&mut addons)?;
        }

        Ok(Box::new(tls))
    } else {
        let mut sock = sock;
        http_upgrade_handshake(&mut sock, "/eval")?;

        let header = super::raw::build_vless_header(uuid, target_addr, target_port, flow);
        sock.write_all(&header)?;

        let mut resp = [0u8; 2];
        sock.read_exact(&mut resp)?;
        if resp[1] > 0 {
            let mut addons = vec![0u8; resp[1] as usize];
            sock.read_exact(&mut addons)?;
        }

        Ok(Box::new(sock))
    }
}

trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}
