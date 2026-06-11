//! WebSocket transport: optional TLS + WS upgrade + VLESS in masked frames.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;

use super::BoxedIo;
use super::tls_common;

/// WebSocket frame from the client (always masked, random key).
fn make_ws_frame(payload: &[u8]) -> Vec<u8> {
    let mask: [u8; 4] = rand::random();
    let payload_len = payload.len();

    let mut frame = Vec::with_capacity(14 + payload_len);
    frame.push(0x82); // FIN | Binary opcode
    if payload_len < 126 {
        frame.push(0x80 | payload_len as u8);
    } else if payload_len <= 65535 {
        frame.push(0x80 | 126u8);
        frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127u8);
        frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i % 4]);
    }
    frame
}

/// Read a WebSocket header from the server (unmasked).
fn read_ws_header(stream: &mut dyn Read) -> io::Result<(u8, u64)> {
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr)?;
    let opcode = hdr[0] & 0x0F;
    let mut len = (hdr[1] & 0x7F) as u64;

    if len == 126 {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        len = u16::from_be_bytes(buf) as u64;
    } else if len == 127 {
        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf)?;
        len = u64::from_be_bytes(buf);
    }

    Ok((opcode, len))
}

/// WebSocket I/O wrapper: frames outgoing data, deframes incoming data.
struct WsConnection {
    inner: Box<dyn super::ReadWrite>,
    read_buf: Vec<u8>,
}

impl WsConnection {
    fn new(inner: Box<dyn super::ReadWrite>) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
        }
    }
}

impl Read for WsConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Serve from buffer first
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.len());
            buf[..n].copy_from_slice(&self.read_buf[..n]);
            self.read_buf.drain(..n);
            if n > 0 {
                return Ok(n);
            }
        }

        // Read next frame
        loop {
            let (opcode, len) = read_ws_header(self.inner.as_mut())?;
            let mut payload = vec![0u8; len as usize];
            if len > 0 {
                self.inner.read_exact(&mut payload)?;
            }

            match opcode {
                0x02 => {
                    // Binary frame — return payload
                    let n = payload.len().min(buf.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    if n < payload.len() {
                        self.read_buf.extend_from_slice(&payload[n..]);
                    }
                    return Ok(n);
                }
                0x08 => {
                    // Close frame
                    return Ok(0);
                }
                0x09 => {
                    // Ping — respond with masked pong
                    let mask: [u8; 4] = rand::random();
                    let pong: Vec<u8> = vec![0x8A, 0x80, mask[0], mask[1], mask[2], mask[3]];
                    let _ = self.inner.write_all(&pong);
                }
                _ => {} // Skip other frames
            }
        }
    }
}

impl Write for WsConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let frame = make_ws_frame(buf);
        self.inner.write_all(&frame)?;
        self.inner.flush()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ── Connection ───────────────────────────────────────────────────────────

/// Perform the HTTP upgrade to WebSocket (with random key per RFC 6455).
fn ws_upgrade_handshake(stream: &mut dyn ReadWrite, path: &str) -> io::Result<()> {
    let random_bytes: [u8; 16] = rand::random();
    use base64::Engine;
    let key = base64::engine::general_purpose::STANDARD.encode(random_bytes);
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
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
                "WS upgrade: connection closed",
            ));
        }
        total += n;
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if total >= 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WS upgrade response too large",
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

trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

/// Connect via WebSocket (with optional TLS).
pub fn connect_ws(
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

        ws_upgrade_handshake(&mut tls, "/eval")?;

        let header = super::raw::build_vless_header(uuid, target_addr, target_port, flow);
        let frame = make_ws_frame(&header);
        tls.write_all(&frame)?;

        // Read VLESS response
        let (_opcode, len) = read_ws_header(&mut tls)?;
        if len > 0 {
            let mut discard = vec![0u8; len as usize];
            tls.read_exact(&mut discard)?;
        }

        Ok(Box::new(WsConnection::new(Box::new(tls))))
    } else {
        let mut sock = sock;
        ws_upgrade_handshake(&mut sock, "/eval")?;

        let header = super::raw::build_vless_header(uuid, target_addr, target_port, flow);
        let frame = make_ws_frame(&header);
        sock.write_all(&frame)?;

        let (_opcode, len) = read_ws_header(&mut sock)?;
        if len > 0 {
            let mut discard = vec![0u8; len as usize];
            sock.read_exact(&mut discard)?;
        }

        Ok(Box::new(WsConnection::new(Box::new(sock))))
    }
}
