//! WebSocket transport: optional TLS + WS upgrade + VLESS in masked frames.
//!
//! Frame encoding delegates to the `wrongsv-websocket` crate. Frame decoding
//! keeps WouldBlock-tolerant reads specific to the evaluator's I/O model.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use wrongsv_websocket::{Frame, Opcode};

use super::BoxedIo;
use super::tls_common;

/// Build a masked client→server WebSocket frame using the websocket crate.
fn make_ws_frame(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(14 + payload.len());
    wrongsv_websocket::write_frame(
        &mut buf,
        &Frame {
            fin: true,
            opcode: Opcode::Binary,
            payload: payload.to_vec(),
        },
        true, // masked: client → server
    )
    .expect("write to Vec is infallible");
    buf
}

/// Read a WebSocket header from the server (unmasked).
/// Uses WouldBlock-tolerant reads for high-RTT paths.
fn read_ws_header(stream: &mut dyn Read) -> io::Result<(u8, u64)> {
    let mut hdr = [0u8; 2];
    read_exact_ws(stream, &mut hdr)?;
    let opcode = hdr[0] & 0x0F;
    let mut len = (hdr[1] & 0x7F) as u64;

    if len == 126 {
        let mut buf = [0u8; 2];
        read_exact_ws(stream, &mut buf)?;
        len = u16::from_be_bytes(buf) as u64;
    } else if len == 127 {
        let mut buf = [0u8; 8];
        read_exact_ws(stream, &mut buf)?;
        len = u64::from_be_bytes(buf);
    }

    Ok((opcode, len))
}

/// WouldBlock-tolerant read_exact for WebSocket framing.
fn read_exact_ws(stream: &mut dyn Read, mut buf: &mut [u8]) -> io::Result<()> {
    let mut retries: u32 = 0;
    const MAX_RETRIES: u32 = 600;
    while !buf.is_empty() {
        match stream.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                let tmp = buf;
                buf = &mut tmp[n..];
                retries = 0;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                retries += 1;
                if retries > MAX_RETRIES {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "ws read_exact: too many WouldBlock retries",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => return Err(e),
        }
    }
    if buf.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "ws read_exact: failed to fill buffer",
        ))
    }
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
                read_exact_ws(self.inner.as_mut(), &mut payload)?;
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
                    // Ping — respond with masked pong per RFC 6455 §5.5.3.
                    // The pong MUST echo the ping's application data.
                    let mut pong = Vec::new();
                    let _ = wrongsv_websocket::write_frame(
                        &mut pong,
                        &Frame {
                            fin: true,
                            opcode: Opcode::Pong,
                            payload,
                        },
                        true, // masked: client → server
                    );
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
    let mut retries: u32 = 0;
    loop {
        match stream.read(&mut buf[total..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "WS upgrade: connection closed",
                ));
            }
            Ok(n) => {
                total += n;
                retries = 0;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                retries += 1;
                if retries > 600 {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "WS upgrade: too many WouldBlock retries",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            Err(e) => return Err(e),
        }
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
            super::read_exact_retry(&mut tls, &mut discard)?;
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
            super::read_exact_retry(&mut sock, &mut discard)?;
        }

        Ok(Box::new(WsConnection::new(Box::new(sock))))
    }
}

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Mock stream that feeds a server→client ping frame and captures writes.
    /// Uses Arc<Mutex<Vec<u8>>> for the write buffer so the test can inspect
    /// the pong after WsConnection takes ownership of the mock.
    struct PingMock {
        frame: Vec<u8>,
        pos: usize,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl PingMock {
        fn new(payload: &[u8]) -> (Self, Arc<Mutex<Vec<u8>>>) {
            // Build unmasked ping frame (server→client direction)
            let mut frame = Vec::new();
            frame.push(0x89); // FIN | Ping
            frame.push(payload.len() as u8); // unmasked
            frame.extend_from_slice(payload);
            let written = Arc::new(Mutex::new(Vec::new()));
            let mock = PingMock {
                frame,
                pos: 0,
                written: Arc::clone(&written),
            };
            (mock, written)
        }
    }

    impl Read for PingMock {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.frame.len() {
                // Return UnexpectedEof so WouldBlock-tolerant readers stop
                // immediately instead of retrying for 3 seconds.
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mock exhausted",
                ));
            }
            let n = (self.frame.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.frame[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    impl Write for PingMock {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn pong_echoes_ping_payload_per_rfc6455() {
        let ping_payload = b"hello";
        let (mock, written) = PingMock::new(ping_payload);
        let mut conn = WsConnection::new(Box::new(mock));

        // Read will process the ping frame and write a pong response.
        // After consuming the ping, the mock returns UnexpectedEof (no more frames).
        // WsConnection::read propagates this to the caller.
        let mut buf = [0u8; 64];
        let result = conn.read(&mut buf);
        assert!(
            matches!(&result, Err(e) if e.kind() == io::ErrorKind::UnexpectedEof),
            "expected UnexpectedEof after ping (mock exhausted), got {result:?}"
        );

        let pong = written.lock().unwrap();
        assert!(!pong.is_empty(), "pong frame was written");

        // Pong frame structure: [0x8A, 0x85, mask[4], masked_payload[...]]
        assert_eq!(pong[0], 0x8A, "pong opcode byte");
        let mask_flag = pong[1];
        assert!(mask_flag & 0x80 != 0, "pong must be masked (client→server)");
        let plen = (mask_flag & 0x7F) as usize;
        assert_eq!(
            plen,
            ping_payload.len(),
            "pong payload length must equal ping payload length"
        );
        assert_eq!(pong.len(), 2 + 4 + plen, "pong frame total length");

        // XOR-unmask the payload
        let mask = &pong[2..6];
        let unmasked: Vec<u8> = pong[6..]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        assert_eq!(
            &unmasked, ping_payload,
            "RFC 6455 §5.5.3: pong MUST echo ping's application data"
        );
    }

    #[test]
    fn pong_handles_empty_ping() {
        let (mock, written) = PingMock::new(b"");
        let mut conn = WsConnection::new(Box::new(mock));
        let mut buf = [0u8; 64];
        let _ = conn.read(&mut buf);

        let pong = written.lock().unwrap();
        assert!(!pong.is_empty(), "empty ping still gets a pong response");
        assert_eq!(pong[0], 0x8A, "pong opcode");
        let plen = (pong[1] & 0x7F) as usize;
        assert_eq!(plen, 0, "empty ping → empty pong payload");
        // Just mask bytes (4), no payload
        assert_eq!(pong.len(), 2 + 4);
    }

    #[test]
    fn pong_handles_large_ping_payload() {
        let ping_payload = vec![0xAAu8; 125]; // max 7-bit length
        let (mock, written) = PingMock::new(&ping_payload);
        let mut conn = WsConnection::new(Box::new(mock));
        let mut buf = [0u8; 64];
        let _ = conn.read(&mut buf);

        let pong = written.lock().unwrap();
        let plen = (pong[1] & 0x7F) as usize;
        assert_eq!(plen, 125, "large ping payload round-trips");
        assert_eq!(pong.len(), 2 + 4 + 125);

        // Verify all bytes round-trip correctly
        let mask = &pong[2..6];
        for (i, b) in pong[6..].iter().enumerate() {
            assert_eq!(b ^ mask[i % 4], 0xAA, "byte {i} round-trips");
        }
    }

    /// Verify that `make_ws_frame` (which delegates to the `wrongsv-websocket`
    /// crate) produces frames the crate can parse back.
    #[test]
    fn make_ws_frame_uses_crate_and_roundtrips() {
        let payload = b"hello crate integration";
        let frame_bytes = make_ws_frame(payload);

        // The crate's read_frame should parse this back as a masked binary frame.
        let mut cursor = std::io::Cursor::new(frame_bytes);
        let frame = wrongsv_websocket::read_frame(&mut cursor, false).unwrap();
        assert!(frame.fin, "FIN bit must be set");
        assert_eq!(frame.opcode, Opcode::Binary);
        assert_eq!(frame.payload, payload);
    }

    /// Empty payload roundtrip via crate.
    #[test]
    fn make_ws_frame_empty_payload_roundtrips() {
        let frame_bytes = make_ws_frame(b"");
        let mut cursor = std::io::Cursor::new(frame_bytes);
        let frame = wrongsv_websocket::read_frame(&mut cursor, false).unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, Opcode::Binary);
        assert!(frame.payload.is_empty());
    }

    /// Large payload (64 KiB) roundtrip via crate.
    #[test]
    fn make_ws_frame_large_payload_roundtrips() {
        let payload = vec![0xABu8; 65536];
        let frame_bytes = make_ws_frame(&payload);
        let mut cursor = std::io::Cursor::new(frame_bytes);
        let frame = wrongsv_websocket::read_frame(&mut cursor, false).unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, Opcode::Binary);
        assert_eq!(frame.payload, payload);
    }
}
