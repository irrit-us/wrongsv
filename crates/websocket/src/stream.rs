//! `WebSocketStream<S>` — a WebSocket-framed wrapper around any `Read + Write` stream.
//!
//! After the WebSocket upgrade handshake, wrap the underlying stream (whether
//! raw TCP or TLS) in a `WebSocketStream`. The wrapper implements `Read` and
//! `Write`, transparently handling WebSocket frame boundaries so the caller
//! sees a plain byte stream.

use std::io::{ErrorKind, Read, Result as IoResult, Write};

use crate::frame::{self, FrameError, Opcode};

/// Wraps an underlying `Read + Write` stream, handling WebSocket framing.
///
/// - `Read`: reads binary frames from the inner stream, auto-replies to Ping
///   frames, and signals EOF on Close frames.
/// - `Write`: wraps each write in a single binary WebSocket frame.
pub struct WebSocketStream<S> {
    inner: S,
    /// Buffered payload from a partially-consumed frame.
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Set to true when we've received a Close frame — subsequent reads
    /// will return Ok(0) (EOF).
    closed: bool,
}

impl<S> WebSocketStream<S> {
    /// Wrap an existing stream. Any pre-buffered data (e.g. early data after
    /// the HTTP upgrade) is consumed as the initial read buffer.
    pub fn new(inner: S, initial: Vec<u8>) -> Self {
        Self {
            inner,
            read_buf: initial,
            read_pos: 0,
            closed: false,
        }
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Write a WebSocket close frame and flush.
    pub fn write_close(&mut self, code: u16) -> IoResult<()>
    where
        S: Write,
    {
        frame::write_close(&mut self.inner, code).map_err(std::io::Error::other)?;
        self.inner.flush()
    }

    /// Return unread bytes still in our internal buffer.
    fn buf_remaining(&self) -> usize {
        self.read_buf.len().saturating_sub(self.read_pos)
    }

    /// Try to fill the read buffer with the next binary frame from the inner stream.
    fn fill_buffer(&mut self) -> IoResult<bool>
    where
        S: Read + Write,
    {
        use std::io::ErrorKind::WouldBlock;

        loop {
            match frame::read_frame(&mut self.inner, true) {
                // client frames MUST be masked
                Ok(frame) => match frame.opcode {
                    Opcode::Binary => {
                        self.read_buf = frame.payload;
                        self.read_pos = 0;
                        return Ok(true);
                    }
                    Opcode::Text => {
                        // We don't support text frames — treat as error
                        return Err(std::io::Error::other(
                            "unexpected text frame (only binary supported)",
                        ));
                    }
                    Opcode::Ping => {
                        // Auto-reply with Pong
                        let _ = frame::write_pong(&mut self.inner, &frame.payload);
                        let _ = self.inner.flush();
                        // Continue loop to read next frame
                    }
                    Opcode::Pong => {
                        // Ignore (unsolicited pong)
                        // Continue loop
                    }
                    Opcode::Close => {
                        // RFC 6455: echo close frame back
                        let _ = frame::write_close(&mut self.inner, 1000);
                        let _ = self.inner.flush();
                        self.closed = true;
                        self.read_buf.clear();
                        self.read_pos = 0;
                        return Ok(false);
                    }
                },
                Err(FrameError::Io(e))
                    if matches!(e.kind(), WouldBlock | std::io::ErrorKind::TimedOut) =>
                {
                    return Err(e);
                }
                Err(e) => {
                    return Err(std::io::Error::other(e));
                }
            }
        }
    }
}

impl<S: Read + Write> Read for WebSocketStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if self.closed {
            return Ok(0);
        }

        // Serve from buffered data first
        let remaining = self.buf_remaining();
        if remaining > 0 {
            let n = remaining.min(buf.len());
            buf[..n].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
            self.read_pos += n;
            return Ok(n);
        }

        // Need a new frame
        match self.fill_buffer() {
            Ok(true) => {
                // Now serve from the fresh buffer
                let n = self.buf_remaining().min(buf.len());
                buf[..n].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
                self.read_pos += n;
                Ok(n)
            }
            Ok(false) => Ok(0), // Close frame → EOF
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => Err(std::io::Error::new(
                ErrorKind::WouldBlock,
                "no WebSocket frame available",
            )),
            Err(e) => Err(e),
        }
    }
}

impl<S: Read + Write> Write for WebSocketStream<S> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        frame::write_binary(&mut self.inner, buf).map_err(std::io::Error::other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A paired "stream" implemented as two byte buffers: one for
    /// client→server, one for server→client.
    struct TestChannel {
        client_to_server: Cursor<Vec<u8>>,
        server_to_client: Vec<u8>,
    }

    impl Read for TestChannel {
        fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
            self.client_to_server.read(buf)
        }
    }

    impl Write for TestChannel {
        fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
            self.server_to_client.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    /// Write a masked binary frame (simulating client → server).
    fn write_masked_binary<W: Write>(writer: &mut W, data: &[u8]) {
        crate::frame::write_frame(
            writer,
            &crate::frame::Frame {
                fin: true,
                opcode: crate::frame::Opcode::Binary,
                payload: data.to_vec(),
            },
            true, // client frames are masked
        )
        .unwrap();
    }

    /// Write a masked close frame.
    fn write_masked_close<W: Write>(writer: &mut W, code: u16) {
        crate::frame::write_frame(
            writer,
            &crate::frame::Frame {
                fin: true,
                opcode: crate::frame::Opcode::Close,
                payload: code.to_be_bytes().to_vec(),
            },
            true,
        )
        .unwrap();
    }

    /// Write a masked ping frame.
    fn write_masked_ping<W: Write>(writer: &mut W, data: &[u8]) {
        crate::frame::write_frame(
            writer,
            &crate::frame::Frame {
                fin: true,
                opcode: crate::frame::Opcode::Ping,
                payload: data.to_vec(),
            },
            true,
        )
        .unwrap();
    }

    #[test]
    fn read_binary_frame() {
        // Client writes a masked binary frame into the channel
        let data = b"hello from client";
        let mut client_buf = Vec::new();
        write_masked_binary(&mut client_buf, data);

        let channel = TestChannel {
            client_to_server: Cursor::new(client_buf),
            server_to_client: Vec::new(),
        };

        let mut ws = WebSocketStream::new(channel, Vec::new());
        let mut out = [0u8; 128];
        let n = ws.read(&mut out).unwrap();
        assert_eq!(&out[..n], data);
    }

    #[test]
    fn write_binary_frame() {
        let channel = TestChannel {
            client_to_server: Cursor::new(Vec::new()),
            server_to_client: Vec::new(),
        };

        let mut ws = WebSocketStream::new(channel, Vec::new());
        ws.write_all(b"hello from server").unwrap();
        ws.flush().unwrap();

        let sent = ws.into_inner().server_to_client;
        // Decode the frame from server_to_client
        let frame = frame::read_frame(&mut Cursor::new(sent), false).unwrap();
        assert_eq!(frame.opcode, Opcode::Binary);
        assert_eq!(frame.payload, b"hello from server");
    }

    #[test]
    fn close_frame_signals_eof() {
        let mut buf = Vec::new();
        write_masked_close(&mut buf, 1000);

        let channel = TestChannel {
            client_to_server: Cursor::new(buf),
            server_to_client: Vec::new(),
        };

        let mut ws = WebSocketStream::new(channel, Vec::new());
        let mut out = [0u8; 128];
        let n = ws.read(&mut out).unwrap();
        assert_eq!(n, 0); // EOF

        // Second read also returns EOF
        let n = ws.read(&mut out).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn ping_auto_reply_then_read_data() {
        // Write a masked Ping frame, then a masked Binary frame
        let mut buf = Vec::new();
        write_masked_ping(&mut buf, b"keepalive");
        write_masked_binary(&mut buf, b"real data");

        let channel = TestChannel {
            client_to_server: Cursor::new(buf),
            server_to_client: Vec::new(),
        };

        let mut ws = WebSocketStream::new(channel, Vec::new());

        // Should skip the Ping (auto-reply Pong) and read the Binary frame
        let mut out = [0u8; 128];
        let n = ws.read(&mut out).unwrap();
        assert_eq!(&out[..n], b"real data");

        // Check that a Pong was sent back
        let sent = ws.into_inner().server_to_client;
        let frame = frame::read_frame(&mut Cursor::new(sent), false).unwrap();
        assert_eq!(frame.opcode, Opcode::Pong);
        assert_eq!(frame.payload, b"keepalive");
    }

    #[test]
    fn initial_buffer_consumed_first() {
        let channel = TestChannel {
            client_to_server: Cursor::new(Vec::new()),
            server_to_client: Vec::new(),
        };

        let mut ws = WebSocketStream::new(channel, b"early data".to_vec());
        let mut out = [0u8; 5];
        let n = ws.read(&mut out).unwrap();
        assert_eq!(&out[..n], b"early");
        let n = ws.read(&mut out).unwrap();
        assert_eq!(&out[..n], b" data");
    }
}
