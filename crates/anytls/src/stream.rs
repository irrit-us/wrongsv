/// Per-stream handle for sing-anytls multiplexed streams.
///
/// Each stream receives data via an mpsc channel filled by the session reader.
/// The stream's relay thread reads from this channel and writes framed PSH
/// data back through the shared SessionWriter.
use std::sync::mpsc::{Receiver, TryRecvError};

use super::session::SessionWriter;

pub struct SingStream {
    pub id: u32,
    data_rx: Receiver<Vec<u8>>,
    /// Buffered data not yet consumed by the relay
    buffer: Vec<u8>,
    buf_pos: usize,
    /// True when the sender has been dropped (FIN received)
    closed: bool,
}

impl SingStream {
    pub fn new(id: u32, data_rx: Receiver<Vec<u8>>) -> Self {
        Self {
            id,
            data_rx,
            buffer: Vec::new(),
            buf_pos: 0,
            closed: false,
        }
    }

    /// Read the next chunk of data from this stream (blocking).
    /// Returns `None` when the stream is closed (sender dropped).
    pub fn read_chunk(&mut self) -> Option<Vec<u8>> {
        if self.closed {
            return None;
        }
        if self.buf_pos < self.buffer.len() {
            let remaining = self.buffer[self.buf_pos..].to_vec();
            self.buf_pos = self.buffer.len();
            return Some(remaining);
        }

        match self.data_rx.recv() {
            Ok(data) => {
                self.buffer = data;
                self.buf_pos = self.buffer.len();
                Some(self.buffer.clone())
            }
            Err(_) => {
                self.closed = true;
                None
            }
        }
    }

    /// Try to read without blocking.
    /// Returns `Some(data)` if data is available, `None` if the stream is
    /// closed, or blocks briefly (polls once, no blocking).
    pub fn try_read_chunk(&mut self) -> Option<Vec<u8>> {
        if self.closed {
            return None;
        }
        if self.buf_pos < self.buffer.len() {
            let remaining = self.buffer[self.buf_pos..].to_vec();
            self.buf_pos = self.buffer.len();
            return Some(remaining);
        }

        match self.data_rx.try_recv() {
            Ok(data) => {
                self.buffer = data;
                self.buf_pos = self.buffer.len();
                Some(self.buffer.clone())
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.closed = true;
                None
            }
        }
    }

    /// Read exactly `len` bytes. Returns fewer if stream closes.
    pub fn read_exact(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            if self.closed || self.buf_pos >= self.buffer.len() {
                match self.data_rx.recv() {
                    Ok(data) => {
                        self.buffer = data;
                        self.buf_pos = 0;
                    }
                    Err(_) => {
                        self.closed = true;
                        break;
                    }
                }
            }
            let remaining = self.buffer.len() - self.buf_pos;
            let take = remaining.min(len - out.len());
            out.extend_from_slice(&self.buffer[self.buf_pos..self.buf_pos + take]);
            self.buf_pos += take;
        }
        out
    }

    /// True when the stream has been closed (FIN received or channel hung up).
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Peek at the first byte of the next chunk without consuming it.
    /// Blocks until data arrives or stream closes.
    pub fn peek_byte(&mut self) -> Option<u8> {
        if self.closed {
            return None;
        }
        if self.buf_pos < self.buffer.len() {
            return Some(self.buffer[self.buf_pos]);
        }
        match self.data_rx.recv() {
            Ok(data) => {
                let byte = data[0];
                self.buffer = data;
                self.buf_pos = 0;
                Some(byte)
            }
            Err(_) => {
                self.closed = true;
                None
            }
        }
    }
}

/// Writer adapter: sends data as PSH frames through the shared SessionWriter,
/// and sends FIN on close.
pub struct SingStreamWriter {
    pub sid: u32,
    writer: SessionWriter,
}

impl SingStreamWriter {
    pub fn new(sid: u32, writer: SessionWriter) -> Self {
        Self { sid, writer }
    }

    pub fn write(&self, data: &[u8]) -> Result<(), crate::AnyTlsError> {
        self.writer.send_psh(self.sid, data)
    }

    pub fn close(&self) -> Result<(), crate::AnyTlsError> {
        self.writer.send_fin(self.sid)
    }
}
