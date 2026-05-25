/// Body framing for VLESS: length-prefixed packets (UDP) and raw passthrough (TCP).
use bytes::BytesMut;
use std::io::{Read, Write};
use thiserror::Error;

/// Maximum packet size for length-prefixed UDP frames.
pub const MAX_PACKET_SIZE: usize = 65535;

// ── MultiLengthPacketWriter (used by server for UDP responses) ────────────

/// Writes each buffer prefixed with a 2-byte big-endian length.
pub struct MultiLengthPacketWriter<W: Write> {
    inner: W,
}

impl<W: Write> MultiLengthPacketWriter<W> {
    pub fn new(writer: W) -> Self {
        MultiLengthPacketWriter { inner: writer }
    }

    /// Write multiple buffers, each prefixed with its 2-byte length.
    pub fn write_buffers(&mut self, buffers: &[BytesMut]) -> Result<(), std::io::Error> {
        for buf in buffers {
            let len = buf.len();
            if len == 0 || len + 2 > 65536 {
                continue;
            }
            self.inner.write_all(&(len as u16).to_be_bytes())?;
            self.inner.write_all(buf)?;
        }
        Ok(())
    }
}

// ── LengthPacketWriter (single buffer, length-prefixed) ───────────────────

pub struct LengthPacketWriter<W: Write> {
    inner: W,
}

impl<W: Write> LengthPacketWriter<W> {
    pub fn new(writer: W) -> Self {
        LengthPacketWriter { inner: writer }
    }

    /// Write a single buffer with 2-byte length prefix.
    pub fn write_packet(&mut self, buf: &[u8]) -> Result<(), std::io::Error> {
        let len = buf.len();
        self.inner.write_all(&(len as u16).to_be_bytes())?;
        self.inner.write_all(buf)?;
        Ok(())
    }
}

// ── LengthPacketReader ────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PacketReadError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("packet too large: {0} bytes")]
    TooLarge(usize),
}

pub struct LengthPacketReader<R: Read> {
    inner: R,
}

impl<R: Read> LengthPacketReader<R> {
    pub fn new(reader: R) -> Self {
        LengthPacketReader { inner: reader }
    }

    /// Read one length-prefixed packet. Returns the payload bytes.
    pub fn read_packet(&mut self) -> Result<BytesMut, PacketReadError> {
        let mut len_buf = [0u8; 2];
        self.inner.read_exact(&mut len_buf)?;
        let length = u16::from_be_bytes(len_buf) as usize;
        if length > MAX_PACKET_SIZE {
            return Err(PacketReadError::TooLarge(length));
        }
        let mut payload = BytesMut::zeroed(length);
        self.inner.read_exact(&mut payload)?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_length_packet_roundtrip() {
        let payload = b"hello world";
        let mut buf = Vec::new();
        {
            let mut writer = LengthPacketWriter::new(&mut buf);
            writer.write_packet(payload).unwrap();
        }
        let mut cursor = Cursor::new(&buf);
        let mut reader = LengthPacketReader::new(&mut cursor);
        let decoded = reader.read_packet().unwrap();
        assert_eq!(&decoded[..], payload);
    }

    #[test]
    fn test_multi_length_writer() {
        let payloads = vec![BytesMut::from(&b"hello"[..]), BytesMut::from(&b"world"[..])];
        let mut buf = Vec::new();
        {
            let mut writer = MultiLengthPacketWriter::new(&mut buf);
            writer.write_buffers(&payloads).unwrap();
        }
        // 2 bytes len + 5 bytes "hello" + 2 bytes len + 5 bytes "world"
        assert_eq!(buf.len(), 14);
        assert_eq!(&buf[2..7], b"hello");
        assert_eq!(&buf[9..14], b"world");
    }

    #[test]
    fn test_length_packet_zero_length() {
        let len_bytes = 0u16.to_be_bytes();
        let mut cursor = Cursor::new(&len_bytes[..]);
        let mut reader = LengthPacketReader::new(&mut cursor);
        let result = reader.read_packet().unwrap();
        assert!(result.is_empty());
    }
}
