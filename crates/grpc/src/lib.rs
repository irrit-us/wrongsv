//! gRPC transport for VLESS — V2Ray-style gRPC carrier.
//!
//! ## Wire format
//!
//! The V2Ray gRPC transport wraps VLESS data in the gRPC wire protocol
//! over HTTP/2. Each gRPC message is a Hunk protobuf frame with a
//! 5-byte gRPC header:
//!
//! ```text
//! 1 byte  compression flag (0 = uncompressed)
//! 4 bytes payload length (big-endian)
//! N bytes protobuf-encoded Hunk { data: bytes }
//! ```
//!
//! ## HTTP/2 bridging
//!
//! The `GrpcStream` type bridges between the sync VLESS relay code and
//! the async HTTP/2 layer (h2 crate). It uses a small tokio runtime
//! per connection to drive the HTTP/2 state machine, then exchanges
//! gRPC Hunk frames through `std::sync::mpsc` channels.

use std::io::Write;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use prost::Message;

// Include the generated protobuf code.
pub mod gun {
    include!(concat!(env!("OUT_DIR"), "/gun.rs"));
}

pub use gun::Hunk;

const GRPC_HEADER_SIZE: usize = 5; // 1B compression + 4B length

/// Encode a VLESS data payload into a single gRPC Hunk frame.
///
/// Returns the wire-format bytes: 5-byte gRPC header + protobuf Hunk.
pub fn encode_hunk_frame(data: &[u8]) -> Bytes {
    let hunk = Hunk {
        data: data.to_vec(),
    };
    // gRPC header: 1 byte compression flag (0) + 4 bytes length BE
    let proto_len = hunk.encoded_len();
    let mut frame = BytesMut::with_capacity(GRPC_HEADER_SIZE + proto_len);
    frame.put_u8(0); // no compression
    frame.put_u32(proto_len as u32);
    hunk.encode(&mut frame)
        .expect("Hunk encode should not fail");
    frame.freeze()
}

/// Decode one gRPC Hunk frame from a buffer.
///
/// Returns `Some(data)` on success. Returns `None` if the buffer doesn't
/// contain a complete frame yet. Returns `Err` on invalid data.
pub fn decode_hunk_frame(buf: &mut BytesMut) -> Result<Option<Vec<u8>>, GrpcError> {
    if buf.len() < GRPC_HEADER_SIZE {
        return Ok(None);
    }

    let compression = buf[0];
    if compression != 0 {
        return Err(GrpcError::CompressionNotSupported(compression));
    }

    let payload_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if buf.len() < GRPC_HEADER_SIZE + payload_len {
        return Ok(None);
    }

    // Advance past the header
    buf.advance(GRPC_HEADER_SIZE);
    let proto_bytes = buf.split_to(payload_len);

    let hunk = Hunk::decode(proto_bytes).map_err(GrpcError::ProtoDecode)?;
    Ok(Some(hunk.data))
}

/// Stream-oriented gRPC frame reader.
///
/// Reads gRPC Hunk frames from an underlying byte stream (e.g. HTTP/2
/// body or raw TCP after HTTP/2 handoff). Handles partial reads and
/// frame reassembly.
pub struct GrpcFrameReader {
    buf: BytesMut,
}

impl GrpcFrameReader {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::with_capacity(65536),
        }
    }

    /// Feed raw bytes into the reader and try to extract a complete
    /// gRPC Hunk frame. Returns `Some(data)` when a frame is decoded,
    /// `None` when more data is needed.
    pub fn feed(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, GrpcError> {
        self.buf.extend_from_slice(data);
        decode_hunk_frame(&mut self.buf)
    }

    /// Pending data that hasn't been decoded into a frame yet.
    pub fn pending(&self) -> &[u8] {
        &self.buf
    }

    /// Clear the internal buffer.
    pub fn clear(&mut self) {
        self.buf.clear();
    }
}

impl Default for GrpcFrameReader {
    fn default() -> Self {
        Self::new()
    }
}

/// Stream-oriented gRPC frame writer.
///
/// Wraps gRPC Hunk frames and writes them to an underlying byte sink.
pub struct GrpcFrameWriter<W: Write> {
    inner: W,
}

impl<W: Write> GrpcFrameWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Write VLESS data as a gRPC Hunk frame.
    pub fn write_frame(&mut self, data: &[u8]) -> std::io::Result<()> {
        let frame = encode_hunk_frame(data);
        self.inner.write_all(&frame)?;
        self.inner.flush()
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// gRPC transport errors.
#[derive(Debug, thiserror::Error)]
pub enum GrpcError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protobuf decode error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("compression algorithm {0} not supported (only 0=none)")]
    CompressionNotSupported(u8),
    #[error("HTTP/2 error: {0}")]
    H2(String),
    #[error("gRPC stream closed by peer")]
    StreamClosed,
    #[error("invalid gRPC frame: {0}")]
    InvalidFrame(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let payload = b"hello gRPC";
        let frame = encode_hunk_frame(payload);

        let mut buf = BytesMut::from(frame.as_ref());
        let decoded = decode_hunk_frame(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn decode_needs_more_data() {
        let mut buf = BytesMut::from(&b"\x00\x00\x00\x00\x10"[..3]);
        assert!(decode_hunk_frame(&mut buf).unwrap().is_none());
    }

    #[test]
    fn reader_streaming() {
        let mut reader = GrpcFrameReader::new();
        let payload = b"streaming test payload";

        // Send header partial, then rest
        let frame = encode_hunk_frame(payload);
        assert!(reader.feed(&frame[..3]).unwrap().is_none());
        let result = reader.feed(&frame[3..]).unwrap().unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn writer_flushes() {
        let mut buf = Vec::new();
        {
            let mut writer = GrpcFrameWriter::new(&mut buf);
            writer.write_frame(b"test").unwrap();
        }
        // Verify it's a valid frame
        let mut b = BytesMut::from(buf.as_slice());
        let decoded = decode_hunk_frame(&mut b).unwrap().unwrap();
        assert_eq!(decoded, b"test");
    }

    #[test]
    fn rejected_compression() {
        let mut buf = BytesMut::new();
        buf.put_u8(1); // gzip compression — not supported
        buf.put_u32(10);
        buf.extend_from_slice(b"0123456789");
        let err = decode_hunk_frame(&mut buf).unwrap_err();
        assert!(matches!(err, GrpcError::CompressionNotSupported(1)));
    }
}
