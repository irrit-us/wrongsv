//! RFC 6455 WebSocket frame encoding and decoding.
//!
//! We only use binary frames (opcode 0x02) for data. Client-to-server frames
//! MUST be masked; server-to-client frames MUST NOT be masked.

use std::io::{Read, Result as IoResult, Write};

/// Maximum frame payload size we accept (256 KiB).
pub const MAX_FRAME_SIZE: usize = 256 * 1024;

/// Maximum control frame payload (125 bytes per RFC 6455 §5.5).
const MAX_CTRL_PAYLOAD: usize = 125;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Text = 0x01,
    Binary = 0x02,
    Close = 0x08,
    Ping = 0x09,
    Pong = 0x0A,
}

impl Opcode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Opcode::Text),
            0x02 => Some(Opcode::Binary),
            0x08 => Some(Opcode::Close),
            0x09 => Some(Opcode::Ping),
            0x0A => Some(Opcode::Pong),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Frame {
    pub fin: bool,
    pub opcode: Opcode,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid opcode: {0:#04x}")]
    InvalidOpcode(u8),
    #[error("frame payload exceeds maximum ({0} > {MAX_FRAME_SIZE})")]
    PayloadTooLarge(usize),
    #[error("control frame payload exceeds 125 bytes ({0})")]
    ControlPayloadTooLarge(usize),
    #[error("client frame not masked (RFC 6455 §5.1)")]
    NotMasked,
    #[error("UTF-8 validation error in text frame")]
    Utf8Error,
}

/// Read a single WebSocket frame from a reader.
///
/// If `require_masked` is true (server reading client frames), frames without
/// the MASK bit set are rejected.
pub fn read_frame<R: Read>(reader: &mut R, require_masked: bool) -> Result<Frame, FrameError> {
    // Byte 0: FIN (bit 7) + RSV (6-4) + opcode (3-0)
    let mut head = [0u8; 2];
    read_exact(reader, &mut head)?;
    let fin = (head[0] & 0x80) != 0;
    let opcode =
        Opcode::from_u8(head[0] & 0x0F).ok_or(FrameError::InvalidOpcode(head[0] & 0x0F))?;

    // Byte 1: MASK (bit 7) + payload length (6-0)
    let masked = (head[1] & 0x80) != 0;
    let mut payload_len = (head[1] & 0x7F) as u64;

    // Extended payload length
    if payload_len == 126 {
        let mut ext = [0u8; 2];
        read_exact(reader, &mut ext)?;
        payload_len = u16::from_be_bytes(ext) as u64;
    } else if payload_len == 127 {
        let mut ext = [0u8; 8];
        read_exact(reader, &mut ext)?;
        payload_len = u64::from_be_bytes(ext);
    }

    // Size check
    if payload_len > MAX_FRAME_SIZE as u64 {
        return Err(FrameError::PayloadTooLarge(payload_len as usize));
    }

    // Control frames must have payload ≤ 125
    if opcode != Opcode::Binary && opcode != Opcode::Text && payload_len > MAX_CTRL_PAYLOAD as u64 {
        return Err(FrameError::ControlPayloadTooLarge(payload_len as usize));
    }

    // Mask enforcement for server
    if require_masked && !masked {
        return Err(FrameError::NotMasked);
    }

    // Read mask key (if present)
    let mask_key: Option<[u8; 4]> = if masked {
        let mut mk = [0u8; 4];
        read_exact(reader, &mut mk)?;
        Some(mk)
    } else {
        None
    };

    // Read payload
    let mut payload = vec![0u8; payload_len as usize];
    if payload_len > 0 {
        read_exact(reader, &mut payload)?;
    }

    // Unmask
    if let Some(mk) = mask_key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mk[i % 4];
        }
    }

    Ok(Frame {
        fin,
        opcode,
        payload,
    })
}

/// Write a WebSocket frame to a writer.
///
/// If `masked` is true, a random 4-byte mask key is generated and applied.
pub fn write_frame<W: Write>(
    writer: &mut W,
    frame: &Frame,
    masked: bool,
) -> Result<(), FrameError> {
    let mut header = Vec::with_capacity(14);

    // Byte 0: FIN + opcode
    header.push((if frame.fin { 0x80 } else { 0x00 }) | (frame.opcode as u8));

    // Byte 1+: MASK + length
    let len = frame.payload.len();
    let mask_byte: u8 = if masked { 0x80 } else { 0x00 };
    if len < 126 {
        header.push(mask_byte | (len as u8));
    } else if len <= u16::MAX as usize {
        header.push(mask_byte | 126);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(mask_byte | 127);
        header.extend_from_slice(&(len as u64).to_be_bytes());
    }

    // Mask key
    let mask_key: Option<[u8; 4]> = if masked {
        let mk: [u8; 4] = rand::random();
        header.extend_from_slice(&mk);
        Some(mk)
    } else {
        None
    };

    writer.write_all(&header)?;

    // Payload (possibly masked)
    if let Some(mk) = mask_key {
        let masked_payload: Vec<u8> = frame
            .payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mk[i % 4])
            .collect();
        writer.write_all(&masked_payload)?;
    } else if !frame.payload.is_empty() {
        writer.write_all(&frame.payload)?;
    }

    Ok(())
}

/// Convenience: write binary data as a single FIN WebSocket frame (server → client).
pub fn write_binary<W: Write>(writer: &mut W, data: &[u8]) -> Result<(), FrameError> {
    write_frame(
        writer,
        &Frame {
            fin: true,
            opcode: Opcode::Binary,
            payload: data.to_vec(),
        },
        false, // server → client: never masked
    )
}

pub fn write_ping<W: Write>(writer: &mut W, data: &[u8]) -> Result<(), FrameError> {
    if data.len() > MAX_CTRL_PAYLOAD {
        return Err(FrameError::ControlPayloadTooLarge(data.len()));
    }
    write_frame(
        writer,
        &Frame {
            fin: true,
            opcode: Opcode::Ping,
            payload: data.to_vec(),
        },
        false,
    )
}

pub fn write_pong<W: Write>(writer: &mut W, data: &[u8]) -> Result<(), FrameError> {
    if data.len() > MAX_CTRL_PAYLOAD {
        return Err(FrameError::ControlPayloadTooLarge(data.len()));
    }
    write_frame(
        writer,
        &Frame {
            fin: true,
            opcode: Opcode::Pong,
            payload: data.to_vec(),
        },
        false,
    )
}

pub fn write_close<W: Write>(writer: &mut W, code: u16) -> Result<(), FrameError> {
    let payload = code.to_be_bytes().to_vec();
    write_frame(
        writer,
        &Frame {
            fin: true,
            opcode: Opcode::Close,
            payload,
        },
        false,
    )
}

/// Read exactly `buf.len()` bytes, returning an error on short reads.
fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> IoResult<()> {
    let mut offset = 0;
    while offset < buf.len() {
        match reader.read(&mut buf[offset..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated WebSocket frame",
                ));
            }
            Ok(n) => offset += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_binary_unmasked() {
        let payload = b"hello websocket";
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &Frame {
                fin: true,
                opcode: Opcode::Binary,
                payload: payload.to_vec(),
            },
            false,
        )
        .unwrap();

        let frame = read_frame(&mut Cursor::new(buf), false).unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, Opcode::Binary);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn roundtrip_binary_masked() {
        let payload = vec![42u8; 256];
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &Frame {
                fin: true,
                opcode: Opcode::Binary,
                payload: payload.clone(),
            },
            true, // masked
        )
        .unwrap();

        let frame = read_frame(&mut Cursor::new(buf), false).unwrap();
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn read_rejects_unmasked_client_frame() {
        let payload = b"unmasked";
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &Frame {
                fin: true,
                opcode: Opcode::Binary,
                payload: payload.to_vec(),
            },
            false, // not masked
        )
        .unwrap();

        let err = read_frame(&mut Cursor::new(buf), true).unwrap_err(); // require masked
        assert!(matches!(err, FrameError::NotMasked));
    }

    #[test]
    fn read_accepts_masked_client_frame() {
        let payload = b"masked";
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &Frame {
                fin: true,
                opcode: Opcode::Binary,
                payload: payload.to_vec(),
            },
            true,
        )
        .unwrap();

        let frame = read_frame(&mut Cursor::new(buf), true).unwrap();
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn ping_pong_close() {
        // Ping
        let mut buf = Vec::new();
        write_ping(&mut buf, b"are you there?").unwrap();
        let frame = read_frame(&mut Cursor::new(buf), false).unwrap();
        assert_eq!(frame.opcode, Opcode::Ping);
        assert_eq!(frame.payload, b"are you there?");

        // Pong
        let mut buf = Vec::new();
        write_pong(&mut buf, b"yes").unwrap();
        let frame = read_frame(&mut Cursor::new(buf), false).unwrap();
        assert_eq!(frame.opcode, Opcode::Pong);
        assert_eq!(frame.payload, b"yes");

        // Close
        let mut buf = Vec::new();
        write_close(&mut buf, 1000).unwrap();
        let frame = read_frame(&mut Cursor::new(buf), false).unwrap();
        assert_eq!(frame.opcode, Opcode::Close);
        assert_eq!(frame.payload, 1000u16.to_be_bytes());
    }

    #[test]
    fn payload_126_boundary() {
        let payload = vec![0u8; 126];
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &Frame {
                fin: true,
                opcode: Opcode::Binary,
                payload: payload.clone(),
            },
            false,
        )
        .unwrap();
        let frame = read_frame(&mut Cursor::new(buf), false).unwrap();
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn payload_65536() {
        let payload = vec![0xABu8; 65536];
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &Frame {
                fin: true,
                opcode: Opcode::Binary,
                payload: payload.clone(),
            },
            false,
        )
        .unwrap();
        let frame = read_frame(&mut Cursor::new(buf), false).unwrap();
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn control_payload_too_large() {
        let data = vec![0u8; 126];
        let err = write_ping(&mut Vec::new(), &data).unwrap_err();
        assert!(matches!(err, FrameError::ControlPayloadTooLarge(126)));
    }

    #[test]
    fn reject_oversized_frame() {
        // We can't actually write a frame > MAX_FRAME_SIZE because write_frame
        // would alloc the vec, but we can test the read path.
        // Simulate a header claiming huge length:
        let mut header = Vec::new();
        header.push(0x82); // FIN + Binary
        header.push(0x7F); // MASK=0, len=127 (8-byte extended)
        let huge: u64 = (MAX_FRAME_SIZE + 1) as u64;
        header.extend_from_slice(&huge.to_be_bytes());

        let err = read_frame(&mut Cursor::new(header), false).unwrap_err();
        assert!(matches!(err, FrameError::PayloadTooLarge(_)));
    }
}
