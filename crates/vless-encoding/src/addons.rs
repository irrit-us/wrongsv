use bytes::{BufMut, BytesMut};
use prost::Message;
use thiserror::Error;

// Include the generated protobuf code. Module path must match proto package.
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/vless_encoding.rs"));
}

pub use pb::Addons;

#[derive(Debug, Error)]
pub enum AddonsError {
    #[error("failed to marshal addons: {0}")]
    Marshal(#[from] prost::EncodeError),
    #[error("failed to unmarshal addons: {0}")]
    Unmarshal(#[from] prost::DecodeError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Encode addons: 1 byte length prefix + protobuf bytes.
/// If addons has no flow (empty string), writes a single 0x00 byte.
pub fn encode_header_addons(buf: &mut BytesMut, addons: &Addons) -> Result<(), AddonsError> {
    if addons.flow.is_empty() {
        buf.put_u8(0);
        return Ok(());
    }
    let bytes = addons.encode_to_vec();
    buf.put_u8(bytes.len() as u8);
    buf.put_slice(&bytes);
    Ok(())
}

/// Decode addons from a reader. Reads 1 byte length, then that many bytes of proto.
pub fn decode_header_addons<R: std::io::Read>(reader: &mut R) -> Result<Addons, AddonsError> {
    let mut len_buf = [0u8; 1];
    reader.read_exact(&mut len_buf)?;
    let length = len_buf[0] as usize;
    if length == 0 {
        return Ok(Addons::default());
    }
    let mut proto_bytes = vec![0u8; length];
    reader.read_exact(&mut proto_bytes)?;
    let addons = Addons::decode(&proto_bytes[..])?;
    Ok(addons)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_roundtrip_empty_addons() {
        let addons = Addons::default();
        let mut buf = BytesMut::new();
        encode_header_addons(&mut buf, &addons).unwrap();
        assert_eq!(buf[0], 0);

        let mut cursor = Cursor::new(&buf[..]);
        let decoded = decode_header_addons(&mut cursor).unwrap();
        assert_eq!(decoded.flow, "");
    }

    #[test]
    fn test_roundtrip_flow() {
        let addons = Addons {
            flow: "xtls-rprx-vision".to_string(),
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        encode_header_addons(&mut buf, &addons).unwrap();

        let mut cursor = Cursor::new(&buf[..]);
        let decoded = decode_header_addons(&mut cursor).unwrap();
        assert_eq!(decoded.flow, "xtls-rprx-vision");
    }
}
