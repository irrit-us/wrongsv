/// TLS 1.3 record header handling for encrypted transport disguise.
///
/// The encryption layer wraps payload in TLS 1.3 application data records:
///   0x17 0x03 0x03 len_hi len_lo
///
/// This has nothing to do with actual TLS — it's purely a disguise to make
/// the encrypted bytes look like TLS traffic to passive observers.

/// Write a 5-byte TLS 1.3 application data record header.
pub fn encode_header(hdr: &mut [u8; 5], payload_len: usize) {
    hdr[0] = 0x17;
    hdr[1] = 0x03;
    hdr[2] = 0x03;
    hdr[3] = (payload_len >> 8) as u8;
    hdr[4] = payload_len as u8;
}

/// Decode a 5-byte header. Returns payload length, or error.
pub fn decode_header(hdr: &[u8; 5]) -> Result<usize, HeaderError> {
    if hdr[0] != 0x17 || hdr[1] != 0x03 || hdr[2] != 0x03 {
        return Err(HeaderError::InvalidMagic(hdr[0], hdr[1], hdr[2]));
    }
    let len = ((hdr[3] as usize) << 8) | (hdr[4] as usize);
    if len < 17 || len > 16640 {
        return Err(HeaderError::InvalidLength(len));
    }
    Ok(len)
}

#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    #[error("invalid TLS record header: {0:02x} {1:02x} {2:02x}")]
    InvalidMagic(u8, u8, u8),
    #[error("invalid TLS record length: {0}")]
    InvalidLength(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut hdr = [0u8; 5];
        encode_header(&mut hdr, 42);
        assert_eq!(hdr[0], 0x17);
        assert_eq!(hdr[1], 0x03);
        assert_eq!(hdr[2], 0x03);
        assert_eq!(decode_header(&hdr).unwrap(), 42);
    }

    #[test]
    fn test_decode_rejects_bad_magic() {
        let hdr = [0x16, 0x03, 0x03, 0x00, 0x20];
        assert!(decode_header(&hdr).is_err());
    }

    #[test]
    fn test_decode_rejects_bad_length() {
        let hdr = [0x17, 0x03, 0x03, 0x00, 0x01];
        assert!(decode_header(&hdr).is_err());
    }
}
