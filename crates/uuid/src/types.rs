use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fmt;

/// 16-byte UUID as used by VLESS protocol.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid(pub [u8; 16]);

impl Uuid {
    /// Generate a random v4 UUID.
    pub fn new_v4() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
        Uuid(bytes)
    }

    /// Create from raw bytes. Fails if length != 16.
    pub fn parse_bytes(b: &[u8]) -> Result<Self, ParseUuidError> {
        if b.len() != 16 {
            return Err(ParseUuidError::InvalidLength(b.len()));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(b);
        Ok(Uuid(out))
    }

    /// Parse from hex string with optional dashes.
    /// Falls back to SHA-256 hash for short names (following xray-core behavior).
    pub fn parse_string(s: &str) -> Result<Self, ParseUuidError> {
        let text = s.as_bytes();
        if text.len() < 32 || text.len() > 36 {
            if !text.is_empty() && text.len() <= 30 {
                return Self::from_short_name(s);
            }
            return Err(ParseUuidError::InvalidFormat(s.to_string()));
        }
        // Parse hex groups: 8-4-4-4-12
        let mut bytes = [0u8; 16];
        let mut pos = 0;
        let groups: [(usize, usize); 5] = [(8, 4), (4, 2), (4, 2), (4, 2), (12, 6)];
        let mut text = text;
        for (hex_len, byte_len) in groups {
            if !text.is_empty() && text[0] == b'-' {
                text = &text[1..];
            }
            if text.len() < hex_len {
                return Err(ParseUuidError::InvalidFormat(s.to_string()));
            }
            let hex_str = std::str::from_utf8(&text[..hex_len])
                .map_err(|_| ParseUuidError::InvalidFormat(s.to_string()))?;
            let decoded =
                hex::decode(hex_str).map_err(|_| ParseUuidError::InvalidFormat(s.to_string()))?;
            bytes[pos..pos + byte_len].copy_from_slice(&decoded);
            pos += byte_len;
            text = &text[hex_len..];
        }
        Ok(Uuid(bytes))
    }

    fn from_short_name(name: &str) -> Result<Self, ParseUuidError> {
        let mut hasher = Sha256::new();
        hasher.update([0u8; 16]); // null uuid as salt
        hasher.update(name.as_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x50; // version 5-ish
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
        Ok(Uuid(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Zero bytes 6 and 7 of the UUID — used for routing in VLESS.
/// This is how xray-core's `ProcessUUID` works.
pub fn process_uuid(id: &[u8; 16]) -> [u8; 16] {
    let mut out = *id;
    out[6] = 0;
    out[7] = 0;
    out
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5],
            self.0[6],
            self.0[7],
            self.0[8],
            self.0[9],
            self.0[10],
            self.0[11],
            self.0[12],
            self.0[13],
            self.0[14],
            self.0[15],
        )
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uuid({})", self)
    }
}

impl From<[u8; 16]> for Uuid {
    fn from(bytes: [u8; 16]) -> Self {
        Uuid(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseUuidError {
    InvalidLength(usize),
    InvalidFormat(String),
}

impl fmt::Display for ParseUuidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseUuidError::InvalidLength(l) => write!(f, "invalid UUID length: {}", l),
            ParseUuidError::InvalidFormat(s) => write!(f, "invalid UUID: {}", s),
        }
    }
}

impl std::error::Error for ParseUuidError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_v4_is_valid() {
        let u = Uuid::new_v4();
        assert_eq!(u.0[6] >> 4, 4, "version bits should be 4");
        assert_eq!(u.0[8] >> 6, 2, "variant bits should be 2");
    }

    #[test]
    fn test_parse_string_roundtrip() {
        let s = "12345678-1234-1234-1234-123456789abc";
        let u = Uuid::parse_string(s).unwrap();
        assert_eq!(u.to_string(), s);
    }

    #[test]
    fn test_parse_bytes_roundtrip() {
        let bytes = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let u = Uuid::parse_bytes(&bytes).unwrap();
        assert_eq!(u.as_bytes(), &bytes);
    }

    #[test]
    fn test_parse_bytes_invalid_length() {
        assert!(Uuid::parse_bytes(&[0; 15]).is_err());
        assert!(Uuid::parse_bytes(&[0; 17]).is_err());
    }

    #[test]
    fn test_short_name_fallback() {
        let u = Uuid::parse_string("myuser").unwrap();
        // Should produce a valid UUID string
        let s = u.to_string();
        assert!(s.len() == 36);
    }

    #[test]
    fn test_process_uuid_zeros_bytes_6_and_7() {
        let id = [0xff; 16];
        let processed = process_uuid(&id);
        assert_eq!(processed[6], 0);
        assert_eq!(processed[7], 0);
        assert_eq!(processed[0], 0xff);
        assert_eq!(processed[15], 0xff);
    }

    #[test]
    fn test_display_format() {
        let u = Uuid([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        assert_eq!(u.to_string(), "00112233-4455-6677-8899-aabbccddeeff");
    }
}
