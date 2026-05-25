//! TLS 1.3 ClientHello parser.
//!
//! Extracts the fields REALITY needs: random (32 bytes), session_id,
//! and the client's ephemeral X25519 public key from the key_share extension.

use crate::RealityError;

/// Wire-format positions in a TLS ClientHello record.
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_CLIENT_HELLO: u8 = 0x01;
const EXT_KEY_SHARE: u16 = 0x0033;
const NAMED_GROUP_X25519: u16 = 0x001D;

#[derive(Debug)]
pub struct ParsedClientHello {
    /// Full raw ClientHello handshake body (from handshake type through extensions).
    /// Used as AAD in the REALITY auth AEAD.
    pub raw_body: Vec<u8>,
    /// The 32-byte random from ClientHello.
    pub random: [u8; 32],
    /// The 32-byte session_id (REALITY auth payload).
    pub session_id: [u8; 32],
    /// Client's ephemeral X25519 public key from key_share extension.
    pub key_share: [u8; 32],
}

/// Parse a buffered TLS record into a `ParsedClientHello`.
///
/// `buf` must contain at least the TLS record header + full ClientHello
/// (typically the first ~512–2048 bytes of the connection).
pub fn parse_client_hello(buf: &[u8]) -> Result<ParsedClientHello, RealityError> {
    if buf.len() < 5 {
        return Err(RealityError::TlsParse("buffer too short for TLS record header".into()));
    }
    if buf[0] != TLS_HANDSHAKE {
        return Err(RealityError::TlsParse(format!(
            "expected TLS handshake (0x16), got 0x{:02x}", buf[0]
        )));
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return Err(RealityError::TlsParse(format!(
            "buffer too short for TLS record: need {}, got {}", 5 + record_len, buf.len()
        )));
    }

    // Handshake header starts at buf[5]
    let hs = &buf[5..];
    if hs.len() < 4 {
        return Err(RealityError::TlsParse("buffer too short for handshake header".into()));
    }
    if hs[0] != TLS_CLIENT_HELLO {
        return Err(RealityError::TlsParse(format!(
            "expected ClientHello (0x01), got 0x{:02x}", hs[0]
        )));
    }
    let hs_len = u24_be(&hs[1..4]) as usize;
    let body_end = 4 + hs_len;
    if hs.len() < body_end {
        return Err(RealityError::TlsParse(format!(
            "buffer too short for handshake body: need {}, got {}", body_end, hs.len()
        )));
    }

    let body = &hs[..body_end];
    // body: handshake_type(1) + len(3) + client_version(2) + random(32) + ...
    if body.len() < 38 {
        return Err(RealityError::TlsParse("ClientHello body too short".into()));
    }

    // random is at offset 6 within handshake message
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[6..38]);

    // session_id at offset 38: length(1) + data(variable)
    if body.len() < 39 {
        return Err(RealityError::TlsParse("no session_id length byte".into()));
    }
    let sid_len = body[38] as usize;
    if sid_len != 32 {
        return Err(RealityError::TlsParse(format!(
            "REALITY requires 32-byte session_id, got {sid_len}"
        )));
    }
    if body.len() < 39 + sid_len {
        return Err(RealityError::TlsParse("session_id truncated".into()));
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&body[39..39 + 32]);

    // Scan extensions for key_share (0x0033)
    let extensions_start = 39 + sid_len // after session_id
        + 2 // cipher_suites length
        + u16::be_bytes_to_usize(&body[39 + sid_len..39 + sid_len + 2]) // cipher_suites data
        + 1 // compression_methods length (always 1 byte)
        + 1; // null compression method
    if extensions_start + 2 > body.len() {
        return Err(RealityError::TlsParse("extensions truncated".into()));
    }
    let ext_len = u16::from_be_bytes([body[extensions_start], body[extensions_start + 1]]) as usize;
    let ext_data = &body[extensions_start + 2..];
    let ext_end = ext_len.min(ext_data.len());

    let key_share = parse_key_share_ext(ext_data, ext_end)?;

    Ok(ParsedClientHello {
        raw_body: body.to_vec(),
        random,
        session_id,
        key_share,
    })
}

/// Find the X25519 key_share entry in TLS extensions.
fn parse_key_share_ext(ext_data: &[u8], ext_end: usize) -> Result<[u8; 32], RealityError> {
    let mut pos = 0;
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([ext_data[pos], ext_data[pos + 1]]);
        let ext_len = u16::from_be_bytes([ext_data[pos + 2], ext_data[pos + 3]]) as usize;
        pos += 4;

        if ext_type == EXT_KEY_SHARE {
            // key_share extension: KeyShareClientHello
            // [0..2]: client_shares length
            if pos + 2 > ext_end {
                break;
            }
            let shares_end = pos + u16::be_bytes_to_usize(&ext_data[pos..pos + 2]);
            pos += 2;

            // Scan key share entries
            while pos + 4 <= ext_end && pos + 4 <= shares_end {
                let group = u16::from_be_bytes([ext_data[pos], ext_data[pos + 1]]);
                let ke_len = u16::from_be_bytes([ext_data[pos + 2], ext_data[pos + 3]]) as usize;
                pos += 4;

                if group == NAMED_GROUP_X25519 && ke_len == 32 {
                    if pos + 32 > ext_end {
                        break;
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&ext_data[pos..pos + 32]);
                    return Ok(key);
                }
                pos += ke_len;
            }
            return Err(RealityError::TlsParse(
                "X25519 key_share not found in extension".into(),
            ));
        }
        pos += ext_len;
    }
    Err(RealityError::TlsParse("key_share extension (0x0033) not found".into()))
}

fn u24_be(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32)
}

trait U16Ext {
    fn be_bytes_to_usize(bytes: &[u8]) -> usize;
}

impl U16Ext for u16 {
    fn be_bytes_to_usize(bytes: &[u8]) -> usize {
        u16::from_be_bytes([bytes[0], bytes[1]]) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS 1.3 ClientHello with a 32-byte session_id and X25519 key_share.
    fn build_client_hello(random: [u8; 32], session_id: [u8; 32], key_share: [u8; 32]) -> Vec<u8> {
        let mut body = Vec::new();
        // handshake type + length placeholder
        body.push(TLS_CLIENT_HELLO);
        body.extend_from_slice(&[0x00, 0x00, 0x00]); // length, filled later
        // client version (TLS 1.2 compat)
        body.extend_from_slice(&[0x03, 0x03]);
        // random
        body.extend_from_slice(&random);
        // session_id
        body.push(32);
        body.extend_from_slice(&session_id);
        // cipher_suites: one suite (TLS_AES_128_GCM_SHA256 = 0x1301)
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        // compression: null
        body.extend_from_slice(&[0x01, 0x00]);

        // extensions: key_share only
        // key_share entry: group(2) + ke_len(2) + ke_data(32) = 36 bytes
        // key_share ext: client_shares_len(2) + entries = 38 bytes
        // extension: type(2) + len(2) + data = 42 bytes
        let mut ext_data = Vec::new();
        // key_share extension type
        ext_data.extend_from_slice(&0x0033u16.to_be_bytes());
        // extension length: 38 (2 + 36)
        ext_data.extend_from_slice(&38u16.to_be_bytes());
        // client_shares length
        ext_data.extend_from_slice(&36u16.to_be_bytes());
        // entry: X25519
        ext_data.extend_from_slice(&NAMED_GROUP_X25519.to_be_bytes());
        // key length
        ext_data.extend_from_slice(&32u16.to_be_bytes());
        // key data
        ext_data.extend_from_slice(&key_share);

        body.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_data);

        // Fill in handshake length
        let hs_len = (body.len() - 4) as u32;
        body[1] = (hs_len >> 16) as u8;
        body[2] = (hs_len >> 8) as u8;
        body[3] = hs_len as u8;

        // Wrap in TLS record
        let mut record = Vec::new();
        record.push(TLS_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);

        record
    }

    #[test]
    fn test_parse_roundtrip() {
        let random = [0xAAu8; 32];
        let session_id = {
            let mut s = [0u8; 32];
            s[0..3].copy_from_slice(&[1, 2, 3]); // version
            s[3] = 0;
            s[4..8].copy_from_slice(&0x12345678u32.to_be_bytes()); // timestamp
            s[8..16].copy_from_slice(b"shortid!"); // shortId
            s
        };
        let key_share = [0xBBu8; 32];

        let record = build_client_hello(random, session_id, key_share);
        let parsed = parse_client_hello(&record).unwrap();

        assert_eq!(parsed.random, random);
        assert_eq!(parsed.session_id, session_id);
        assert_eq!(parsed.key_share, key_share);
    }

    #[test]
    fn test_parse_rejects_short_buffer() {
        assert!(parse_client_hello(&[0u8; 3]).is_err());
    }

    #[test]
    fn test_parse_rejects_non_handshake() {
        let mut buf = vec![0u8; 100];
        buf[0] = 0x17; // application data, not handshake
        assert!(parse_client_hello(&buf).is_err());
    }

    #[test]
    fn test_parse_rejects_wrong_session_id_len() {
        let random = [0xAAu8; 32];
        let mut sid = [0u8; 32];
        sid[0..3].copy_from_slice(&[1, 2, 3]);
        let key_share = [0xBBu8; 32];

        // Build with 32-byte sid, then tamper the length byte
        let mut record = build_client_hello(random, sid, key_share);
        // session_id_len is at record[5+4+2+32] = record[43]
        record[43] = 16; // change from 32 to 16
        assert!(parse_client_hello(&record).is_err());
    }
}
