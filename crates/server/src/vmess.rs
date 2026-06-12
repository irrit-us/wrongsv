//! VMess AEAD protocol — encrypted proxy with UUID-based authentication.
//!
//! Implements the VMess AEAD protocol (v2ray-core v4.28.1+) with
//! AES-128-GCM body encryption and TCP CONNECT command support.
//!
//! ## Protocol flow
//!
//! ```text
//! Client → Server:  EAuID (16 bytes, AES-128-ECB encrypted auth block)
//! Client → Server:  HeaderLen (2 bytes BE) + HeaderCiphertext
//! Client ⇄ Server:  Chunked AEAD body (bidirectional)
//! ```
//!
//! ## Key derivation
//!
//! `cmd_key = HMAC-SHA256("VMess AEAD KDF", user_uuid_bytes)[:16]`
//!
//! Client-side functions are used by wrongsv-evaluator-client.
#![allow(dead_code)]

use std::io::{self, Read, Write};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes_gcm::{AeadInPlace, Key};
use sha2::{Digest, Sha256};

use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

// ── Constants ─────────────────────────────────────────────────────────

/// AES-GCM tag length (16 bytes per chunk)
const GCM_TAG_LEN: usize = 16;

/// EAuID plaintext size: timestamp(8) + random(4) + crc32(4)
const EAUID_PLAINTEXT_LEN: usize = 16;

/// Header instruction minimum size (before variable-length address)
const HEADER_INSTRUCTION_MIN_LEN: usize = 42;

/// Maximum body chunk payload size
const MAX_CHUNK_PAYLOAD: usize = 16384;

/// Maximum clock skew for EAuID timestamp validation (seconds)
const MAX_CLOCK_SKEW: u64 = 120;

// ── Error ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum VmessError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("VMess authentication failed: {0}")]
    AuthFailed(String),
    #[error("VMess invalid command: 0x{0:02x}")]
    InvalidCommand(u8),
    #[error("VMess invalid address type: 0x{0:02x}")]
    InvalidAddressType(u8),
    #[error("VMess unsupported body cipher")]
    UnsupportedBodyCipher,
    #[error("VMess protocol error: {0}")]
    Protocol(String),
}

// ── KDF ───────────────────────────────────────────────────────────────

/// Derive the 16-byte command key from a user UUID.
pub fn derive_cmd_key(uuid_bytes: &[u8; 16]) -> [u8; 16] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(b"VMess AEAD KDF").expect("HMAC-SHA256 should init");
    mac.update(uuid_bytes);
    let result = mac.finalize();
    let full: [u8; 32] = result.into_bytes().into();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Derive the 16-byte response key from the command key.
pub fn derive_response_key(cmd_key: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(cmd_key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

// ── CRC32 (IEEE 802.3) ────────────────────────────────────────────────

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffffffff;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xedb88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ── EAuID ─────────────────────────────────────────────────────────────

/// Generate an EAuID (Encrypted Authentication ID).
///
/// ```text
/// plaintext = timestamp(8 bytes BE) || random(4 bytes) || CRC32(12 bytes)
/// eaudid = AES-128-ECB(cmd_key, plaintext)
/// ```
pub fn generate_eaudid(
    cmd_key: &[u8; 16],
) -> ([u8; EAUID_PLAINTEXT_LEN], [u8; EAUID_PLAINTEXT_LEN]) {
    use rand::RngCore;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut plaintext = [0u8; EAUID_PLAINTEXT_LEN];
    plaintext[..8].copy_from_slice(&now.to_be_bytes());
    rand::rngs::OsRng.fill_bytes(&mut plaintext[8..12]);
    let crc = crc32_ieee(&plaintext[..12]);
    plaintext[12..16].copy_from_slice(&crc.to_be_bytes());

    let cipher = aes::Aes128::new_from_slice(cmd_key).expect("AES-128 key is 16 bytes");
    let mut block: [u8; 16] = plaintext;
    cipher.encrypt_block((&mut block).into());

    (plaintext, block)
}

/// Verify an EAuID and return the embedded timestamp.
pub fn verify_eaudid(
    cmd_key: &[u8; 16],
    eaudid: &[u8; EAUID_PLAINTEXT_LEN],
) -> Result<u64, VmessError> {
    let cipher = aes::Aes128::new_from_slice(cmd_key).expect("AES-128 key is 16 bytes");
    let mut plaintext: [u8; 16] = *eaudid;
    cipher.decrypt_block((&mut plaintext).into());

    // Verify CRC32
    let expected_crc =
        u32::from_be_bytes([plaintext[12], plaintext[13], plaintext[14], plaintext[15]]);
    let computed_crc = crc32_ieee(&plaintext[..12]);
    if expected_crc != computed_crc {
        return Err(VmessError::AuthFailed("CRC32 mismatch".into()));
    }

    // Check timestamp
    let ts = u64::from_be_bytes([
        plaintext[0],
        plaintext[1],
        plaintext[2],
        plaintext[3],
        plaintext[4],
        plaintext[5],
        plaintext[6],
        plaintext[7],
    ]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let skew = ts.abs_diff(now);
    if skew > MAX_CLOCK_SKEW {
        return Err(VmessError::AuthFailed(format!(
            "timestamp skew too large: {skew}s (max {MAX_CLOCK_SKEW}s)"
        )));
    }

    Ok(ts)
}

// ── VMess Request ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VmessRequest {
    pub command: VmessCommand,
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessCommand {
    Tcp = 0x01,
    Udp = 0x02,
}

impl VmessCommand {
    fn from_byte(b: u8) -> Result<Self, VmessError> {
        match b {
            0x01 => Ok(Self::Tcp),
            0x02 => Ok(Self::Udp),
            other => Err(VmessError::InvalidCommand(other)),
        }
    }
}

// ── Header ────────────────────────────────────────────────────────────

/// Decrypted VMess header instruction section.
#[derive(Debug)]
pub struct VmessHeaderInstruction {
    pub body_iv: [u8; 16],
    pub body_key: [u8; 16],
    pub command: VmessCommand,
    pub address: String,
    pub port: u16,
}

/// Options byte bit flags
pub const OPTION_CHACHA20_POLY1305: u8 = 0x02;

/// Build and encrypt a VMess header.
///
/// Returns `(header_len, header_payload)` where `header_payload = nonce || ciphertext`.
pub fn build_header(
    cmd_key: &[u8; 16],
    eaudid: &[u8; 16],
    body_key: &[u8; 16],
    body_iv: &[u8; 16],
    request: &VmessRequest,
) -> Result<(u16, Vec<u8>), VmessError> {
    // Build instruction plaintext
    let addr_bytes = encode_address(&request.address);
    let padding_len = rand::random::<u8>() & 0x1f; // 0..31 bytes
    let instr_len = HEADER_INSTRUCTION_MIN_LEN + addr_bytes.len() + padding_len as usize;
    let mut instruction = Vec::with_capacity(instr_len);

    instruction.push(0x01); // version
    instruction.extend_from_slice(body_iv);
    instruction.extend_from_slice(body_key);
    instruction.push(request.response_auth_v()); // response_auth_v
    instruction.push(0x01); // options (AES-128-GCM standard)
    instruction.push(padding_len); // padding length
    instruction.push(0x00); // reserved
    instruction.push(request.command as u8);
    instruction.extend_from_slice(&request.port.to_be_bytes());
    instruction.extend_from_slice(&addr_bytes);
    // padding
    for _ in 0..padding_len {
        instruction.push(rand::random::<u8>());
    }

    // Generate nonce
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    // Encrypt with AES-128-GCM
    let key = Key::<aes_gcm::Aes128Gcm>::from_slice(cmd_key);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let cipher = aes_gcm::Aes128Gcm::new(key);
    let mut ciphertext = instruction.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, eaudid, &mut ciphertext)
        .map_err(|e| VmessError::Protocol(format!("header encrypt: {e}")))?;

    let mut payload = nonce_bytes.to_vec();
    payload.append(&mut ciphertext);
    payload.extend_from_slice(tag.as_slice());

    let total_len = payload.len() as u16;
    Ok((total_len, payload))
}

/// Decrypt and parse a VMess header.
pub fn decrypt_header(
    cmd_key: &[u8; 16],
    eaudid: &[u8; 16],
    header_payload: &[u8],
) -> Result<VmessHeaderInstruction, VmessError> {
    if header_payload.len() < 28 {
        // 12 (nonce) + 1 (min instruction) + 16 (tag)
        return Err(VmessError::Protocol("header too short".into()));
    }

    let nonce_bytes: &[u8; 12] = header_payload[..12].try_into().unwrap();
    let ciphertext_with_tag = &header_payload[12..];

    let key = Key::<aes_gcm::Aes128Gcm>::from_slice(cmd_key);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let cipher = aes_gcm::Aes128Gcm::new(key);

    // Split ciphertext and tag
    let tag_len = GCM_TAG_LEN;
    if ciphertext_with_tag.len() < tag_len + 1 {
        return Err(VmessError::Protocol("header ciphertext too short".into()));
    }
    let ct_len = ciphertext_with_tag.len() - tag_len;
    let mut plaintext = ciphertext_with_tag[..ct_len].to_vec();
    let tag = aes_gcm::Tag::from_slice(&ciphertext_with_tag[ct_len..]);

    cipher
        .decrypt_in_place_detached(nonce, eaudid, &mut plaintext, tag)
        .map_err(|e| VmessError::AuthFailed(format!("header decrypt: {e}")))?;

    parse_instruction(&plaintext)
}

fn parse_instruction(data: &[u8]) -> Result<VmessHeaderInstruction, VmessError> {
    if data.len() < HEADER_INSTRUCTION_MIN_LEN {
        return Err(VmessError::Protocol("instruction too short".into()));
    }

    let version = data[0];
    if version != 1 {
        return Err(VmessError::Protocol(format!(
            "unsupported version: {version}"
        )));
    }

    let body_iv: [u8; 16] = data[1..17].try_into().unwrap();
    let body_key: [u8; 16] = data[17..33].try_into().unwrap();
    let options = data[34];
    let padding_len = data[35] as usize;

    // Reject ChaCha20-Poly1305 for now
    if options & OPTION_CHACHA20_POLY1305 != 0 {
        return Err(VmessError::UnsupportedBodyCipher);
    }

    // reserved = data[36]
    let command = VmessCommand::from_byte(data[37])?;
    let port = u16::from_be_bytes([data[38], data[39]]);
    let addr_type = data[40];
    let addr_start = 41;
    let addr_end = data.len().saturating_sub(padding_len);

    if addr_start >= addr_end {
        return Err(VmessError::InvalidAddressType(addr_type));
    }

    let address = decode_address(&data[addr_start..addr_end], addr_type)?;

    Ok(VmessHeaderInstruction {
        body_iv,
        body_key,
        command,
        address,
        port,
    })
}

impl VmessRequest {
    fn response_auth_v(&self) -> u8 {
        0x01
    }
}

// ── Address encoding ──────────────────────────────────────────────────

/// Encode an address string to wire format.
/// Returns: `addr_type_byte || address_bytes`
fn encode_address(addr: &str) -> Vec<u8> {
    // Try IPv4
    if let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
        let mut out = vec![0x01];
        out.extend_from_slice(&ip.octets());
        return out;
    }
    // Try IPv6
    if let Ok(ip) = addr.parse::<std::net::Ipv6Addr>() {
        let mut out = vec![0x03];
        out.extend_from_slice(&ip.octets());
        return out;
    }
    // Domain
    let domain = addr.as_bytes();
    let domain_len = if domain.len() > 255 {
        255
    } else {
        domain.len()
    };
    let mut out = vec![0x02, domain_len as u8];
    out.extend_from_slice(domain);
    out
}

fn decode_address(data: &[u8], addr_type: u8) -> Result<String, VmessError> {
    match addr_type {
        0x01 => {
            // IPv4
            if data.len() < 4 {
                return Err(VmessError::InvalidAddressType(addr_type));
            }
            let octets: [u8; 4] = data[..4].try_into().unwrap();
            Ok(std::net::Ipv4Addr::from(octets).to_string())
        }
        0x02 => {
            // Domain
            if data.is_empty() {
                return Err(VmessError::InvalidAddressType(addr_type));
            }
            let len = data[0] as usize;
            if data.len() < 1 + len {
                return Err(VmessError::InvalidAddressType(addr_type));
            }
            String::from_utf8(data[1..1 + len].to_vec())
                .map_err(|_| VmessError::InvalidAddressType(addr_type))
        }
        0x03 => {
            // IPv6
            if data.len() < 16 {
                return Err(VmessError::InvalidAddressType(addr_type));
            }
            let octets: [u8; 16] = data[..16].try_into().unwrap();
            Ok(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => Err(VmessError::InvalidAddressType(addr_type)),
    }
}

// ── Body reader/writer ────────────────────────────────────────────────

/// Reader for chunked AEAD body data.
///
/// Each chunk on the wire is:
/// ```text
/// length (2 bytes BE) || AES-128-GCM ciphertext (length bytes, includes 16-byte tag)
/// ```
///
/// `length` is the encrypted payload + 16 (GCM tag).
pub struct VmessBodyReader {
    key: [u8; 16],
    iv: [u8; 16],
    counter: u64,
    buf: Vec<u8>,
}

impl VmessBodyReader {
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            key: *key,
            iv: *iv,
            counter: 0,
            buf: Vec::new(),
        }
    }

    /// Read and decrypt one chunk from `reader`, appending plaintext to `out`.
    /// Returns `Ok(true)` if a chunk was read, `Ok(false)` on EOF.
    pub fn read_chunk(
        &mut self,
        reader: &mut impl Read,
        out: &mut Vec<u8>,
    ) -> Result<bool, VmessError> {
        // Read 2-byte length
        let mut len_buf = [0u8; 2];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(VmessError::Io(e)),
        }
        let chunk_len = u16::from_be_bytes(len_buf) as usize;
        if chunk_len == 0 {
            return Ok(false); // EOF marker
        }
        if chunk_len > MAX_CHUNK_PAYLOAD + GCM_TAG_LEN {
            return Err(VmessError::Protocol(format!(
                "chunk too large: {chunk_len}"
            )));
        }

        // Read ciphertext
        self.buf.resize(chunk_len, 0);
        reader.read_exact(&mut self.buf)?;

        // Derive nonce: IV ^ counter (big-endian)
        let counter_bytes = self.counter.to_be_bytes();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.iv[..4]);
        for i in 0..8 {
            nonce_bytes[4 + i] = self.iv[4 + i] ^ counter_bytes[i];
        }

        let key = Key::<aes_gcm::Aes128Gcm>::from_slice(&self.key);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let cipher = aes_gcm::Aes128Gcm::new(key);

        let plaintext_len = self.buf.len().saturating_sub(GCM_TAG_LEN);
        let tag_start = plaintext_len;
        let (ciphertext, tag_bytes) = self.buf.split_at_mut(tag_start);
        let tag = aes_gcm::Tag::from_slice(&tag_bytes[..GCM_TAG_LEN]);

        let mut plaintext_vec = ciphertext.to_vec();
        cipher
            .decrypt_in_place_detached(nonce, b"", &mut plaintext_vec, tag)
            .map_err(|e| VmessError::Protocol(format!("body decrypt: {e}")))?;

        out.extend_from_slice(&plaintext_vec);
        self.counter += 1;
        Ok(true)
    }
}

/// Writer for chunked AEAD body data.
pub struct VmessBodyWriter {
    key: [u8; 16],
    iv: [u8; 16],
    counter: u64,
}

impl VmessBodyWriter {
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            key: *key,
            iv: *iv,
            counter: 0,
        }
    }

    /// Encrypt and write one chunk to `writer`.
    pub fn write_chunk(
        &mut self,
        writer: &mut impl Write,
        plaintext: &[u8],
    ) -> Result<(), VmessError> {
        if plaintext.len() > MAX_CHUNK_PAYLOAD {
            return Err(VmessError::Protocol(format!(
                "chunk payload too large: {}",
                plaintext.len()
            )));
        }

        // Derive nonce: IV ^ counter
        let counter_bytes = self.counter.to_be_bytes();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.iv[..4]);
        for i in 0..8 {
            nonce_bytes[4 + i] = self.iv[4 + i] ^ counter_bytes[i];
        }

        let key = Key::<aes_gcm::Aes128Gcm>::from_slice(&self.key);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let cipher = aes_gcm::Aes128Gcm::new(key);

        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut ciphertext)
            .map_err(|e| VmessError::Protocol(format!("body encrypt: {e}")))?;

        let total_len = (ciphertext.len() + GCM_TAG_LEN) as u16;
        writer.write_all(&total_len.to_be_bytes())?;
        writer.write_all(&ciphertext)?;
        writer.write_all(tag.as_slice())?;

        self.counter += 1;
        Ok(())
    }

    /// Write EOF marker (zero-length chunk).
    pub fn write_eof(&mut self, writer: &mut impl Write) -> Result<(), VmessError> {
        writer.write_all(&[0x00, 0x00])?;
        Ok(())
    }
}

// ── Response ──────────────────────────────────────────────────────────

/// Build a VMess response header.
///
/// ```text
/// nonce(12) || AES-128-GCM(response_key, nonce, [0x00])
/// ```
pub fn build_response(response_key: &[u8; 16]) -> Result<Vec<u8>, VmessError> {
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let key = Key::<aes_gcm::Aes128Gcm>::from_slice(response_key);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let cipher = aes_gcm::Aes128Gcm::new(key);

    let mut plaintext = vec![0x00u8];
    let tag = cipher
        .encrypt_in_place_detached(nonce, b"", &mut plaintext)
        .map_err(|e| VmessError::Protocol(format!("response encrypt: {e}")))?;

    let mut payload = nonce_bytes.to_vec();
    payload.append(&mut plaintext);
    payload.extend_from_slice(tag.as_slice());

    Ok(payload)
}

/// Read and verify a VMess response header.
pub fn read_response(response_key: &[u8; 16], reader: &mut impl Read) -> Result<(), VmessError> {
    let mut buf = [0u8; 12 + 1 + 16]; // nonce + result byte + tag
    reader.read_exact(&mut buf)?;

    let nonce_bytes: &[u8; 12] = buf[..12].try_into().unwrap();
    let ciphertext = &buf[12..13]; // 1 byte result
    let tag_bytes = &buf[13..];

    let key = Key::<aes_gcm::Aes128Gcm>::from_slice(response_key);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let cipher = aes_gcm::Aes128Gcm::new(key);
    let tag = aes_gcm::Tag::from_slice(tag_bytes);

    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(nonce, b"", &mut plaintext, tag)
        .map_err(|e| VmessError::AuthFailed(format!("response decrypt: {e}")))?;

    if plaintext[0] != 0x00 {
        return Err(VmessError::AuthFailed(format!(
            "server returned error: 0x{:02x}",
            plaintext[0]
        )));
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uuid() -> [u8; 16] {
        let mut uuid = [0u8; 16];
        uuid[6] = 0x40;
        uuid[8] = 0x80;
        for (i, b) in uuid.iter_mut().enumerate() {
            if i != 6 && i != 8 {
                *b = i as u8 + 1;
            }
        }
        uuid
    }

    #[test]
    fn test_kdf_deterministic() {
        let uuid = test_uuid();
        let k1 = derive_cmd_key(&uuid);
        let k2 = derive_cmd_key(&uuid);
        assert_eq!(k1, k2);
        assert_ne!(k1, [0u8; 16]);
    }

    #[test]
    fn test_kdf_different_uuids() {
        let uuid1 = test_uuid();
        let mut uuid2 = test_uuid();
        uuid2[0] ^= 1;
        let k1 = derive_cmd_key(&uuid1);
        let k2 = derive_cmd_key(&uuid2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_response_key_derivation() {
        let cmd_key = derive_cmd_key(&test_uuid());
        let resp_key = derive_response_key(&cmd_key);
        assert_eq!(resp_key.len(), 16);
    }

    #[test]
    fn test_eaudid_roundtrip() {
        let cmd_key = derive_cmd_key(&test_uuid());
        let (_plain, eaudid) = generate_eaudid(&cmd_key);
        let ts = verify_eaudid(&cmd_key, &eaudid).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!((ts as i64 - now as i64).abs() <= 5);
    }

    #[test]
    fn test_eaudid_rejects_wrong_key() {
        let k1 = derive_cmd_key(&test_uuid());
        let mut uuid2 = test_uuid();
        uuid2[0] ^= 1;
        let k2 = derive_cmd_key(&uuid2);
        let (_plain, eaudid) = generate_eaudid(&k1);
        assert!(verify_eaudid(&k2, &eaudid).is_err());
    }

    #[test]
    fn test_eaudid_tamper_detection() {
        let cmd_key = derive_cmd_key(&test_uuid());
        let (_plain, mut eaudid) = generate_eaudid(&cmd_key);
        eaudid[0] ^= 1;
        assert!(verify_eaudid(&cmd_key, &eaudid).is_err());
    }

    #[test]
    fn test_header_roundtrip() {
        let cmd_key = derive_cmd_key(&test_uuid());
        let (_plain, eaudid) = generate_eaudid(&cmd_key);

        let mut body_key = [0u8; 16];
        let mut body_iv = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut body_key);
        rand::rngs::OsRng.fill_bytes(&mut body_iv);

        let request = VmessRequest {
            command: VmessCommand::Tcp,
            address: "example.com".into(),
            port: 443,
        };

        let (_len, payload) =
            build_header(&cmd_key, &eaudid, &body_key, &body_iv, &request).unwrap();
        let instr = decrypt_header(&cmd_key, &eaudid, &payload).unwrap();

        assert_eq!(instr.command, VmessCommand::Tcp);
        assert_eq!(instr.address, "example.com");
        assert_eq!(instr.port, 443);
        assert_eq!(instr.body_key, body_key);
        assert_eq!(instr.body_iv, body_iv);
    }

    #[test]
    fn test_header_roundtrip_ipv4() {
        let cmd_key = derive_cmd_key(&test_uuid());
        let (_plain, eaudid) = generate_eaudid(&cmd_key);

        let mut body_key = [0u8; 16];
        let mut body_iv = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut body_key);
        rand::rngs::OsRng.fill_bytes(&mut body_iv);

        let request = VmessRequest {
            command: VmessCommand::Tcp,
            address: "127.0.0.1".into(),
            port: 8080,
        };

        let (_len, payload) =
            build_header(&cmd_key, &eaudid, &body_key, &body_iv, &request).unwrap();
        let instr = decrypt_header(&cmd_key, &eaudid, &payload).unwrap();

        assert_eq!(instr.command, VmessCommand::Tcp);
        assert_eq!(instr.address, "127.0.0.1");
        assert_eq!(instr.port, 8080);
    }

    #[test]
    fn test_header_rejects_wrong_key() {
        let k1 = derive_cmd_key(&test_uuid());
        let mut uuid2 = test_uuid();
        uuid2[0] ^= 1;
        let k2 = derive_cmd_key(&uuid2);

        let (_plain, eaudid) = generate_eaudid(&k1);
        let mut body_key = [0u8; 16];
        let mut body_iv = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut body_key);
        rand::rngs::OsRng.fill_bytes(&mut body_iv);

        let request = VmessRequest {
            command: VmessCommand::Tcp,
            address: "example.com".into(),
            port: 443,
        };

        let (_len, payload) = build_header(&k1, &eaudid, &body_key, &body_iv, &request).unwrap();
        assert!(decrypt_header(&k2, &eaudid, &payload).is_err());
    }

    #[test]
    fn test_header_total_len_matches_payload() {
        // Regression test for #48 sub-bug 1: build_header returned
        // total_len = 2 + payload.len() which caused the server to
        // expect 2 extra bytes and deadlock.
        let cmd_key = derive_cmd_key(&test_uuid());
        let (_plain, eaudid) = generate_eaudid(&cmd_key);
        let body_key = [0u8; 16];
        let body_iv = [0u8; 16];

        let request = VmessRequest {
            command: VmessCommand::Tcp,
            address: "test.example.com".into(),
            port: 443,
        };

        let (total_len, payload) =
            build_header(&cmd_key, &eaudid, &body_key, &body_iv, &request).unwrap();
        assert_eq!(
            total_len as usize,
            payload.len(),
            "total_len must equal payload.len(), not 2+len"
        );
    }

    #[test]
    fn test_body_roundtrip() {
        let mut key = [0u8; 16];
        let mut iv = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut key);
        rand::rngs::OsRng.fill_bytes(&mut iv);

        let mut writer = VmessBodyWriter::new(&key, &iv);
        let mut reader = VmessBodyReader::new(&key, &iv);

        let mut buf = Vec::new();

        // Write chunks
        writer.write_chunk(&mut buf, b"hello ").unwrap();
        writer.write_chunk(&mut buf, b"world").unwrap();
        writer.write_eof(&mut buf).unwrap();

        // Read chunks
        let mut out = Vec::new();
        let mut cursor = std::io::Cursor::new(&buf);
        assert!(reader.read_chunk(&mut cursor, &mut out).unwrap());
        assert!(reader.read_chunk(&mut cursor, &mut out).unwrap());
        // EOF marker → false
        assert!(!reader.read_chunk(&mut cursor, &mut out).unwrap());

        assert_eq!(out, b"hello world");
    }

    #[test]
    fn test_response_roundtrip() {
        let cmd_key = derive_cmd_key(&test_uuid());
        let resp_key = derive_response_key(&cmd_key);

        let payload = build_response(&resp_key).unwrap();
        read_response(&resp_key, &mut std::io::Cursor::new(&payload)).unwrap();
    }

    #[test]
    fn test_response_rejects_wrong_key() {
        let cmd_key = derive_cmd_key(&test_uuid());
        let resp_key = derive_response_key(&cmd_key);
        let wrong_key: [u8; 16] = [0xaa; 16];

        let payload = build_response(&resp_key).unwrap();
        assert!(read_response(&wrong_key, &mut std::io::Cursor::new(&payload)).is_err());
    }
}
