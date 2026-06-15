//! Standard VMess AEAD helpers used by wrongsv's VMess inbound and evaluator.
//!
//! This module now follows the xray/v2fly wire format closely enough for
//! real-client interoperability:
//! - command-key derivation uses `MD5(uuid || magic-guid)`
//! - AuthID uses xray's nested-HMAC KDF and AES-ECB wrapper
//! - request headers use the two-stage AEAD envelope (`len` + `payload`)
//! - response headers use xray's AEAD response-header layout
//! - body chunks use the default VMess stream framing with chunk masking,
//!   optional global padding, and AEAD-encrypted empty-chunk EOF markers
#![allow(dead_code)]

use std::io::{self, Read, Write};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::aead::AeadInPlace;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha2::{Digest, Sha256};
use sha3::{
    Shake128, Shake128Reader,
    digest::{ExtendableOutput, Update as XofUpdate, XofReader},
};

type HmacSha256 = Hmac<Sha256>;

const AEAD_TAG_LEN: usize = 16;
const HEADER_FIXED_LEN: usize = 38;
const MAX_HEADER_LEN: usize = 8192;
const MAX_CHUNK_PAYLOAD: usize = 16 * 1024;
const MAX_PADDING_LEN: usize = 64;
const MAX_CLOCK_SKEW_SECS: i64 = 120;

const VMESS_CMD_KEY_GUID: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const KDF_SALT_AEAD: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_AUTH_ID: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_LEN_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
const KDF_SALT_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_HEADER_NONCE: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_AUTH_LEN: &[u8] = b"auth_len";
const KDF_SALT_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_RESP_LEN_NONCE: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_RESP_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_RESP_NONCE: &[u8] = b"AEAD Resp Header IV";

pub const REQUEST_OPTION_CHUNK_STREAM: u8 = 0x01;
pub const REQUEST_OPTION_CHUNK_MASKING: u8 = 0x04;
pub const REQUEST_OPTION_GLOBAL_PADDING: u8 = 0x08;
pub const REQUEST_OPTION_AUTHENTICATED_LENGTH: u8 = 0x10;

pub const SECURITY_AES128_GCM: u8 = 0x03;
pub const SECURITY_CHACHA20_POLY1305: u8 = 0x04;
pub const SECURITY_NONE: u8 = 0x05;
pub const SECURITY_ZERO: u8 = 0x06;

pub const DEFAULT_REQUEST_OPTIONS: u8 =
    REQUEST_OPTION_CHUNK_STREAM | REQUEST_OPTION_CHUNK_MASKING | REQUEST_OPTION_GLOBAL_PADDING;
pub const DEFAULT_SECURITY: u8 = SECURITY_AES128_GCM;
pub const DEFAULT_RESPONSE_HEADER: u8 = 0;

#[derive(Debug, thiserror::Error)]
pub enum VmessError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("VMess authentication failed: {0}")]
    AuthFailed(String),
    #[error("VMess protocol error: {0}")]
    Protocol(String),
    #[error("VMess invalid command: 0x{0:02x}")]
    InvalidCommand(u8),
    #[error("VMess invalid address type: 0x{0:02x}")]
    InvalidAddressType(u8),
    #[error("VMess unsupported security: 0x{0:02x}")]
    UnsupportedSecurity(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessCommand {
    Tcp = 0x01,
    Udp = 0x02,
    Mux = 0x03,
}

impl VmessCommand {
    fn from_byte(byte: u8) -> Result<Self, VmessError> {
        match byte {
            0x01 => Ok(Self::Tcp),
            0x02 => Ok(Self::Udp),
            0x03 => Ok(Self::Mux),
            other => Err(VmessError::InvalidCommand(other)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VmessRequest {
    pub command: VmessCommand,
    pub address: String,
    pub port: u16,
    pub option: u8,
    pub security: u8,
    pub response_header: u8,
}

impl VmessRequest {
    pub fn standard_tcp(address: impl Into<String>, port: u16) -> Self {
        Self {
            command: VmessCommand::Tcp,
            address: address.into(),
            port,
            option: DEFAULT_REQUEST_OPTIONS,
            security: DEFAULT_SECURITY,
            response_header: DEFAULT_RESPONSE_HEADER,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VmessHeaderInstruction {
    pub body_iv: [u8; 16],
    pub body_key: [u8; 16],
    pub response_header: u8,
    pub option: u8,
    pub security: u8,
    pub command: VmessCommand,
    pub address: String,
    pub port: u16,
}

pub fn derive_cmd_key(uuid_bytes: &[u8; 16]) -> [u8; 16] {
    let mut md5 = Md5::new();
    Digest::update(&mut md5, uuid_bytes);
    Digest::update(&mut md5, VMESS_CMD_KEY_GUID);
    let digest = md5.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 should init");
    Mac::update(&mut mac, data);
    mac.finalize().into_bytes().into()
}

fn hmac_nested_with<F>(hash_fn: &F, key: &[u8], data: &[u8]) -> [u8; 32]
where
    F: Fn(&[u8]) -> [u8; 32],
{
    let mut key_block = [0u8; 64];
    if key.len() > key_block.len() {
        key_block[..32].copy_from_slice(&hash_fn(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_key = key_block;
    for byte in &mut inner_key {
        *byte ^= 0x36;
    }
    let mut inner_msg = Vec::with_capacity(inner_key.len() + data.len());
    inner_msg.extend_from_slice(&inner_key);
    inner_msg.extend_from_slice(data);
    let inner_digest = hash_fn(&inner_msg);

    let mut outer_key = key_block;
    for byte in &mut outer_key {
        *byte ^= 0x5c;
    }
    let mut outer_msg = Vec::with_capacity(outer_key.len() + inner_digest.len());
    outer_msg.extend_from_slice(&outer_key);
    outer_msg.extend_from_slice(&inner_digest);
    hash_fn(&outer_msg)
}

fn vmess_kdf_digest(data: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    match paths.split_last() {
        None => hmac_sha256(KDF_SALT_AEAD, data),
        Some((last, rest)) => hmac_nested_with(&|input| vmess_kdf_digest(input, rest), last, data),
    }
}

fn vmess_kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    vmess_kdf_digest(key, paths)
}

fn vmess_kdf16(key: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let digest = vmess_kdf(key, paths);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

pub fn generate_eaudid(cmd_key: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    use rand::RngCore;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut plaintext = [0u8; 16];
    plaintext[..8].copy_from_slice(&now.to_be_bytes());
    rand::rngs::OsRng.fill_bytes(&mut plaintext[8..12]);
    let crc = crc32_ieee(&plaintext[..12]);
    plaintext[12..16].copy_from_slice(&crc.to_be_bytes());

    let auth_id_key = vmess_kdf16(cmd_key, &[KDF_SALT_AUTH_ID]);
    let cipher = aes::Aes128::new_from_slice(&auth_id_key).expect("AES-128 key length");
    let mut block = plaintext;
    cipher.encrypt_block((&mut block).into());
    (plaintext, block)
}

pub fn verify_eaudid(cmd_key: &[u8; 16], eaudid: &[u8; 16]) -> Result<i64, VmessError> {
    let auth_id_key = vmess_kdf16(cmd_key, &[KDF_SALT_AUTH_ID]);
    let cipher = aes::Aes128::new_from_slice(&auth_id_key).expect("AES-128 key length");
    let mut block = *eaudid;
    cipher.decrypt_block((&mut block).into());

    let expected_crc = u32::from_be_bytes(block[12..16].try_into().unwrap());
    if expected_crc != crc32_ieee(&block[..12]) {
        return Err(VmessError::AuthFailed("CRC32 mismatch".into()));
    }

    let timestamp = i64::from_be_bytes(block[..8].try_into().unwrap());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if timestamp.abs_diff(now) > MAX_CLOCK_SKEW_SECS as u64 {
        return Err(VmessError::AuthFailed(format!(
            "timestamp skew too large: {}s",
            timestamp.abs_diff(now)
        )));
    }

    Ok(timestamp)
}

pub fn build_header(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    body_key: &[u8; 16],
    body_iv: &[u8; 16],
    request: &VmessRequest,
) -> Result<(u16, Vec<u8>), VmessError> {
    use rand::RngCore;

    validate_security(request.security)?;

    let padding_len = rand::random::<u8>() & 0x0f;
    let mut plaintext = Vec::with_capacity(HEADER_FIXED_LEN + 32);
    plaintext.push(1);
    plaintext.extend_from_slice(body_iv);
    plaintext.extend_from_slice(body_key);
    plaintext.push(request.response_header);
    plaintext.push(request.option);
    plaintext.push((padding_len << 4) | (request.security & 0x0f));
    plaintext.push(0);
    plaintext.push(request.command as u8);
    plaintext.extend_from_slice(&request.port.to_be_bytes());
    plaintext.extend_from_slice(&encode_address(&request.address)?);

    if padding_len > 0 {
        let start = plaintext.len();
        plaintext.resize(start + padding_len as usize, 0);
        rand::rngs::OsRng.fill_bytes(&mut plaintext[start..]);
    }

    let checksum = fnv1a32(&plaintext);
    plaintext.extend_from_slice(&checksum.to_be_bytes());

    let mut connection_nonce = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut connection_nonce);

    let header_len = plaintext.len() as u16;
    let mut encrypted_len = header_len.to_be_bytes().to_vec();
    let len_key = vmess_kdf16(
        cmd_key,
        &[
            KDF_SALT_HEADER_LEN_KEY,
            auth_id.as_slice(),
            connection_nonce.as_slice(),
        ],
    );
    let len_nonce = vmess_kdf(
        cmd_key,
        &[
            KDF_SALT_HEADER_LEN_NONCE,
            auth_id.as_slice(),
            connection_nonce.as_slice(),
        ],
    );
    let len_cipher = aes_gcm::Aes128Gcm::new_from_slice(&len_key).expect("AES-GCM key length");
    let len_tag = len_cipher
        .encrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(&len_nonce[..12]),
            auth_id,
            &mut encrypted_len,
        )
        .map_err(|e| VmessError::Protocol(format!("header len encrypt: {e}")))?;
    encrypted_len.extend_from_slice(len_tag.as_slice());

    let mut encrypted_header = plaintext;
    let header_key = vmess_kdf16(
        cmd_key,
        &[
            KDF_SALT_HEADER_KEY,
            auth_id.as_slice(),
            connection_nonce.as_slice(),
        ],
    );
    let header_nonce = vmess_kdf(
        cmd_key,
        &[
            KDF_SALT_HEADER_NONCE,
            auth_id.as_slice(),
            connection_nonce.as_slice(),
        ],
    );
    let header_cipher =
        aes_gcm::Aes128Gcm::new_from_slice(&header_key).expect("AES-GCM key length");
    let header_tag = header_cipher
        .encrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(&header_nonce[..12]),
            auth_id,
            &mut encrypted_header,
        )
        .map_err(|e| VmessError::Protocol(format!("header encrypt: {e}")))?;
    encrypted_header.extend_from_slice(header_tag.as_slice());

    let mut payload =
        Vec::with_capacity(encrypted_len.len() + connection_nonce.len() + encrypted_header.len());
    payload.extend_from_slice(&encrypted_len);
    payload.extend_from_slice(&connection_nonce);
    payload.extend_from_slice(&encrypted_header);
    Ok((payload.len() as u16, payload))
}

pub fn read_header(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    reader: &mut impl Read,
) -> Result<VmessHeaderInstruction, VmessError> {
    let mut encrypted_len = [0u8; 18];
    reader.read_exact(&mut encrypted_len)?;

    let mut connection_nonce = [0u8; 8];
    reader.read_exact(&mut connection_nonce)?;

    let len_key = vmess_kdf16(
        cmd_key,
        &[
            KDF_SALT_HEADER_LEN_KEY,
            auth_id.as_slice(),
            connection_nonce.as_slice(),
        ],
    );
    let len_nonce = vmess_kdf(
        cmd_key,
        &[
            KDF_SALT_HEADER_LEN_NONCE,
            auth_id.as_slice(),
            connection_nonce.as_slice(),
        ],
    );
    let len_cipher = aes_gcm::Aes128Gcm::new_from_slice(&len_key).expect("AES-GCM key length");
    let mut decrypted_len = encrypted_len[..2].to_vec();
    len_cipher
        .decrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(&len_nonce[..12]),
            auth_id,
            &mut decrypted_len,
            aes_gcm::Tag::from_slice(&encrypted_len[2..]),
        )
        .map_err(|e| VmessError::AuthFailed(format!("header len decrypt: {e}")))?;
    let header_len = u16::from_be_bytes(decrypted_len[..2].try_into().unwrap()) as usize;
    if !(HEADER_FIXED_LEN + 7..=MAX_HEADER_LEN).contains(&header_len) {
        return Err(VmessError::Protocol(format!(
            "header length out of range: {header_len}"
        )));
    }

    let mut encrypted_header = vec![0u8; header_len + AEAD_TAG_LEN];
    reader.read_exact(&mut encrypted_header)?;

    let header_key = vmess_kdf16(
        cmd_key,
        &[
            KDF_SALT_HEADER_KEY,
            auth_id.as_slice(),
            connection_nonce.as_slice(),
        ],
    );
    let header_nonce = vmess_kdf(
        cmd_key,
        &[
            KDF_SALT_HEADER_NONCE,
            auth_id.as_slice(),
            connection_nonce.as_slice(),
        ],
    );
    let header_cipher =
        aes_gcm::Aes128Gcm::new_from_slice(&header_key).expect("AES-GCM key length");
    let tag_index = encrypted_header
        .len()
        .checked_sub(AEAD_TAG_LEN)
        .ok_or_else(|| VmessError::Protocol("header ciphertext too short".into()))?;
    let mut plaintext = encrypted_header[..tag_index].to_vec();
    header_cipher
        .decrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(&header_nonce[..12]),
            auth_id,
            &mut plaintext,
            aes_gcm::Tag::from_slice(&encrypted_header[tag_index..]),
        )
        .map_err(|e| VmessError::AuthFailed(format!("header decrypt: {e}")))?;

    parse_instruction(&plaintext)
}

pub fn decrypt_header(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    header_payload: &[u8],
) -> Result<VmessHeaderInstruction, VmessError> {
    read_header(cmd_key, auth_id, &mut std::io::Cursor::new(header_payload))
}

fn parse_instruction(data: &[u8]) -> Result<VmessHeaderInstruction, VmessError> {
    if data.len() < HEADER_FIXED_LEN + 7 {
        return Err(VmessError::Protocol("instruction too short".into()));
    }
    if data[0] != 1 {
        return Err(VmessError::Protocol(format!(
            "unsupported VMess version: {}",
            data[0]
        )));
    }

    let mut body_iv = [0u8; 16];
    body_iv.copy_from_slice(&data[1..17]);
    let mut body_key = [0u8; 16];
    body_key.copy_from_slice(&data[17..33]);
    let response_header = data[33];
    let option = data[34];
    let padding_len = (data[35] >> 4) as usize;
    let security = data[35] & 0x0f;
    validate_security(security)?;
    let command = VmessCommand::from_byte(data[37])?;

    let mut offset = HEADER_FIXED_LEN;
    if data.len() < offset + 3 + 4 {
        return Err(VmessError::Protocol(
            "instruction truncated before address".into(),
        ));
    }
    let port = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap());
    offset += 2;

    let (address, consumed) = decode_address(&data[offset..])?;
    offset += consumed;
    if data.len() < offset + padding_len + 4 {
        return Err(VmessError::Protocol(
            "instruction truncated after address".into(),
        ));
    }

    let checksum_offset = data.len() - 4;
    let expected = u32::from_be_bytes(data[checksum_offset..].try_into().unwrap());
    let actual = fnv1a32(&data[..checksum_offset]);
    if actual != expected {
        return Err(VmessError::AuthFailed("header checksum mismatch".into()));
    }

    Ok(VmessHeaderInstruction {
        body_iv,
        body_key,
        response_header,
        option,
        security,
        command,
        address,
        port,
    })
}

fn encode_address(address: &str) -> Result<Vec<u8>, VmessError> {
    if let Ok(ipv4) = address.parse::<std::net::Ipv4Addr>() {
        let mut out = vec![0x01];
        out.extend_from_slice(&ipv4.octets());
        return Ok(out);
    }
    if let Ok(ipv6) = address.parse::<std::net::Ipv6Addr>() {
        let mut out = vec![0x03];
        out.extend_from_slice(&ipv6.octets());
        return Ok(out);
    }
    let domain = address.as_bytes();
    if domain.is_empty() || domain.len() > 255 {
        return Err(VmessError::Protocol("invalid domain length".into()));
    }
    let mut out = vec![0x02, domain.len() as u8];
    out.extend_from_slice(domain);
    Ok(out)
}

fn decode_address(data: &[u8]) -> Result<(String, usize), VmessError> {
    let Some(&addr_type) = data.first() else {
        return Err(VmessError::InvalidAddressType(0));
    };
    match addr_type {
        0x01 => {
            if data.len() < 5 {
                return Err(VmessError::InvalidAddressType(addr_type));
            }
            let octets: [u8; 4] = data[1..5].try_into().unwrap();
            Ok((std::net::Ipv4Addr::from(octets).to_string(), 5))
        }
        0x02 => {
            if data.len() < 2 {
                return Err(VmessError::InvalidAddressType(addr_type));
            }
            let len = data[1] as usize;
            if data.len() < 2 + len {
                return Err(VmessError::InvalidAddressType(addr_type));
            }
            let domain = String::from_utf8(data[2..2 + len].to_vec())
                .map_err(|_| VmessError::InvalidAddressType(addr_type))?;
            Ok((domain, 2 + len))
        }
        0x03 => {
            if data.len() < 17 {
                return Err(VmessError::InvalidAddressType(addr_type));
            }
            let octets: [u8; 16] = data[1..17].try_into().unwrap();
            Ok((std::net::Ipv6Addr::from(octets).to_string(), 17))
        }
        other => Err(VmessError::InvalidAddressType(other)),
    }
}

fn validate_security(security: u8) -> Result<(), VmessError> {
    match security {
        SECURITY_AES128_GCM | SECURITY_CHACHA20_POLY1305 | SECURITY_NONE | SECURITY_ZERO => Ok(()),
        other => Err(VmessError::UnsupportedSecurity(other)),
    }
}

pub fn derive_response_body_key(request_body_key: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(request_body_key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

pub fn derive_response_body_iv(request_body_iv: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(request_body_iv);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

pub fn build_response(
    request_body_key: &[u8; 16],
    request_body_iv: &[u8; 16],
    response_header: u8,
) -> Result<Vec<u8>, VmessError> {
    let response_body_key = derive_response_body_key(request_body_key);
    let response_body_iv = derive_response_body_iv(request_body_iv);

    let mut plaintext = vec![response_header, 0, 0, 0];
    let len_key = vmess_kdf16(&response_body_key, &[KDF_SALT_RESP_LEN_KEY]);
    let len_nonce = vmess_kdf(&response_body_iv, &[KDF_SALT_RESP_LEN_NONCE]);
    let len_cipher = aes_gcm::Aes128Gcm::new_from_slice(&len_key).expect("AES-GCM key length");
    let mut encrypted_len = (plaintext.len() as u16).to_be_bytes().to_vec();
    let len_tag = len_cipher
        .encrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(&len_nonce[..12]),
            b"",
            &mut encrypted_len,
        )
        .map_err(|e| VmessError::Protocol(format!("response len encrypt: {e}")))?;
    encrypted_len.extend_from_slice(len_tag.as_slice());

    let payload_key = vmess_kdf16(&response_body_key, &[KDF_SALT_RESP_KEY]);
    let payload_nonce = vmess_kdf(&response_body_iv, &[KDF_SALT_RESP_NONCE]);
    let payload_cipher =
        aes_gcm::Aes128Gcm::new_from_slice(&payload_key).expect("AES-GCM key length");
    let payload_tag = payload_cipher
        .encrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(&payload_nonce[..12]),
            b"",
            &mut plaintext,
        )
        .map_err(|e| VmessError::Protocol(format!("response payload encrypt: {e}")))?;
    plaintext.extend_from_slice(payload_tag.as_slice());

    let mut out = encrypted_len;
    out.extend_from_slice(&plaintext);
    Ok(out)
}

pub fn read_response(
    request_body_key: &[u8; 16],
    request_body_iv: &[u8; 16],
    expected_response_header: u8,
    reader: &mut impl Read,
) -> Result<(), VmessError> {
    let response_body_key = derive_response_body_key(request_body_key);
    let response_body_iv = derive_response_body_iv(request_body_iv);

    let mut encrypted_len = [0u8; 18];
    reader.read_exact(&mut encrypted_len)?;

    let len_key = vmess_kdf16(&response_body_key, &[KDF_SALT_RESP_LEN_KEY]);
    let len_nonce = vmess_kdf(&response_body_iv, &[KDF_SALT_RESP_LEN_NONCE]);
    let len_cipher = aes_gcm::Aes128Gcm::new_from_slice(&len_key).expect("AES-GCM key length");
    let mut decrypted_len = encrypted_len[..2].to_vec();
    len_cipher
        .decrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(&len_nonce[..12]),
            b"",
            &mut decrypted_len,
            aes_gcm::Tag::from_slice(&encrypted_len[2..]),
        )
        .map_err(|e| VmessError::AuthFailed(format!("response len decrypt: {e}")))?;
    let payload_len = u16::from_be_bytes(decrypted_len[..2].try_into().unwrap()) as usize;
    if !(4..=255).contains(&payload_len) {
        return Err(VmessError::Protocol(format!(
            "response header length out of range: {payload_len}"
        )));
    }

    let mut encrypted_payload = vec![0u8; payload_len + AEAD_TAG_LEN];
    reader.read_exact(&mut encrypted_payload)?;
    let payload_key = vmess_kdf16(&response_body_key, &[KDF_SALT_RESP_KEY]);
    let payload_nonce = vmess_kdf(&response_body_iv, &[KDF_SALT_RESP_NONCE]);
    let payload_cipher =
        aes_gcm::Aes128Gcm::new_from_slice(&payload_key).expect("AES-GCM key length");
    let tag_index = encrypted_payload.len() - AEAD_TAG_LEN;
    let mut plaintext = encrypted_payload[..tag_index].to_vec();
    payload_cipher
        .decrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(&payload_nonce[..12]),
            b"",
            &mut plaintext,
            aes_gcm::Tag::from_slice(&encrypted_payload[tag_index..]),
        )
        .map_err(|e| VmessError::AuthFailed(format!("response payload decrypt: {e}")))?;

    if plaintext.first().copied() != Some(expected_response_header) {
        return Err(VmessError::AuthFailed(format!(
            "unexpected response header byte: expected {expected_response_header:#04x}, got {:?}",
            plaintext.first().copied()
        )));
    }
    Ok(())
}

#[derive(Clone)]
struct ShakeState {
    reader: Shake128Reader,
    buf: [u8; 2],
}

impl ShakeState {
    fn new(seed: &[u8; 16]) -> Self {
        let mut shake = Shake128::default();
        XofUpdate::update(&mut shake, seed);
        Self {
            reader: shake.finalize_xof(),
            buf: [0u8; 2],
        }
    }

    fn next_u16(&mut self) -> u16 {
        XofReader::read(&mut self.reader, &mut self.buf);
        u16::from_be_bytes(self.buf)
    }

    fn next_padding_len(&mut self) -> usize {
        (self.next_u16() % MAX_PADDING_LEN as u16) as usize
    }
}

fn generate_chacha20poly1305_key(key: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];

    let mut md5 = Md5::new();
    Digest::update(&mut md5, key);
    let first = md5.finalize_reset();
    out[..16].copy_from_slice(&first[..16]);

    Digest::update(&mut md5, &out[..16]);
    let second = md5.finalize();
    out[16..].copy_from_slice(&second[..16]);
    out
}

fn chunk_nonce(base: &[u8; 16], counter: u16, size: usize) -> Vec<u8> {
    let mut nonce = base.to_vec();
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce.truncate(size);
    nonce
}

enum PayloadCipher {
    None,
    Aes128Gcm {
        key: [u8; 16],
        iv: [u8; 16],
        counter: u16,
    },
    ChaCha20Poly1305 {
        key: [u8; 32],
        iv: [u8; 16],
        counter: u16,
    },
}

impl PayloadCipher {
    fn new(key: &[u8; 16], iv: &[u8; 16], security: u8) -> Result<Self, VmessError> {
        match security {
            SECURITY_AES128_GCM => Ok(Self::Aes128Gcm {
                key: *key,
                iv: *iv,
                counter: 0,
            }),
            SECURITY_CHACHA20_POLY1305 => Ok(Self::ChaCha20Poly1305 {
                key: generate_chacha20poly1305_key(key),
                iv: *iv,
                counter: 0,
            }),
            SECURITY_NONE | SECURITY_ZERO => Ok(Self::None),
            other => Err(VmessError::UnsupportedSecurity(other)),
        }
    }

    fn overhead(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Aes128Gcm { .. } | Self::ChaCha20Poly1305 { .. } => AEAD_TAG_LEN,
        }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, VmessError> {
        match self {
            Self::None => Ok(plaintext.to_vec()),
            Self::Aes128Gcm { key, iv, counter } => {
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).expect("AES-GCM key length");
                let nonce = chunk_nonce(iv, *counter, 12);
                *counter = counter.wrapping_add(1);
                let mut out = plaintext.to_vec();
                let tag = cipher
                    .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&nonce), b"", &mut out)
                    .map_err(|e| VmessError::Protocol(format!("body encrypt: {e}")))?;
                out.extend_from_slice(tag.as_slice());
                Ok(out)
            }
            Self::ChaCha20Poly1305 { key, iv, counter } => {
                let cipher =
                    ChaCha20Poly1305::new_from_slice(key).expect("ChaCha20-Poly1305 key length");
                let nonce = chunk_nonce(iv, *counter, 12);
                *counter = counter.wrapping_add(1);
                let mut out = plaintext.to_vec();
                let tag = cipher
                    .encrypt_in_place_detached(
                        chacha20poly1305::Nonce::from_slice(&nonce),
                        b"",
                        &mut out,
                    )
                    .map_err(|e| VmessError::Protocol(format!("body encrypt: {e}")))?;
                out.extend_from_slice(tag.as_slice());
                Ok(out)
            }
        }
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, VmessError> {
        match self {
            Self::None => Ok(ciphertext.to_vec()),
            Self::Aes128Gcm { key, iv, counter } => {
                if ciphertext.len() < AEAD_TAG_LEN {
                    return Err(VmessError::Protocol("body ciphertext too short".into()));
                }
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).expect("AES-GCM key length");
                let nonce = chunk_nonce(iv, *counter, 12);
                *counter = counter.wrapping_add(1);
                let split = ciphertext.len() - AEAD_TAG_LEN;
                let mut out = ciphertext[..split].to_vec();
                cipher
                    .decrypt_in_place_detached(
                        aes_gcm::Nonce::from_slice(&nonce),
                        b"",
                        &mut out,
                        aes_gcm::Tag::from_slice(&ciphertext[split..]),
                    )
                    .map_err(|e| VmessError::Protocol(format!("body decrypt: {e}")))?;
                Ok(out)
            }
            Self::ChaCha20Poly1305 { key, iv, counter } => {
                if ciphertext.len() < AEAD_TAG_LEN {
                    return Err(VmessError::Protocol("body ciphertext too short".into()));
                }
                let cipher =
                    ChaCha20Poly1305::new_from_slice(key).expect("ChaCha20-Poly1305 key length");
                let nonce = chunk_nonce(iv, *counter, 12);
                *counter = counter.wrapping_add(1);
                let split = ciphertext.len() - AEAD_TAG_LEN;
                let mut out = ciphertext[..split].to_vec();
                cipher
                    .decrypt_in_place_detached(
                        chacha20poly1305::Nonce::from_slice(&nonce),
                        b"",
                        &mut out,
                        chacha20poly1305::Tag::from_slice(&ciphertext[split..]),
                    )
                    .map_err(|e| VmessError::Protocol(format!("body decrypt: {e}")))?;
                Ok(out)
            }
        }
    }
}

enum SizeMode {
    Plain,
    ShakeMasked,
    AuthenticatedLength(AuthenticatedLengthCipher),
}

struct AuthenticatedLengthCipher {
    inner: PayloadCipher,
}

impl AuthenticatedLengthCipher {
    fn new(key_source: &[u8; 16], iv_source: &[u8; 16], security: u8) -> Result<Self, VmessError> {
        let auth_len_key = vmess_kdf16(key_source, &[KDF_SALT_AUTH_LEN]);
        Ok(Self {
            inner: PayloadCipher::new(&auth_len_key, iv_source, security)?,
        })
    }

    fn encode_size(&mut self, total_size: u16) -> Result<Vec<u8>, VmessError> {
        if total_size < AEAD_TAG_LEN as u16 {
            return Err(VmessError::Protocol(
                "authenticated length underflow".into(),
            ));
        }
        self.inner
            .encrypt(&(total_size - AEAD_TAG_LEN as u16).to_be_bytes())
    }

    fn decode_size(&mut self, ciphertext: &[u8]) -> Result<u16, VmessError> {
        let plaintext = self.inner.decrypt(ciphertext)?;
        if plaintext.len() != 2 {
            return Err(VmessError::Protocol(
                "invalid authenticated length size".into(),
            ));
        }
        Ok(u16::from_be_bytes(plaintext[..2].try_into().unwrap()) + AEAD_TAG_LEN as u16)
    }
}

pub struct VmessBodyReader {
    payload: PayloadCipher,
    size_mode: SizeMode,
    shake: Option<ShakeState>,
    use_global_padding: bool,
    done: bool,
}

impl VmessBodyReader {
    pub fn new(payload_key: &[u8; 16], payload_iv: &[u8; 16]) -> Self {
        Self::new_with_options(
            payload_key,
            payload_iv,
            payload_key,
            payload_iv,
            DEFAULT_REQUEST_OPTIONS,
            DEFAULT_SECURITY,
        )
        .expect("default VMess codec should build")
    }

    pub fn new_with_options(
        payload_key: &[u8; 16],
        payload_iv: &[u8; 16],
        size_key_source: &[u8; 16],
        size_iv_source: &[u8; 16],
        option: u8,
        security: u8,
    ) -> Result<Self, VmessError> {
        let payload = PayloadCipher::new(payload_key, payload_iv, security)?;
        let has_chunk_masking = option & REQUEST_OPTION_CHUNK_MASKING != 0;
        let use_global_padding = option & REQUEST_OPTION_GLOBAL_PADDING != 0;
        let shake = has_chunk_masking.then(|| ShakeState::new(payload_iv));
        let size_mode = if option & REQUEST_OPTION_AUTHENTICATED_LENGTH != 0 {
            SizeMode::AuthenticatedLength(AuthenticatedLengthCipher::new(
                size_key_source,
                size_iv_source,
                security,
            )?)
        } else if has_chunk_masking {
            SizeMode::ShakeMasked
        } else {
            SizeMode::Plain
        };

        Ok(Self {
            payload,
            size_mode,
            shake,
            use_global_padding,
            done: false,
        })
    }

    fn next_padding_len(&mut self) -> Result<usize, VmessError> {
        if !self.use_global_padding {
            return Ok(0);
        }
        self.shake
            .as_mut()
            .map(ShakeState::next_padding_len)
            .ok_or_else(|| {
                VmessError::Protocol("global padding requested without shake state".into())
            })
    }

    fn decode_size(&mut self, reader: &mut impl Read) -> Result<(usize, usize), VmessError> {
        let padding_len = self.next_padding_len()?;
        let size = match &mut self.size_mode {
            SizeMode::Plain => {
                let mut buf = [0u8; 2];
                reader.read_exact(&mut buf)?;
                u16::from_be_bytes(buf) as usize
            }
            SizeMode::ShakeMasked => {
                let mut buf = [0u8; 2];
                reader.read_exact(&mut buf)?;
                let mask = self
                    .shake
                    .as_mut()
                    .ok_or_else(|| VmessError::Protocol("missing shake state".into()))?
                    .next_u16();
                (u16::from_be_bytes(buf) ^ mask) as usize
            }
            SizeMode::AuthenticatedLength(cipher) => {
                let mut buf = [0u8; 18];
                reader.read_exact(&mut buf)?;
                cipher.decode_size(&buf)? as usize
            }
        };
        Ok((size, padding_len))
    }

    pub fn read_chunk(
        &mut self,
        reader: &mut impl Read,
        out: &mut Vec<u8>,
    ) -> Result<bool, VmessError> {
        if self.done {
            return Ok(false);
        }

        let (total_size, padding_len) = match self.decode_size(reader) {
            Ok(values) => values,
            Err(VmessError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(e),
        };
        let payload_overhead = self.payload.overhead();
        if total_size == payload_overhead + padding_len {
            self.done = true;
            return Ok(false);
        }
        if total_size < payload_overhead + padding_len {
            return Err(VmessError::Protocol(format!(
                "chunk smaller than overhead: size={total_size} overhead={payload_overhead} padding={padding_len}"
            )));
        }
        if total_size > MAX_CHUNK_PAYLOAD + payload_overhead + MAX_PADDING_LEN {
            return Err(VmessError::Protocol(format!(
                "chunk too large: {total_size}"
            )));
        }

        let mut chunk = vec![0u8; total_size];
        reader.read_exact(&mut chunk)?;
        let payload_size = total_size - padding_len;
        let plaintext = self.payload.decrypt(&chunk[..payload_size])?;
        out.extend_from_slice(&plaintext);
        Ok(true)
    }
}

pub struct VmessBodyWriter {
    payload: PayloadCipher,
    size_mode: SizeMode,
    shake: Option<ShakeState>,
    use_global_padding: bool,
}

impl VmessBodyWriter {
    pub fn new(payload_key: &[u8; 16], payload_iv: &[u8; 16]) -> Self {
        Self::new_with_options(
            payload_key,
            payload_iv,
            payload_key,
            payload_iv,
            DEFAULT_REQUEST_OPTIONS,
            DEFAULT_SECURITY,
        )
        .expect("default VMess codec should build")
    }

    pub fn new_with_options(
        payload_key: &[u8; 16],
        payload_iv: &[u8; 16],
        size_key_source: &[u8; 16],
        size_iv_source: &[u8; 16],
        option: u8,
        security: u8,
    ) -> Result<Self, VmessError> {
        let payload = PayloadCipher::new(payload_key, payload_iv, security)?;
        let has_chunk_masking = option & REQUEST_OPTION_CHUNK_MASKING != 0;
        let use_global_padding = option & REQUEST_OPTION_GLOBAL_PADDING != 0;
        let shake = has_chunk_masking.then(|| ShakeState::new(payload_iv));
        let size_mode = if option & REQUEST_OPTION_AUTHENTICATED_LENGTH != 0 {
            SizeMode::AuthenticatedLength(AuthenticatedLengthCipher::new(
                size_key_source,
                size_iv_source,
                security,
            )?)
        } else if has_chunk_masking {
            SizeMode::ShakeMasked
        } else {
            SizeMode::Plain
        };

        Ok(Self {
            payload,
            size_mode,
            shake,
            use_global_padding,
        })
    }

    fn next_padding_len(&mut self) -> Result<usize, VmessError> {
        if !self.use_global_padding {
            return Ok(0);
        }
        self.shake
            .as_mut()
            .map(ShakeState::next_padding_len)
            .ok_or_else(|| {
                VmessError::Protocol("global padding requested without shake state".into())
            })
    }

    fn encode_size(&mut self, total_size: u16) -> Result<Vec<u8>, VmessError> {
        match &mut self.size_mode {
            SizeMode::Plain => Ok(total_size.to_be_bytes().to_vec()),
            SizeMode::ShakeMasked => {
                let mask = self
                    .shake
                    .as_mut()
                    .ok_or_else(|| VmessError::Protocol("missing shake state".into()))?
                    .next_u16();
                Ok((mask ^ total_size).to_be_bytes().to_vec())
            }
            SizeMode::AuthenticatedLength(cipher) => cipher.encode_size(total_size),
        }
    }

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
        let ciphertext = self.payload.encrypt(plaintext)?;
        let padding_len = self.next_padding_len()?;
        let total_size = ciphertext
            .len()
            .checked_add(padding_len)
            .ok_or_else(|| VmessError::Protocol("chunk size overflow".into()))?;
        let size_bytes = self.encode_size(total_size as u16)?;
        writer.write_all(&size_bytes)?;
        writer.write_all(&ciphertext)?;
        if padding_len > 0 {
            use rand::RngCore;
            let mut padding = vec![0u8; padding_len];
            rand::rngs::OsRng.fill_bytes(&mut padding);
            writer.write_all(&padding)?;
        }
        Ok(())
    }

    pub fn write_eof(&mut self, writer: &mut impl Write) -> Result<(), VmessError> {
        self.write_chunk(writer, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uuid() -> [u8; 16] {
        let uuid =
            wrongsv_uuid::Uuid::parse_string("41309a00-3cbe-43a2-80e7-76c8a4fe65be").unwrap();
        *uuid.as_bytes()
    }

    #[test]
    fn cmd_key_is_deterministic_and_nonzero() {
        let cmd_key = derive_cmd_key(&test_uuid());
        assert_eq!(cmd_key, derive_cmd_key(&test_uuid()));
        assert_ne!(cmd_key, [0u8; 16]);
    }

    #[test]
    fn eaudid_roundtrip() {
        let cmd_key = derive_cmd_key(&test_uuid());
        let (_plain, auth_id) = generate_eaudid(&cmd_key);
        let ts = verify_eaudid(&cmd_key, &auth_id).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!((ts - now).abs() <= 5);
    }

    #[test]
    fn request_header_roundtrip() {
        use rand::RngCore;

        let cmd_key = derive_cmd_key(&test_uuid());
        let (_plain, auth_id) = generate_eaudid(&cmd_key);
        let mut body_key = [0u8; 16];
        let mut body_iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut body_key);
        rand::rngs::OsRng.fill_bytes(&mut body_iv);
        let request = VmessRequest::standard_tcp("example.com", 443);

        let (_len, payload) =
            build_header(&cmd_key, &auth_id, &body_key, &body_iv, &request).unwrap();
        let header = decrypt_header(&cmd_key, &auth_id, &payload).unwrap();
        assert_eq!(header.command, VmessCommand::Tcp);
        assert_eq!(header.address, "example.com");
        assert_eq!(header.port, 443);
        assert_eq!(header.option, DEFAULT_REQUEST_OPTIONS);
        assert_eq!(header.security, DEFAULT_SECURITY);
        assert_eq!(header.response_header, DEFAULT_RESPONSE_HEADER);
        assert_eq!(header.body_key, body_key);
        assert_eq!(header.body_iv, body_iv);
    }

    #[test]
    fn body_roundtrip_standard_stream() {
        use rand::RngCore;

        let mut body_key = [0u8; 16];
        let mut body_iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut body_key);
        rand::rngs::OsRng.fill_bytes(&mut body_iv);

        let mut writer = VmessBodyWriter::new(&body_key, &body_iv);
        let mut reader = VmessBodyReader::new(&body_key, &body_iv);
        let mut encoded = Vec::new();

        writer.write_chunk(&mut encoded, b"hello ").unwrap();
        writer.write_chunk(&mut encoded, b"world").unwrap();
        writer.write_eof(&mut encoded).unwrap();

        let mut out = Vec::new();
        let mut cursor = std::io::Cursor::new(&encoded);
        assert!(reader.read_chunk(&mut cursor, &mut out).unwrap());
        assert!(reader.read_chunk(&mut cursor, &mut out).unwrap());
        assert!(!reader.read_chunk(&mut cursor, &mut out).unwrap());
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn response_header_roundtrip() {
        use rand::RngCore;

        let mut body_key = [0u8; 16];
        let mut body_iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut body_key);
        rand::rngs::OsRng.fill_bytes(&mut body_iv);

        let payload = build_response(&body_key, &body_iv, 0x5a).unwrap();
        read_response(
            &body_key,
            &body_iv,
            0x5a,
            &mut std::io::Cursor::new(&payload),
        )
        .unwrap();
    }
}
