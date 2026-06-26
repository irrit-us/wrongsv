use std::collections::VecDeque;
use std::io::{Read, Write};

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Algorithm, Argon2, Params, Version as ArgonVersion};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use wrongsv_net_types::{Address, Port};

const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;
const LEN_SIZE: usize = 2;
const MAX_CHUNK_LEN: usize = 0x3fff;

pub const WIRE_VERSION: u8 = 1;
pub const COMMAND_CONNECT: u8 = 1;
pub const COMMAND_CONNECT_V2: u8 = 5;
pub const COMMAND_UDP: u8 = 6;
pub const COMMAND_TUNNEL: u8 = 0;
pub const COMMAND_ERROR: u8 = 2;
pub const COMMAND_UDP_FORWARD: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnellVersion {
    V1,
    V2,
    V3,
}

impl SnellVersion {
    pub fn parse(value: u8) -> Result<Self, SnellError> {
        match value {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            other => Err(SnellError::UnsupportedVersion(other)),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::V1 => 32,
            Self::V2 | Self::V3 => 16,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnellConfig {
    psk: Vec<u8>,
    version: SnellVersion,
}

impl SnellConfig {
    pub fn new(psk: impl Into<Vec<u8>>, version: u8) -> Result<Self, SnellError> {
        let psk = psk.into();
        if psk.is_empty() {
            return Err(SnellError::EmptyPsk);
        }
        Ok(Self {
            psk,
            version: SnellVersion::parse(version)?,
        })
    }

    pub fn psk(&self) -> &[u8] {
        &self.psk
    }

    pub fn version(&self) -> SnellVersion {
        self.version
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientCommand {
    Connect {
        address: Address,
        port: Port,
        initial_payload: Vec<u8>,
    },
    Udp,
}

pub fn encode_connect_header(
    host: &str,
    port: u16,
    version: SnellVersion,
) -> Result<Vec<u8>, SnellError> {
    let host_bytes = host.as_bytes();
    if host_bytes.is_empty() || host_bytes.len() > u8::MAX as usize {
        return Err(SnellError::InvalidAddress);
    }
    let command = if version == SnellVersion::V2 {
        COMMAND_CONNECT_V2
    } else {
        COMMAND_CONNECT
    };
    let mut out = Vec::with_capacity(6 + host_bytes.len());
    out.push(WIRE_VERSION);
    out.push(command);
    out.push(0);
    out.push(host_bytes.len() as u8);
    out.extend_from_slice(host_bytes);
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

pub fn encode_udp_header() -> Vec<u8> {
    vec![WIRE_VERSION, COMMAND_UDP, 0]
}

pub fn parse_client_command(data: &[u8]) -> Result<ClientCommand, SnellError> {
    let mut pos = 0;
    let version = read_u8(data, &mut pos)?;
    if version != WIRE_VERSION {
        return Err(SnellError::InvalidWireVersion(version));
    }
    let command = read_u8(data, &mut pos)?;
    let client_id_len = read_u8(data, &mut pos)? as usize;
    if data.len() < pos + client_id_len {
        return Err(SnellError::InvalidHeader);
    }
    pos += client_id_len;

    match command {
        COMMAND_CONNECT | COMMAND_CONNECT_V2 => {
            let host_len = read_u8(data, &mut pos)? as usize;
            if host_len == 0 || data.len() < pos + host_len + 2 {
                return Err(SnellError::InvalidAddress);
            }
            let host = std::str::from_utf8(&data[pos..pos + host_len])
                .map_err(|_| SnellError::InvalidAddress)?
                .to_string();
            pos += host_len;
            let port = read_u16(data, &mut pos)?;
            Ok(ClientCommand::Connect {
                address: Address::Domain(host),
                port: Port(port),
                initial_payload: data[pos..].to_vec(),
            })
        }
        COMMAND_UDP => Ok(ClientCommand::Udp),
        other => Err(SnellError::UnsupportedCommand(other)),
    }
}

pub fn encode_error_response(code: u8, message: &str) -> Vec<u8> {
    let message = message.as_bytes();
    let len = message.len().min(u8::MAX as usize);
    let mut out = Vec::with_capacity(3 + len);
    out.push(COMMAND_ERROR);
    out.push(code);
    out.push(len as u8);
    out.extend_from_slice(&message[..len]);
    out
}

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, SnellError> {
    let value = *data.get(*pos).ok_or(SnellError::InvalidHeader)?;
    *pos += 1;
    Ok(value)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, SnellError> {
    if data.len() < *pos + 2 {
        return Err(SnellError::InvalidHeader);
    }
    let value = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Ok(value)
}

enum Cipher {
    Aes128(Box<Aes128Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

struct CryptoState {
    cipher: Cipher,
    nonce: [u8; 12],
}

impl CryptoState {
    fn new(config: &SnellConfig, salt: &[u8]) -> Result<Self, SnellError> {
        if salt.len() != SALT_LEN {
            return Err(SnellError::InvalidSaltLength {
                expected: SALT_LEN,
                actual: salt.len(),
            });
        }
        let key = derive_key(config.version, &config.psk, salt)?;
        let cipher = match config.version {
            SnellVersion::V1 => Cipher::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(&key).map_err(|_| SnellError::InvalidKey)?,
            )),
            SnellVersion::V2 | SnellVersion::V3 => Cipher::Aes128(Box::new(
                Aes128Gcm::new_from_slice(&key).map_err(|_| SnellError::InvalidKey)?,
            )),
        };
        Ok(Self {
            cipher,
            nonce: [0u8; 12],
        })
    }

    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SnellError> {
        let nonce = self.next_nonce();
        match &self.cipher {
            Cipher::Aes128(cipher) => cipher
                .encrypt((&nonce).into(), plaintext)
                .map_err(|_| SnellError::Encrypt),
            Cipher::ChaCha(cipher) => cipher
                .encrypt((&nonce).into(), plaintext)
                .map_err(|_| SnellError::Encrypt),
        }
    }

    fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SnellError> {
        let nonce = self.next_nonce();
        match &self.cipher {
            Cipher::Aes128(cipher) => cipher
                .decrypt((&nonce).into(), ciphertext)
                .map_err(|_| SnellError::Decrypt),
            Cipher::ChaCha(cipher) => cipher
                .decrypt((&nonce).into(), ciphertext)
                .map_err(|_| SnellError::Decrypt),
        }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let current = self.nonce;
        for byte in &mut self.nonce {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        current
    }
}

fn derive_key(version: SnellVersion, psk: &[u8], salt: &[u8]) -> Result<Vec<u8>, SnellError> {
    let params = Params::new(8, 3, 1, Some(32)).map_err(|_| SnellError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, ArgonVersion::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(psk, salt, &mut out)
        .map_err(|_| SnellError::KeyDerivation)?;
    Ok(out[..version.key_len()].to_vec())
}

pub struct SnellReader<R> {
    inner: R,
    crypto: CryptoState,
    pending: VecDeque<u8>,
}

impl<R: Read> SnellReader<R> {
    pub fn new(mut inner: R, config: &SnellConfig) -> Result<Self, SnellError> {
        let mut salt = [0u8; SALT_LEN];
        inner.read_exact(&mut salt)?;
        Ok(Self {
            inner,
            crypto: CryptoState::new(config, &salt)?,
            pending: VecDeque::new(),
        })
    }

    pub fn read_chunk(&mut self) -> Result<Vec<u8>, SnellError> {
        let mut encrypted_len = [0u8; LEN_SIZE + TAG_LEN];
        self.inner.read_exact(&mut encrypted_len)?;
        let plain_len = self.crypto.open(&encrypted_len)?;
        if plain_len.len() != LEN_SIZE {
            return Err(SnellError::InvalidChunkLength(plain_len.len()));
        }
        let len = u16::from_be_bytes([plain_len[0], plain_len[1]]) as usize;
        if len == 0 {
            return Ok(Vec::new());
        }
        if len > MAX_CHUNK_LEN {
            return Err(SnellError::ChunkTooLarge(len));
        }
        let mut encrypted_payload = vec![0u8; len + TAG_LEN];
        self.inner.read_exact(&mut encrypted_payload)?;
        self.crypto.open(&encrypted_payload)
    }
}

impl<R: Read> Read for SnellReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            for slot in buf.iter_mut().take(n) {
                *slot = self.pending.pop_front().expect("pending data");
            }
            return Ok(n);
        }
        let chunk = self
            .read_chunk()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        if chunk.is_empty() {
            return Ok(0);
        }
        let n = chunk.len().min(buf.len());
        buf[..n].copy_from_slice(&chunk[..n]);
        if n < chunk.len() {
            self.pending.extend(&chunk[n..]);
        }
        Ok(n)
    }
}

pub struct SnellWriter<W> {
    inner: W,
    crypto: CryptoState,
}

impl<W: Write> SnellWriter<W> {
    pub fn new(mut inner: W, config: &SnellConfig) -> Result<Self, SnellError> {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        inner.write_all(&salt)?;
        Ok(Self {
            inner,
            crypto: CryptoState::new(config, &salt)?,
        })
    }

    pub fn write_chunk(&mut self, payload: &[u8]) -> Result<(), SnellError> {
        if payload.len() > MAX_CHUNK_LEN {
            for chunk in payload.chunks(MAX_CHUNK_LEN) {
                self.write_chunk(chunk)?;
            }
            return Ok(());
        }
        let len = (payload.len() as u16).to_be_bytes();
        let encrypted_len = self.crypto.seal(&len)?;
        self.inner.write_all(&encrypted_len)?;
        if !payload.is_empty() {
            let encrypted_payload = self.crypto.seal(payload)?;
            self.inner.write_all(&encrypted_payload)?;
        }
        self.inner.flush()?;
        Ok(())
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }
}

impl<W: Write> Write for SnellWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_chunk(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SnellError {
    #[error("unsupported Snell version: {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported Snell command: {0}")]
    UnsupportedCommand(u8),
    #[error("invalid Snell wire version: {0}")]
    InvalidWireVersion(u8),
    #[error("Snell PSK must be non-empty")]
    EmptyPsk,
    #[error("invalid Snell key")]
    InvalidKey,
    #[error("invalid Snell salt length: expected {expected}, got {actual}")]
    InvalidSaltLength { expected: usize, actual: usize },
    #[error("failed to derive Snell key")]
    KeyDerivation,
    #[error("Snell encryption failed")]
    Encrypt,
    #[error("Snell decryption failed")]
    Decrypt,
    #[error("invalid Snell chunk length plaintext: {0}")]
    InvalidChunkLength(usize),
    #[error("Snell chunk too large: {0}")]
    ChunkTooLarge(usize),
    #[error("invalid Snell header")]
    InvalidHeader,
    #[error("invalid Snell address")]
    InvalidAddress,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn snell_v1_stream_round_trips_chunks() {
        let config = SnellConfig::new(b"secret".to_vec(), 1).unwrap();
        let mut wire = Vec::new();
        {
            let mut writer = SnellWriter::new(&mut wire, &config).unwrap();
            writer.write_chunk(b"hello").unwrap();
            writer.write_chunk(b"world").unwrap();
        }

        let mut reader = SnellReader::new(Cursor::new(wire), &config).unwrap();
        assert_eq!(reader.read_chunk().unwrap(), b"hello");
        assert_eq!(reader.read_chunk().unwrap(), b"world");
    }

    #[test]
    fn connect_header_round_trips() {
        let header = encode_connect_header("example.com", 443, SnellVersion::V1).unwrap();
        let command = parse_client_command(&header).unwrap();
        assert_eq!(
            command,
            ClientCommand::Connect {
                address: Address::Domain("example.com".into()),
                port: Port(443),
                initial_payload: Vec::new(),
            }
        );
    }
}
