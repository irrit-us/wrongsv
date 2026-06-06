use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use rand::RngCore;
use sha1::Sha1;
use std::io::{Read, Write};
use wrongsv_net_types::{Address, Port};

const INFO: &[u8] = b"ss-subkey";
const TAG_LEN: usize = 16;
const LEN_SIZE: usize = 2;
const MAX_CHUNK_LEN: usize = 0x3fff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20IetfPoly1305,
}

impl Method {
    pub fn parse(name: &str) -> Result<Self, ShadowsocksError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" | "aead_aes_256_gcm" => Ok(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "aead_chacha20_poly1305" => Ok(Self::ChaCha20IetfPoly1305),
            other => Err(ShadowsocksError::UnsupportedMethod(other.into())),
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20IetfPoly1305 => 32,
        }
    }

    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20IetfPoly1305 => "chacha20-ietf-poly1305",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub method: Method,
    pub password: String,
}

impl ServerConfig {
    pub fn new(method: &str, password: impl Into<String>) -> Result<Self, ShadowsocksError> {
        Ok(Self {
            method: Method::parse(method)?,
            password: password.into(),
        })
    }

    fn master_key(&self) -> Vec<u8> {
        evp_bytes_to_key(self.password.as_bytes(), self.method.key_len())
    }
}

pub fn parse_request_header(data: &[u8]) -> Result<(Address, Port, usize), ShadowsocksError> {
    let atyp = *data.first().ok_or(ShadowsocksError::ShortAddress)?;
    match atyp {
        0x01 => {
            if data.len() < 1 + 4 + 2 {
                return Err(ShadowsocksError::ShortAddress);
            }
            let addr = Address::IPv4([data[1], data[2], data[3], data[4]]);
            let port = Port(u16::from_be_bytes([data[5], data[6]]));
            Ok((addr, port, 7))
        }
        0x03 => {
            let len = *data.get(1).ok_or(ShadowsocksError::ShortAddress)? as usize;
            let end = 2 + len;
            if data.len() < end + 2 {
                return Err(ShadowsocksError::ShortAddress);
            }
            let domain = std::str::from_utf8(&data[2..end])
                .map_err(|_| ShadowsocksError::InvalidAddress)?
                .to_string();
            let port = Port(u16::from_be_bytes([data[end], data[end + 1]]));
            Ok((Address::Domain(domain), port, end + 2))
        }
        0x04 => {
            if data.len() < 1 + 16 + 2 {
                return Err(ShadowsocksError::ShortAddress);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let port = Port(u16::from_be_bytes([data[17], data[18]]));
            Ok((Address::IPv6(octets), port, 19))
        }
        other => Err(ShadowsocksError::InvalidAddressType(other)),
    }
}

pub fn write_request_header(buf: &mut Vec<u8>, address: &Address, port: Port) {
    match address {
        Address::IPv4(octets) => {
            buf.push(0x01);
            buf.extend_from_slice(octets);
        }
        Address::Domain(domain) => {
            buf.push(0x03);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
        }
        Address::IPv6(octets) => {
            buf.push(0x04);
            buf.extend_from_slice(octets);
        }
    }
    buf.extend_from_slice(&port.0.to_be_bytes());
}

pub fn decrypt_udp_packet(
    packet: &[u8],
    config: &ServerConfig,
) -> Result<Vec<u8>, ShadowsocksError> {
    let salt_len = config.method.salt_len();
    if packet.len() < salt_len + TAG_LEN {
        return Err(ShadowsocksError::ShortUdpPacket);
    }
    let (salt, encrypted_payload) = packet.split_at(salt_len);
    let mut crypto = CryptoState::new(config.method, &config.master_key(), salt)?;
    crypto.open(encrypted_payload)
}

pub fn encrypt_udp_packet(
    payload: &[u8],
    config: &ServerConfig,
) -> Result<Vec<u8>, ShadowsocksError> {
    let mut salt = vec![0u8; config.method.salt_len()];
    rand::thread_rng().fill_bytes(&mut salt);
    encrypt_udp_packet_with_salt(payload, config, &salt)
}

pub fn encrypt_udp_packet_with_salt(
    payload: &[u8],
    config: &ServerConfig,
    salt: &[u8],
) -> Result<Vec<u8>, ShadowsocksError> {
    let mut crypto = CryptoState::new(config.method, &config.master_key(), salt)?;
    let encrypted_payload = crypto.seal(payload)?;
    let mut packet = Vec::with_capacity(salt.len() + encrypted_payload.len());
    packet.extend_from_slice(salt);
    packet.extend_from_slice(&encrypted_payload);
    Ok(packet)
}

pub struct ShadowsocksReader<R> {
    inner: R,
    crypto: CryptoState,
}

impl<R: Read> ShadowsocksReader<R> {
    pub fn new(mut inner: R, config: &ServerConfig) -> Result<Self, ShadowsocksError> {
        let mut salt = vec![0u8; config.method.salt_len()];
        inner.read_exact(&mut salt)?;
        Self::new_with_salt(inner, config, &salt)
    }

    pub fn new_with_salt(
        inner: R,
        config: &ServerConfig,
        salt: &[u8],
    ) -> Result<Self, ShadowsocksError> {
        Ok(Self {
            inner,
            crypto: CryptoState::new(config.method, &config.master_key(), salt)?,
        })
    }

    pub fn read_chunk(&mut self) -> Result<Vec<u8>, ShadowsocksError> {
        let mut len_chunk = [0u8; LEN_SIZE + TAG_LEN];
        self.inner.read_exact(&mut len_chunk)?;
        let len_plain = self.crypto.open(&len_chunk)?;
        if len_plain.len() != LEN_SIZE {
            return Err(ShadowsocksError::InvalidChunkLength(len_plain.len()));
        }
        let len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        if len > MAX_CHUNK_LEN {
            return Err(ShadowsocksError::ChunkTooLarge(len));
        }

        let mut payload_chunk = vec![0u8; len + TAG_LEN];
        self.inner.read_exact(&mut payload_chunk)?;
        self.crypto.open(&payload_chunk)
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

pub struct ShadowsocksWriter<W> {
    inner: W,
    crypto: CryptoState,
}

impl<W: Write> ShadowsocksWriter<W> {
    pub fn new(inner: W, config: &ServerConfig) -> Result<Self, ShadowsocksError> {
        let mut salt = vec![0u8; config.method.salt_len()];
        rand::thread_rng().fill_bytes(&mut salt);
        Self::new_with_salt(inner, config, &salt)
    }

    pub fn new_with_salt(
        mut inner: W,
        config: &ServerConfig,
        salt: &[u8],
    ) -> Result<Self, ShadowsocksError> {
        if salt.len() != config.method.salt_len() {
            return Err(ShadowsocksError::InvalidSaltLength {
                expected: config.method.salt_len(),
                actual: salt.len(),
            });
        }
        inner.write_all(salt)?;
        Ok(Self {
            inner,
            crypto: CryptoState::new(config.method, &config.master_key(), salt)?,
        })
    }

    pub fn write_chunk(&mut self, payload: &[u8]) -> Result<(), ShadowsocksError> {
        if payload.len() > MAX_CHUNK_LEN {
            for chunk in payload.chunks(MAX_CHUNK_LEN) {
                self.write_chunk(chunk)?;
            }
            return Ok(());
        }

        let len = (payload.len() as u16).to_be_bytes();
        let encrypted_len = self.crypto.seal(&len)?;
        let encrypted_payload = self.crypto.seal(payload)?;
        self.inner.write_all(&encrypted_len)?;
        self.inner.write_all(&encrypted_payload)?;
        self.inner.flush()?;
        Ok(())
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }
}

enum Cipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

struct CryptoState {
    cipher: Cipher,
    nonce: [u8; 12],
}

impl CryptoState {
    fn new(method: Method, master_key: &[u8], salt: &[u8]) -> Result<Self, ShadowsocksError> {
        if salt.len() != method.salt_len() {
            return Err(ShadowsocksError::InvalidSaltLength {
                expected: method.salt_len(),
                actual: salt.len(),
            });
        }
        let mut subkey = vec![0u8; method.key_len()];
        Hkdf::<Sha1>::new(Some(salt), master_key)
            .expand(INFO, &mut subkey)
            .map_err(|_| ShadowsocksError::KeyDerivation)?;

        let cipher = match method {
            Method::Aes128Gcm => {
                Cipher::Aes128(Box::new(Aes128Gcm::new_from_slice(&subkey).unwrap()))
            }
            Method::Aes256Gcm => {
                Cipher::Aes256(Box::new(Aes256Gcm::new_from_slice(&subkey).unwrap()))
            }
            Method::ChaCha20IetfPoly1305 => {
                Cipher::ChaCha(Box::new(ChaCha20Poly1305::new_from_slice(&subkey).unwrap()))
            }
        };

        Ok(Self {
            cipher,
            nonce: [0u8; 12],
        })
    }

    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ShadowsocksError> {
        let nonce = self.next_nonce();
        match &self.cipher {
            Cipher::Aes128(cipher) => cipher
                .encrypt((&nonce).into(), plaintext)
                .map_err(|_| ShadowsocksError::Encrypt),
            Cipher::Aes256(cipher) => cipher
                .encrypt((&nonce).into(), plaintext)
                .map_err(|_| ShadowsocksError::Encrypt),
            Cipher::ChaCha(cipher) => cipher
                .encrypt((&nonce).into(), plaintext)
                .map_err(|_| ShadowsocksError::Encrypt),
        }
    }

    fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ShadowsocksError> {
        let nonce = self.next_nonce();
        match &self.cipher {
            Cipher::Aes128(cipher) => cipher
                .decrypt((&nonce).into(), ciphertext)
                .map_err(|_| ShadowsocksError::Decrypt),
            Cipher::Aes256(cipher) => cipher
                .decrypt((&nonce).into(), ciphertext)
                .map_err(|_| ShadowsocksError::Decrypt),
            Cipher::ChaCha(cipher) => cipher
                .decrypt((&nonce).into(), ciphertext)
                .map_err(|_| ShadowsocksError::Decrypt),
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

fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while key.len() < key_len {
        let mut hasher = Md5::new();
        if !previous.is_empty() {
            hasher.update(&previous);
        }
        hasher.update(password);
        previous = hasher.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    key
}

#[derive(Debug, thiserror::Error)]
pub enum ShadowsocksError {
    #[error("unsupported shadowsocks method: {0}")]
    UnsupportedMethod(String),
    #[error("invalid salt length: expected {expected}, got {actual}")]
    InvalidSaltLength { expected: usize, actual: usize },
    #[error("failed to derive shadowsocks subkey")]
    KeyDerivation,
    #[error("shadowsocks encryption failed")]
    Encrypt,
    #[error("shadowsocks decryption failed")]
    Decrypt,
    #[error("invalid shadowsocks chunk length plaintext: {0}")]
    InvalidChunkLength(usize),
    #[error("shadowsocks chunk too large: {0}")]
    ChunkTooLarge(usize),
    #[error("short shadowsocks address header")]
    ShortAddress,
    #[error("invalid shadowsocks address type: {0}")]
    InvalidAddressType(u8),
    #[error("invalid shadowsocks address")]
    InvalidAddress,
    #[error("short shadowsocks UDP packet")]
    ShortUdpPacket,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn config(method: Method) -> ServerConfig {
        ServerConfig {
            method,
            password: "correct horse battery staple".into(),
        }
    }

    #[test]
    fn parses_supported_methods() {
        assert_eq!(Method::parse("aes-128-gcm").unwrap(), Method::Aes128Gcm);
        assert_eq!(Method::parse("aes-256-gcm").unwrap(), Method::Aes256Gcm);
        assert_eq!(
            Method::parse("chacha20-ietf-poly1305").unwrap(),
            Method::ChaCha20IetfPoly1305
        );
        assert!(Method::parse("rc4-md5").is_err());
    }

    #[test]
    fn address_header_roundtrips() {
        let cases = [
            (Address::IPv4([127, 0, 0, 1]), Port(8080)),
            (Address::Domain("example.com".into()), Port(443)),
            (
                Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                Port(53),
            ),
        ];

        for (address, port) in cases {
            let mut buf = Vec::new();
            write_request_header(&mut buf, &address, port);
            let (decoded_address, decoded_port, consumed) = parse_request_header(&buf).unwrap();
            assert_eq!(decoded_address, address);
            assert_eq!(decoded_port, port);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn tcp_chunks_roundtrip_for_supported_methods() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::ChaCha20IetfPoly1305,
        ] {
            let config = config(method);
            let salt = vec![0x5a; method.salt_len()];
            let mut wire = Vec::new();
            {
                let mut writer =
                    ShadowsocksWriter::new_with_salt(&mut wire, &config, &salt).unwrap();
                writer.write_chunk(b"first").unwrap();
                writer.write_chunk(b"second").unwrap();
            }

            let mut reader = ShadowsocksReader::new(Cursor::new(wire), &config).unwrap();
            assert_eq!(reader.read_chunk().unwrap(), b"first");
            assert_eq!(reader.read_chunk().unwrap(), b"second");
        }
    }

    #[test]
    fn large_payload_is_split_into_chunks() {
        let config = config(Method::ChaCha20IetfPoly1305);
        let salt = vec![0x33; config.method.salt_len()];
        let payload = vec![0xab; MAX_CHUNK_LEN + 17];
        let mut wire = Vec::new();
        {
            let mut writer = ShadowsocksWriter::new_with_salt(&mut wire, &config, &salt).unwrap();
            writer.write_chunk(&payload).unwrap();
        }

        let mut reader = ShadowsocksReader::new(Cursor::new(wire), &config).unwrap();
        assert_eq!(reader.read_chunk().unwrap(), vec![0xab; MAX_CHUNK_LEN]);
        assert_eq!(reader.read_chunk().unwrap(), vec![0xab; 17]);
    }

    #[test]
    fn udp_packets_roundtrip_for_supported_methods() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::ChaCha20IetfPoly1305,
        ] {
            let config = config(method);
            let salt = vec![0x22; method.salt_len()];
            let mut payload = Vec::new();
            write_request_header(
                &mut payload,
                &Address::Domain("example.com".into()),
                Port(443),
            );
            payload.extend_from_slice(b"udp payload");

            let packet = encrypt_udp_packet_with_salt(&payload, &config, &salt).unwrap();
            let decrypted = decrypt_udp_packet(&packet, &config).unwrap();
            assert_eq!(decrypted, payload);
        }
    }

    #[test]
    fn short_udp_packets_are_rejected() {
        let config = config(Method::ChaCha20IetfPoly1305);
        assert!(matches!(
            decrypt_udp_packet(&[0u8; 4], &config),
            Err(ShadowsocksError::ShortUdpPacket)
        ));
    }
}
