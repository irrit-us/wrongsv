use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use base64::Engine;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use rand::RngCore;
use sha1::Sha1;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wrongsv_net_types::{Address, Port};

const INFO: &[u8] = b"ss-subkey";
const AEAD_2022_INFO: &str = "shadowsocks 2022 session subkey";
const TAG_LEN: usize = 16;
const LEN_SIZE: usize = 2;
const MAX_CHUNK_LEN: usize = 0x3fff;
const MAX_2022_CHUNK_LEN: usize = 0xffff;
const AEAD_2022_REQUEST_FIXED_HEADER_LEN: usize = 11;
const AEAD_2022_HEADER_TYPE_CLIENT_STREAM: u8 = 0;
const AEAD_2022_HEADER_TYPE_SERVER_STREAM: u8 = 1;
const AEAD_2022_MAX_TIME_DIFF_SECS: u64 = 30;
const AEAD_2022_REPLAY_WINDOW_SECS: u64 = 60;

type ReplayEntry = (Instant, Vec<u8>);
type ReplayCache = Arc<Mutex<VecDeque<ReplayEntry>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20IetfPoly1305,
    Aead2022Blake3Aes128Gcm,
    Aead2022Blake3Aes256Gcm,
}

impl Method {
    pub fn parse(name: &str) -> Result<Self, ShadowsocksError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" | "aead_aes_256_gcm" => Ok(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "aead_chacha20_poly1305" => Ok(Self::ChaCha20IetfPoly1305),
            "2022-blake3-aes-128-gcm" => Ok(Self::Aead2022Blake3Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aead2022Blake3Aes256Gcm),
            other => Err(ShadowsocksError::UnsupportedMethod(other.into())),
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aead2022Blake3Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20IetfPoly1305 | Self::Aead2022Blake3Aes256Gcm => 32,
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
            Self::Aead2022Blake3Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Aead2022Blake3Aes256Gcm => "2022-blake3-aes-256-gcm",
        }
    }

    pub fn is_aead_2022(self) -> bool {
        matches!(
            self,
            Self::Aead2022Blake3Aes128Gcm | Self::Aead2022Blake3Aes256Gcm
        )
    }

    fn max_chunk_len(self) -> usize {
        if self.is_aead_2022() {
            MAX_2022_CHUNK_LEN
        } else {
            MAX_CHUNK_LEN
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub method: Method,
    pub password: String,
    tcp_prefix: Vec<u8>,
    udp_prefix: Vec<u8>,
    replay_cache: ReplayCache,
}

impl ServerConfig {
    pub fn new(method: &str, password: impl Into<String>) -> Result<Self, ShadowsocksError> {
        Self::new_with_prefixes(method, password, Vec::new(), Vec::new())
    }

    pub fn new_with_prefixes(
        method: &str,
        password: impl Into<String>,
        tcp_prefix: Vec<u8>,
        udp_prefix: Vec<u8>,
    ) -> Result<Self, ShadowsocksError> {
        let method = Method::parse(method)?;
        let password = password.into();
        validate_salt_prefix(method, &tcp_prefix)?;
        validate_salt_prefix(method, &udp_prefix)?;
        if method.is_aead_2022() {
            validate_aead_2022_psk(&password, method)?;
            return Ok(Self {
                method,
                password,
                tcp_prefix,
                udp_prefix,
                replay_cache: Arc::new(Mutex::new(VecDeque::new())),
            });
        }
        Ok(Self {
            method,
            password,
            tcp_prefix,
            udp_prefix,
            replay_cache: Arc::new(Mutex::new(VecDeque::new())),
        })
    }

    fn master_key(&self) -> Result<Vec<u8>, ShadowsocksError> {
        if self.method.is_aead_2022() {
            decode_aead_2022_psk(&self.password, self.method)
        } else {
            Ok(evp_bytes_to_key(
                self.password.as_bytes(),
                self.method.key_len(),
            ))
        }
    }

    fn check_and_store_replay_salt(&self, salt: &[u8]) -> Result<(), ShadowsocksError> {
        if !self.method.is_aead_2022() {
            return Ok(());
        }
        let mut cache = self
            .replay_cache
            .lock()
            .map_err(|_| ShadowsocksError::ReplayCachePoisoned)?;
        let now = Instant::now();
        while cache.front().is_some_and(|(seen, _)| {
            now.duration_since(*seen) > Duration::from_secs(AEAD_2022_REPLAY_WINDOW_SECS)
        }) {
            cache.pop_front();
        }
        if cache.iter().any(|(_, cached)| cached.as_slice() == salt) {
            return Err(ShadowsocksError::ReplayDetected);
        }
        cache.push_back((now, salt.to_vec()));
        Ok(())
    }
}

fn validate_salt_prefix(method: Method, prefix: &[u8]) -> Result<(), ShadowsocksError> {
    if method.is_aead_2022() && !prefix.is_empty() {
        return Err(ShadowsocksError::SaltPrefixUnsupportedForMethod(
            method.name().into(),
        ));
    }
    if prefix.len() > 16 || prefix.len() > method.salt_len() {
        return Err(ShadowsocksError::InvalidSaltPrefixLength {
            max: 16.min(method.salt_len()),
            actual: prefix.len(),
        });
    }
    Ok(())
}

fn random_salt(method: Method, prefix: &[u8]) -> Result<Vec<u8>, ShadowsocksError> {
    validate_salt_prefix(method, prefix)?;
    let mut salt = vec![0u8; method.salt_len()];
    rand::thread_rng().fill_bytes(&mut salt);
    salt[..prefix.len()].copy_from_slice(prefix);
    Ok(salt)
}

fn validate_aead_2022_psk(password: &str, method: Method) -> Result<(), ShadowsocksError> {
    decode_aead_2022_psk(password, method).map(|_| ())
}

fn decode_aead_2022_psk(password: &str, method: Method) -> Result<Vec<u8>, ShadowsocksError> {
    let password = password.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(password)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(password))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(password))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(password))
        .map_err(|_| ShadowsocksError::InvalidKey)?;
    if decoded.len() != method.key_len() {
        return Err(ShadowsocksError::InvalidKeyLength {
            expected: method.key_len(),
            actual: decoded.len(),
        });
    }
    Ok(decoded)
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
    if config.method.is_aead_2022() {
        return Err(ShadowsocksError::UnsupportedUdpMethod(
            config.method.name().into(),
        ));
    }
    let salt_len = config.method.salt_len();
    if packet.len() < salt_len + TAG_LEN {
        return Err(ShadowsocksError::ShortUdpPacket);
    }
    let (salt, encrypted_payload) = packet.split_at(salt_len);
    let mut crypto = CryptoState::new(config.method, &config.master_key()?, salt)?;
    crypto.open(encrypted_payload)
}

pub fn encrypt_udp_packet(
    payload: &[u8],
    config: &ServerConfig,
) -> Result<Vec<u8>, ShadowsocksError> {
    if config.method.is_aead_2022() {
        return Err(ShadowsocksError::UnsupportedUdpMethod(
            config.method.name().into(),
        ));
    }
    let salt = random_salt(config.method, &config.udp_prefix)?;
    encrypt_udp_packet_with_salt(payload, config, &salt)
}

pub fn encrypt_udp_packet_with_salt(
    payload: &[u8],
    config: &ServerConfig,
    salt: &[u8],
) -> Result<Vec<u8>, ShadowsocksError> {
    if config.method.is_aead_2022() {
        return Err(ShadowsocksError::UnsupportedUdpMethod(
            config.method.name().into(),
        ));
    }
    let mut crypto = CryptoState::new(config.method, &config.master_key()?, salt)?;
    let encrypted_payload = crypto.seal(payload)?;
    let mut packet = Vec::with_capacity(salt.len() + encrypted_payload.len());
    packet.extend_from_slice(salt);
    packet.extend_from_slice(&encrypted_payload);
    Ok(packet)
}

pub struct ShadowsocksReader<R> {
    inner: R,
    crypto: CryptoState,
    method: Method,
    pending_chunks: VecDeque<Vec<u8>>,
    request_salt: Option<Vec<u8>>,
}

impl<R: Read> ShadowsocksReader<R> {
    pub fn new(mut inner: R, config: &ServerConfig) -> Result<Self, ShadowsocksError> {
        let mut salt = vec![0u8; config.method.salt_len()];
        inner.read_exact(&mut salt)?;
        Self::new_with_salt(inner, config, &salt)
    }

    pub fn new_with_salt(
        mut inner: R,
        config: &ServerConfig,
        salt: &[u8],
    ) -> Result<Self, ShadowsocksError> {
        let mut crypto = CryptoState::new(config.method, &config.master_key()?, salt)?;
        if !config.method.is_aead_2022() {
            return Ok(Self {
                inner,
                crypto,
                method: config.method,
                pending_chunks: VecDeque::new(),
                request_salt: None,
            });
        }

        let mut fixed_header = vec![0u8; AEAD_2022_REQUEST_FIXED_HEADER_LEN + TAG_LEN];
        inner.read_exact(&mut fixed_header)?;
        let fixed_header = crypto.open(&fixed_header)?;
        let variable_header_len = parse_aead_2022_request_fixed_header(&fixed_header)?;
        config.check_and_store_replay_salt(salt)?;

        let mut variable_header = vec![0u8; variable_header_len + TAG_LEN];
        inner.read_exact(&mut variable_header)?;
        let variable_header = crypto.open(&variable_header)?;
        let first_chunk = decode_aead_2022_request_variable_header(&variable_header)?;

        let mut pending_chunks = VecDeque::new();
        pending_chunks.push_back(first_chunk);
        Ok(Self {
            inner,
            crypto,
            method: config.method,
            pending_chunks,
            request_salt: Some(salt.to_vec()),
        })
    }

    pub fn new_response(
        mut inner: R,
        config: &ServerConfig,
        request_salt: Option<&[u8]>,
    ) -> Result<Self, ShadowsocksError> {
        if !config.method.is_aead_2022() {
            return Self::new(inner, config);
        }
        let request_salt = request_salt.ok_or(ShadowsocksError::MissingRequestSalt)?;
        if request_salt.len() != config.method.salt_len() {
            return Err(ShadowsocksError::InvalidSaltLength {
                expected: config.method.salt_len(),
                actual: request_salt.len(),
            });
        }

        let mut salt = vec![0u8; config.method.salt_len()];
        inner.read_exact(&mut salt)?;
        let mut crypto = CryptoState::new(config.method, &config.master_key()?, &salt)?;
        let mut fixed_header =
            vec![0u8; aead_2022_response_fixed_header_len(config.method) + TAG_LEN];
        inner.read_exact(&mut fixed_header)?;
        let fixed_header = crypto.open(&fixed_header)?;
        let payload_len =
            parse_aead_2022_response_fixed_header(&fixed_header, config.method, request_salt)?;
        let mut payload_chunk = vec![0u8; payload_len + TAG_LEN];
        inner.read_exact(&mut payload_chunk)?;
        let payload = crypto.open(&payload_chunk)?;
        let mut pending_chunks = VecDeque::new();
        pending_chunks.push_back(payload);

        Ok(Self {
            inner,
            crypto,
            method: config.method,
            pending_chunks,
            request_salt: None,
        })
    }

    pub fn read_chunk(&mut self) -> Result<Vec<u8>, ShadowsocksError> {
        if let Some(chunk) = self.pending_chunks.pop_front() {
            return Ok(chunk);
        }

        let mut len_chunk = [0u8; LEN_SIZE + TAG_LEN];
        self.inner.read_exact(&mut len_chunk)?;
        let len_plain = self.crypto.open(&len_chunk)?;
        if len_plain.len() != LEN_SIZE {
            return Err(ShadowsocksError::InvalidChunkLength(len_plain.len()));
        }
        let len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        if len > self.method.max_chunk_len() {
            return Err(ShadowsocksError::ChunkTooLarge(len));
        }

        let mut payload_chunk = vec![0u8; len + TAG_LEN];
        self.inner.read_exact(&mut payload_chunk)?;
        self.crypto.open(&payload_chunk)
    }

    pub fn request_salt(&self) -> Option<&[u8]> {
        self.request_salt.as_deref()
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

pub struct ShadowsocksWriter<W> {
    inner: W,
    crypto: CryptoState,
    method: Method,
    aead_2022_response_header: Option<Aead2022ResponseHeader>,
}

struct Aead2022ResponseHeader {
    salt: Vec<u8>,
    request_salt: Vec<u8>,
}

impl<W: Write> ShadowsocksWriter<W> {
    pub fn new(inner: W, config: &ServerConfig) -> Result<Self, ShadowsocksError> {
        let salt = random_salt(config.method, &config.tcp_prefix)?;
        Self::new_with_salt(inner, config, &salt)
    }

    pub fn new_with_salt(
        mut inner: W,
        config: &ServerConfig,
        salt: &[u8],
    ) -> Result<Self, ShadowsocksError> {
        if config.method.is_aead_2022() {
            return Err(ShadowsocksError::MissingRequestSalt);
        }
        if salt.len() != config.method.salt_len() {
            return Err(ShadowsocksError::InvalidSaltLength {
                expected: config.method.salt_len(),
                actual: salt.len(),
            });
        }
        inner.write_all(salt)?;
        Ok(Self {
            inner,
            crypto: CryptoState::new(config.method, &config.master_key()?, salt)?,
            method: config.method,
            aead_2022_response_header: None,
        })
    }

    pub fn new_response(
        inner: W,
        config: &ServerConfig,
        request_salt: Option<&[u8]>,
    ) -> Result<Self, ShadowsocksError> {
        if !config.method.is_aead_2022() {
            return Self::new(inner, config);
        }
        let salt = random_salt(config.method, &config.tcp_prefix)?;
        Self::new_response_with_salt(inner, config, request_salt, &salt)
    }

    pub fn new_response_with_salt(
        inner: W,
        config: &ServerConfig,
        request_salt: Option<&[u8]>,
        salt: &[u8],
    ) -> Result<Self, ShadowsocksError> {
        if !config.method.is_aead_2022() {
            return Self::new_with_salt(inner, config, salt);
        }
        let request_salt = request_salt.ok_or(ShadowsocksError::MissingRequestSalt)?;
        if request_salt.len() != config.method.salt_len() {
            return Err(ShadowsocksError::InvalidSaltLength {
                expected: config.method.salt_len(),
                actual: request_salt.len(),
            });
        }
        if salt.len() != config.method.salt_len() {
            return Err(ShadowsocksError::InvalidSaltLength {
                expected: config.method.salt_len(),
                actual: salt.len(),
            });
        }
        Ok(Self {
            inner,
            crypto: CryptoState::new(config.method, &config.master_key()?, salt)?,
            method: config.method,
            aead_2022_response_header: Some(Aead2022ResponseHeader {
                salt: salt.to_vec(),
                request_salt: request_salt.to_vec(),
            }),
        })
    }

    pub fn new_request(
        inner: W,
        config: &ServerConfig,
        address: &Address,
        port: Port,
        initial_payload: &[u8],
    ) -> Result<(Self, Vec<u8>), ShadowsocksError> {
        let salt = random_salt(config.method, &config.tcp_prefix)?;
        Self::new_request_with_salt(inner, config, address, port, initial_payload, &salt)
    }

    pub fn new_request_with_salt(
        mut inner: W,
        config: &ServerConfig,
        address: &Address,
        port: Port,
        initial_payload: &[u8],
        salt: &[u8],
    ) -> Result<(Self, Vec<u8>), ShadowsocksError> {
        if !config.method.is_aead_2022() {
            let mut writer = Self::new_with_salt(inner, config, salt)?;
            let mut first_chunk = Vec::new();
            write_request_header(&mut first_chunk, address, port);
            first_chunk.extend_from_slice(initial_payload);
            writer.write_chunk(&first_chunk)?;
            return Ok((writer, Vec::new()));
        }
        if salt.len() != config.method.salt_len() {
            return Err(ShadowsocksError::InvalidSaltLength {
                expected: config.method.salt_len(),
                actual: salt.len(),
            });
        }

        let mut crypto = CryptoState::new(config.method, &config.master_key()?, salt)?;
        inner.write_all(salt)?;
        let variable_header =
            encode_aead_2022_request_variable_header(address, port, initial_payload)?;
        let fixed_header = encode_aead_2022_request_fixed_header(variable_header.len())?;
        inner.write_all(&crypto.seal(&fixed_header)?)?;
        inner.write_all(&crypto.seal(&variable_header)?)?;
        inner.flush()?;

        Ok((
            Self {
                inner,
                crypto,
                method: config.method,
                aead_2022_response_header: None,
            },
            salt.to_vec(),
        ))
    }

    pub fn write_chunk(&mut self, payload: &[u8]) -> Result<(), ShadowsocksError> {
        if payload.len() > self.method.max_chunk_len() {
            let chunk_len = self.method.max_chunk_len();
            for chunk in payload.chunks(chunk_len) {
                self.write_chunk(chunk)?;
            }
            return Ok(());
        }

        if let Some(header) = self.aead_2022_response_header.take() {
            self.inner.write_all(&header.salt)?;
            let fixed_header =
                encode_aead_2022_response_fixed_header(&header.request_salt, payload.len())?;
            self.inner.write_all(&self.crypto.seal(&fixed_header)?)?;
            self.inner.write_all(&self.crypto.seal(payload)?)?;
            self.inner.flush()?;
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

fn unix_time_secs() -> Result<u64, ShadowsocksError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShadowsocksError::InvalidTimestamp)?
        .as_secs())
}

fn validate_timestamp(timestamp: u64) -> Result<(), ShadowsocksError> {
    let now = unix_time_secs()?;
    let diff = now.abs_diff(timestamp);
    if diff > AEAD_2022_MAX_TIME_DIFF_SECS {
        return Err(ShadowsocksError::InvalidTimestamp);
    }
    Ok(())
}

fn parse_aead_2022_request_fixed_header(data: &[u8]) -> Result<usize, ShadowsocksError> {
    if data.len() != AEAD_2022_REQUEST_FIXED_HEADER_LEN {
        return Err(ShadowsocksError::InvalidHeader);
    }
    if data[0] != AEAD_2022_HEADER_TYPE_CLIENT_STREAM {
        return Err(ShadowsocksError::InvalidHeader);
    }
    let timestamp = u64::from_be_bytes(
        data[1..9]
            .try_into()
            .map_err(|_| ShadowsocksError::InvalidHeader)?,
    );
    validate_timestamp(timestamp)?;
    Ok(u16::from_be_bytes([data[9], data[10]]) as usize)
}

fn encode_aead_2022_request_fixed_header(
    variable_header_len: usize,
) -> Result<Vec<u8>, ShadowsocksError> {
    let len = u16::try_from(variable_header_len)
        .map_err(|_| ShadowsocksError::ChunkTooLarge(variable_header_len))?;
    let mut out = Vec::with_capacity(AEAD_2022_REQUEST_FIXED_HEADER_LEN);
    out.push(AEAD_2022_HEADER_TYPE_CLIENT_STREAM);
    out.extend_from_slice(&unix_time_secs()?.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    Ok(out)
}

fn encode_aead_2022_request_variable_header(
    address: &Address,
    port: Port,
    initial_payload: &[u8],
) -> Result<Vec<u8>, ShadowsocksError> {
    let mut out = Vec::new();
    write_request_header(&mut out, address, port);
    if initial_payload.is_empty() {
        out.extend_from_slice(&1u16.to_be_bytes());
        let mut padding = [0u8; 1];
        rand::thread_rng().fill_bytes(&mut padding);
        out.extend_from_slice(&padding);
    } else {
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(initial_payload);
    }
    if out.len() > u16::MAX as usize {
        return Err(ShadowsocksError::ChunkTooLarge(out.len()));
    }
    Ok(out)
}

fn decode_aead_2022_request_variable_header(data: &[u8]) -> Result<Vec<u8>, ShadowsocksError> {
    let (_address, _port, consumed) = parse_request_header(data)?;
    if data.len() < consumed + 2 {
        return Err(ShadowsocksError::InvalidHeader);
    }
    let padding_len = u16::from_be_bytes([data[consumed], data[consumed + 1]]) as usize;
    let payload_start = consumed + 2 + padding_len;
    if data.len() < payload_start {
        return Err(ShadowsocksError::InvalidHeader);
    }
    let initial_payload = &data[payload_start..];
    if padding_len == 0 && initial_payload.is_empty() {
        return Err(ShadowsocksError::InvalidHeader);
    }

    let mut first_chunk = Vec::with_capacity(consumed + initial_payload.len());
    first_chunk.extend_from_slice(&data[..consumed]);
    first_chunk.extend_from_slice(initial_payload);
    Ok(first_chunk)
}

fn aead_2022_response_fixed_header_len(method: Method) -> usize {
    1 + 8 + method.salt_len() + 2
}

fn parse_aead_2022_response_fixed_header(
    data: &[u8],
    method: Method,
    request_salt: &[u8],
) -> Result<usize, ShadowsocksError> {
    if data.len() != aead_2022_response_fixed_header_len(method) {
        return Err(ShadowsocksError::InvalidHeader);
    }
    if data[0] != AEAD_2022_HEADER_TYPE_SERVER_STREAM {
        return Err(ShadowsocksError::InvalidHeader);
    }
    let timestamp = u64::from_be_bytes(
        data[1..9]
            .try_into()
            .map_err(|_| ShadowsocksError::InvalidHeader)?,
    );
    validate_timestamp(timestamp)?;
    let salt_end = 9 + method.salt_len();
    if &data[9..salt_end] != request_salt {
        return Err(ShadowsocksError::InvalidHeader);
    }
    Ok(u16::from_be_bytes([data[salt_end], data[salt_end + 1]]) as usize)
}

fn encode_aead_2022_response_fixed_header(
    request_salt: &[u8],
    payload_len: usize,
) -> Result<Vec<u8>, ShadowsocksError> {
    let len =
        u16::try_from(payload_len).map_err(|_| ShadowsocksError::ChunkTooLarge(payload_len))?;
    let mut out = Vec::with_capacity(1 + 8 + request_salt.len() + 2);
    out.push(AEAD_2022_HEADER_TYPE_SERVER_STREAM);
    out.extend_from_slice(&unix_time_secs()?.to_be_bytes());
    out.extend_from_slice(request_salt);
    out.extend_from_slice(&len.to_be_bytes());
    Ok(out)
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
        let subkey = if method.is_aead_2022() {
            let mut key_material = Vec::with_capacity(master_key.len() + salt.len());
            key_material.extend_from_slice(master_key);
            key_material.extend_from_slice(salt);
            let derived = blake3::derive_key(AEAD_2022_INFO, &key_material);
            derived[..method.key_len()].to_vec()
        } else {
            let mut subkey = vec![0u8; method.key_len()];
            Hkdf::<Sha1>::new(Some(salt), master_key)
                .expand(INFO, &mut subkey)
                .map_err(|_| ShadowsocksError::KeyDerivation)?;
            subkey
        };

        let cipher = match method {
            Method::Aes128Gcm | Method::Aead2022Blake3Aes128Gcm => {
                Cipher::Aes128(Box::new(Aes128Gcm::new_from_slice(&subkey).unwrap()))
            }
            Method::Aes256Gcm | Method::Aead2022Blake3Aes256Gcm => {
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
    #[error("unsupported shadowsocks UDP method: {0}")]
    UnsupportedUdpMethod(String),
    #[error("invalid Shadowsocks key")]
    InvalidKey,
    #[error("invalid Shadowsocks key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("invalid salt length: expected {expected}, got {actual}")]
    InvalidSaltLength { expected: usize, actual: usize },
    #[error("invalid salt prefix length: max {max}, got {actual}")]
    InvalidSaltPrefixLength { max: usize, actual: usize },
    #[error("salt prefixes are not supported for shadowsocks method: {0}")]
    SaltPrefixUnsupportedForMethod(String),
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
    #[error("invalid Shadowsocks 2022 header")]
    InvalidHeader,
    #[error("invalid Shadowsocks 2022 timestamp")]
    InvalidTimestamp,
    #[error("replayed Shadowsocks 2022 salt")]
    ReplayDetected,
    #[error("Shadowsocks 2022 replay cache is poisoned")]
    ReplayCachePoisoned,
    #[error("missing Shadowsocks 2022 request salt")]
    MissingRequestSalt,
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
        ServerConfig::new(method.name(), "correct horse battery staple").unwrap()
    }

    fn config_2022(method: Method) -> ServerConfig {
        let key = vec![0x42; method.key_len()];
        let password = base64::engine::general_purpose::STANDARD.encode(key);
        ServerConfig::new(method.name(), password).unwrap()
    }

    #[test]
    fn parses_supported_methods() {
        assert_eq!(Method::parse("aes-128-gcm").unwrap(), Method::Aes128Gcm);
        assert_eq!(Method::parse("aes-256-gcm").unwrap(), Method::Aes256Gcm);
        assert_eq!(
            Method::parse("chacha20-ietf-poly1305").unwrap(),
            Method::ChaCha20IetfPoly1305
        );
        assert_eq!(
            Method::parse("2022-blake3-aes-128-gcm").unwrap(),
            Method::Aead2022Blake3Aes128Gcm
        );
        assert_eq!(
            Method::parse("2022-blake3-aes-256-gcm").unwrap(),
            Method::Aead2022Blake3Aes256Gcm
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
    fn aead_2022_tcp_request_roundtrip_for_required_methods() {
        for method in [
            Method::Aead2022Blake3Aes128Gcm,
            Method::Aead2022Blake3Aes256Gcm,
        ] {
            let config = config_2022(method);
            let salt = vec![0x5a; method.salt_len()];
            let mut wire = Vec::new();
            {
                let (mut writer, request_salt) = ShadowsocksWriter::new_request_with_salt(
                    &mut wire,
                    &config,
                    &Address::Domain("example.com".into()),
                    Port(443),
                    b"initial",
                    &salt,
                )
                .unwrap();
                assert_eq!(request_salt, salt);
                writer.write_chunk(b"second").unwrap();
            }

            let mut reader = ShadowsocksReader::new(Cursor::new(wire), &config).unwrap();
            assert_eq!(reader.request_salt(), Some(salt.as_slice()));
            let first = reader.read_chunk().unwrap();
            let (address, port, consumed) = parse_request_header(&first).unwrap();
            assert_eq!(address, Address::Domain("example.com".into()));
            assert_eq!(port, Port(443));
            assert_eq!(&first[consumed..], b"initial");
            assert_eq!(reader.read_chunk().unwrap(), b"second");
        }
    }

    #[test]
    fn aead_2022_tcp_response_roundtrip_for_required_methods() {
        for method in [
            Method::Aead2022Blake3Aes128Gcm,
            Method::Aead2022Blake3Aes256Gcm,
        ] {
            let config = config_2022(method);
            let request_salt = vec![0x11; method.salt_len()];
            let response_salt = vec![0x22; method.salt_len()];
            let mut wire = Vec::new();
            {
                let mut writer = ShadowsocksWriter::new_response_with_salt(
                    &mut wire,
                    &config,
                    Some(&request_salt),
                    &response_salt,
                )
                .unwrap();
                writer.write_chunk(b"first response").unwrap();
                writer.write_chunk(b"second response").unwrap();
            }

            let mut reader =
                ShadowsocksReader::new_response(Cursor::new(wire), &config, Some(&request_salt))
                    .unwrap();
            assert_eq!(reader.read_chunk().unwrap(), b"first response");
            assert_eq!(reader.read_chunk().unwrap(), b"second response");
        }
    }

    #[test]
    fn aead_2022_rejects_replayed_request_salt() {
        let config = config_2022(Method::Aead2022Blake3Aes128Gcm);
        let salt = vec![0x44; config.method.salt_len()];

        for attempt in 0..2 {
            let mut wire = Vec::new();
            ShadowsocksWriter::new_request_with_salt(
                &mut wire,
                &config,
                &Address::IPv4([127, 0, 0, 1]),
                Port(80),
                b"payload",
                &salt,
            )
            .unwrap();
            let result = ShadowsocksReader::new(Cursor::new(wire), &config);
            if attempt == 0 {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(ShadowsocksError::ReplayDetected)));
            }
        }
    }

    #[test]
    fn aead_2022_requires_fixed_length_base64_psk() {
        assert!(matches!(
            ServerConfig::new("2022-blake3-aes-128-gcm", "not-base64"),
            Err(ShadowsocksError::InvalidKey)
        ));
        let wrong_len = base64::engine::general_purpose::STANDARD.encode([0u8; 15]);
        assert!(matches!(
            ServerConfig::new("2022-blake3-aes-128-gcm", wrong_len),
            Err(ShadowsocksError::InvalidKeyLength { .. })
        ));
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

    #[test]
    fn generated_tcp_and_udp_salts_use_configured_prefixes() {
        let config = ServerConfig::new_with_prefixes(
            "chacha20-ietf-poly1305",
            "password",
            b"HTTP/1.1 ".to_vec(),
            b"\x6b\x7b\x01\x20".to_vec(),
        )
        .unwrap();

        let mut wire = Vec::new();
        {
            let mut writer = ShadowsocksWriter::new(&mut wire, &config).unwrap();
            writer.write_chunk(b"payload").unwrap();
        }
        assert!(wire.starts_with(b"HTTP/1.1 "));

        let packet = encrypt_udp_packet(b"payload", &config).unwrap();
        assert!(packet.starts_with(b"\x6b\x7b\x01\x20"));
    }

    #[test]
    fn salt_prefixes_are_limited_to_16_bytes() {
        assert!(matches!(
            ServerConfig::new_with_prefixes(
                "chacha20-ietf-poly1305",
                "password",
                vec![0u8; 17],
                Vec::new()
            ),
            Err(ShadowsocksError::InvalidSaltPrefixLength { .. })
        ));
    }
}
