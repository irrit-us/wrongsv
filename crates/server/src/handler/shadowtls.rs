//! ShadowTLS v3 carrier for VLESS.
//!
//! The protocol is not a local TLS terminator. Instead, it authenticates the
//! client through a ClientHello session-id HMAC, relays the upstream handshake,
//! and then switches to an authenticated record stream.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tracing::{debug, info, trace, warn};
use wrongsv_protocol::RequestCommand;
use wrongsv_vless::MemoryValidator;
use wrongsv_vless::vision::{TrafficState, VisionWriter};

use crate::config::ShadowTlsServerConfig;

use super::*;

type HmacSha1 = Hmac<Sha1>;

const TLS_RANDOM_SIZE: usize = 32;
const TLS_HEADER_SIZE: usize = 5;
const TLS_SESSION_ID_SIZE: usize = 32;
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;
const HMAC_SIZE: usize = 4;
const TLS_HMAC_HEADER_SIZE: usize = TLS_HEADER_SIZE + HMAC_SIZE;
const SERVER_RANDOM_INDEX: usize = TLS_HEADER_SIZE + 1 + 3 + 2;
const SESSION_ID_LENGTH_INDEX: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;
const SHADOWTLS_RECORD_CHUNK: usize = 16384;
const RELAY_BUF: usize = 32768;

#[derive(Clone)]
pub(crate) struct ShadowTlsConfig {
    pub password: String,
    pub tls_config: Arc<rustls::ServerConfig>,
    pub dest: Option<String>,
}

struct HandshakeBackend {
    stream: TcpStream,
    local_worker: Option<thread::JoinHandle<()>>,
}

impl HandshakeBackend {
    fn connect(config: &ShadowTlsConfig) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(dest) = &config.dest {
            let stream = TcpStream::connect(dest)?;
            stream.set_nodelay(true)?;
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            return Ok(Self {
                stream,
                local_worker: None,
            });
        }

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let tls_config = Arc::clone(&config.tls_config);
        let worker = thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let _ = sock.set_nodelay(true);
            let _ = sock.set_read_timeout(Some(Duration::from_secs(30)));
            let Ok(mut conn) = rustls::ServerConnection::new(tls_config) else {
                return;
            };

            loop {
                match conn.complete_io(&mut sock) {
                    Ok((0, 0)) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });

        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        Ok(Self {
            stream,
            local_worker: Some(worker),
        })
    }

    fn try_clone(&self) -> io::Result<TcpStream> {
        self.stream.try_clone()
    }

    fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    fn shutdown(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    fn join(&mut self) {
        if let Some(worker) = self.local_worker.take() {
            let _ = worker.join();
        }
    }
}

struct ShadowTlsReader {
    stream: TcpStream,
    verify_state: HmacSha1,
    pending: Vec<u8>,
    pending_offset: usize,
}

impl ShadowTlsReader {
    fn new(stream: TcpStream, pending: Vec<u8>, verify_state: HmacSha1) -> Self {
        Self {
            stream,
            verify_state,
            pending,
            pending_offset: 0,
        }
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    fn fill_pending(&mut self) -> io::Result<()> {
        loop {
            let frame = extract_tls_frame(&mut self.stream)?;
            if frame[0] == ALERT {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "shadowtls peer sent alert",
                ));
            }

            let payload = decode_shadowtls_application_data(&frame, &mut self.verify_state)?;
            if !payload.is_empty() {
                self.pending = payload;
                self.pending_offset = 0;
                return Ok(());
            }
        }
    }
}

impl Read for ShadowTlsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pending_offset >= self.pending.len() {
            self.pending.clear();
            self.pending_offset = 0;
            self.fill_pending()?;
        }

        let remaining = &self.pending[self.pending_offset..];
        let n = remaining.len().min(buf.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pending_offset += n;
        if self.pending_offset >= self.pending.len() {
            self.pending.clear();
            self.pending_offset = 0;
        }
        Ok(n)
    }
}

struct ShadowTlsWriter {
    stream: TcpStream,
    add_state: HmacSha1,
}

impl ShadowTlsWriter {
    fn new(stream: TcpStream, add_state: HmacSha1) -> Self {
        Self { stream, add_state }
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.stream.shutdown(Shutdown::Write)
    }
}

impl Write for ShadowTlsWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0usize;
        for chunk in buf.chunks(SHADOWTLS_RECORD_CHUNK) {
            let frame = encode_shadowtls_application_data(chunk, &mut self.add_state)?;
            self.stream.write_all(&frame)?;
            written += chunk.len();
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

pub(crate) struct ShadowTlsStream {
    reader: ShadowTlsReader,
    writer: ShadowTlsWriter,
}

impl ShadowTlsStream {
    fn new(
        stream: TcpStream,
        pending: Vec<u8>,
        verify_state: HmacSha1,
        add_state: HmacSha1,
    ) -> io::Result<Self> {
        let reader_stream = stream.try_clone()?;
        Ok(Self {
            reader: ShadowTlsReader::new(reader_stream, pending, verify_state),
            writer: ShadowTlsWriter::new(stream, add_state),
        })
    }

    fn into_parts(self) -> (ShadowTlsReader, ShadowTlsWriter) {
        (self.reader, self.writer)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.set_read_timeout(timeout)
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.writer.shutdown_write()
    }
}

impl Read for ShadowTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Write for ShadowTlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub(crate) fn parse_shadowtls_config(
    sc: &ShadowTlsServerConfig,
) -> Result<ShadowTlsConfig, String> {
    let (cert_pem, key_pem) = match (&sc.certificate, &sc.key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => {
            let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                .map_err(|e| format!("shadowtls cert: {e}"))?;
            (cert, key)
        }
    };

    let tls_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
        .map_err(|e| format!("shadowtls tls: {e}"))?;

    Ok(ShadowTlsConfig {
        password: sc.password.clone(),
        tls_config: Arc::new(tls_config),
        dest: sc.dest.clone(),
    })
}

fn new_shadowtls_hmac(password: &str) -> io::Result<HmacSha1> {
    HmacSha1::new_from_slice(password.as_bytes())
        .map_err(|e| io::Error::other(format!("shadowtls hmac init: {e}")))
}

fn seed_shadowtls_hmac(
    password: &str,
    server_random: &[u8; TLS_RANDOM_SIZE],
    suffix: &[u8],
) -> io::Result<HmacSha1> {
    let mut hmac = new_shadowtls_hmac(password)?;
    hmac.update(server_random);
    hmac.update(suffix);
    Ok(hmac)
}

fn extract_tls_frame<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0u8; TLS_HEADER_SIZE];
    reader.read_exact(&mut header)?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut frame = Vec::with_capacity(TLS_HEADER_SIZE + len);
    frame.extend_from_slice(&header);
    frame.resize(TLS_HEADER_SIZE + len, 0);
    reader.read_exact(&mut frame[TLS_HEADER_SIZE..])?;
    Ok(frame)
}

fn verify_client_hello(frame: &[u8], password: &str) -> io::Result<bool> {
    let min_len = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE + 1 + TLS_SESSION_ID_SIZE;
    let hmac_index = SESSION_ID_LENGTH_INDEX + 1 + TLS_SESSION_ID_SIZE - HMAC_SIZE;

    if frame.len() < min_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "shadowtls client hello too short",
        ));
    }
    if frame[0] != HANDSHAKE || frame[TLS_HEADER_SIZE] != CLIENT_HELLO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shadowtls expected TLS ClientHello",
        ));
    }
    if frame[SESSION_ID_LENGTH_INDEX] != TLS_SESSION_ID_SIZE as u8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shadowtls unexpected session id length",
        ));
    }

    let mut hmac = new_shadowtls_hmac(password)?;
    hmac.update(&frame[TLS_HEADER_SIZE..hmac_index]);
    hmac.update(&[0, 0, 0, 0]);
    hmac.update(&frame[hmac_index + HMAC_SIZE..]);
    let sum = hmac.finalize().into_bytes();
    Ok(frame[hmac_index..hmac_index + HMAC_SIZE] == sum[..HMAC_SIZE])
}

fn extract_server_random(frame: &[u8]) -> Option<[u8; TLS_RANDOM_SIZE]> {
    let min_len = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;
    if frame.len() < min_len || frame[0] != HANDSHAKE || frame[TLS_HEADER_SIZE] != SERVER_HELLO {
        return None;
    }

    let mut random = [0u8; TLS_RANDOM_SIZE];
    random.copy_from_slice(&frame[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + TLS_RANDOM_SIZE]);
    Some(random)
}

fn shadowtls_kdf(password: &str, server_random: &[u8; TLS_RANDOM_SIZE]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(server_random);
    hasher.finalize().into()
}

fn xor_slice(data: &mut [u8], key: &[u8]) {
    for (idx, byte) in data.iter_mut().enumerate() {
        *byte ^= key[idx % key.len()];
    }
}

fn encode_shadowtls_application_data(payload: &[u8], state: &mut HmacSha1) -> io::Result<Vec<u8>> {
    let record_len = HMAC_SIZE + payload.len();
    if record_len > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "shadowtls record too large",
        ));
    }

    state.update(payload);
    let hmac = state.clone().finalize().into_bytes();
    state.update(&hmac[..HMAC_SIZE]);

    let mut frame = Vec::with_capacity(TLS_HMAC_HEADER_SIZE + payload.len());
    frame.push(APPLICATION_DATA);
    frame.push(3);
    frame.push(3);
    frame.extend_from_slice(&(record_len as u16).to_be_bytes());
    frame.extend_from_slice(&hmac[..HMAC_SIZE]);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn decode_shadowtls_application_data(frame: &[u8], state: &mut HmacSha1) -> io::Result<Vec<u8>> {
    if frame.len() < TLS_HMAC_HEADER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shadowtls frame too short",
        ));
    }
    if frame[0] != APPLICATION_DATA || frame[1] != 3 || frame[2] != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected ShadowTLS record type {}", frame[0]),
        ));
    }

    let payload = &frame[TLS_HMAC_HEADER_SIZE..];
    state.update(payload);
    let expected = state.clone().finalize().into_bytes();
    if frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE] != expected[..HMAC_SIZE] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "shadowtls application data verification failed",
        ));
    }
    state.update(&frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]);
    Ok(payload.to_vec())
}

fn relay_client_shadowtls_handshake(
    client: &mut TcpStream,
    backend: &mut TcpStream,
    password: &str,
    server_random: &[u8; TLS_RANDOM_SIZE],
) -> io::Result<(Vec<u8>, HmacSha1)> {
    loop {
        let frame = extract_tls_frame(client)?;
        if frame.len() > TLS_HMAC_HEADER_SIZE && frame[0] == APPLICATION_DATA {
            let mut candidate = seed_shadowtls_hmac(password, server_random, b"C")?;
            let payload = &frame[TLS_HMAC_HEADER_SIZE..];
            candidate.update(payload);
            let expected = candidate.clone().finalize().into_bytes();
            if frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE] == expected[..HMAC_SIZE] {
                candidate.update(&frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]);
                return Ok((payload.to_vec(), candidate));
            }
        }
        backend.write_all(&frame)?;
    }
}

fn relay_server_shadowtls_handshake(
    backend: TcpStream,
    client: TcpStream,
    password: String,
    server_random: [u8; TLS_RANDOM_SIZE],
) -> io::Result<()> {
    let mut backend = backend;
    let mut client = client;
    let write_key = shadowtls_kdf(&password, &server_random);
    let mut hmac_write = seed_shadowtls_hmac(&password, &server_random, b"")?;

    loop {
        let mut frame = extract_tls_frame(&mut backend)?;
        if frame[0] == APPLICATION_DATA {
            let (header, payload) = frame.split_at_mut(TLS_HEADER_SIZE);
            xor_slice(payload, &write_key);
            hmac_write.update(payload);
            let hmac = hmac_write.clone().finalize().into_bytes();
            let next_len = payload.len() + HMAC_SIZE;
            if next_len > u16::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "shadowtls handshake record too large",
                ));
            }
            header[3..5].copy_from_slice(&(next_len as u16).to_be_bytes());
            client.write_all(header)?;
            client.write_all(&hmac[..HMAC_SIZE])?;
            client.write_all(payload)?;
        } else {
            client.write_all(&frame)?;
        }
    }
}

fn is_normal_shadowtls_close(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::TimedOut
    )
}

fn proxy_bidirectional(mut client_sock: TcpStream, mut server_sock: TcpStream) {
    let _ = server_sock.set_nodelay(true);
    let _ = server_sock.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client_sock.set_read_timeout(Some(Duration::from_secs(30)));

    let mut client_r = match client_sock.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut server_r = match server_sock.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };

    let t1 = thread::spawn(move || {
        let mut buf = [0u8; RELAY_BUF];
        loop {
            match client_r.read(&mut buf) {
                Ok(0) => {
                    let _ = server_sock.shutdown(Shutdown::Write);
                    break;
                }
                Ok(n) => {
                    if server_sock.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(ref e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let mut buf = [0u8; RELAY_BUF];
    loop {
        match server_r.read(&mut buf) {
            Ok(0) => {
                let _ = client_sock.shutdown(Shutdown::Write);
                break;
            }
            Ok(n) => {
                if client_sock.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(ref e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }

    let _ = t1.join();
}

fn accept_shadowtls_stream(
    stream: TcpStream,
    config: &ShadowTlsConfig,
) -> Result<ShadowTlsStream, Box<dyn std::error::Error>> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    let mut backend = HandshakeBackend::connect(config)?;
    let mut client_hello_reader = stream.try_clone()?;
    let client_hello = extract_tls_frame(&mut client_hello_reader)?;
    backend.stream_mut().write_all(&client_hello)?;

    match verify_client_hello(&client_hello, &config.password) {
        Ok(true) => {}
        Ok(false) => {
            info!("shadowtls client hello HMAC mismatch, falling back");
            let backend_stream = backend.try_clone()?;
            proxy_bidirectional(stream, backend_stream);
            backend.shutdown();
            backend.join();
            return Err("shadowtls unauthorized probe".into());
        }
        Err(err) => {
            warn!("shadowtls invalid client hello: {err}");
            let backend_stream = backend.try_clone()?;
            proxy_bidirectional(stream, backend_stream);
            backend.shutdown();
            backend.join();
            return Err(err.into());
        }
    }

    let server_hello = extract_tls_frame(backend.stream_mut())?;
    let Some(server_random) = extract_server_random(&server_hello) else {
        backend.shutdown();
        backend.join();
        return Err("shadowtls server random missing".into());
    };
    let mut client_writer = stream.try_clone()?;
    client_writer.write_all(&server_hello)?;

    let backend_reader = backend.try_clone()?;
    let client_writer_thread = stream.try_clone()?;
    let password = config.password.clone();
    let relay_thread = thread::spawn(move || {
        relay_server_shadowtls_handshake(
            backend_reader,
            client_writer_thread,
            password,
            server_random,
        )
    });

    let mut client_reader = stream.try_clone()?;
    let mut backend_writer = backend.try_clone()?;
    let (pending, verify_state) = relay_client_shadowtls_handshake(
        &mut client_reader,
        &mut backend_writer,
        &config.password,
        &server_random,
    )?;

    backend.shutdown();
    match relay_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) if is_normal_shadowtls_close(&err) => {}
        Ok(Err(err)) => {
            warn!("shadowtls handshake relay ended with error: {err}");
        }
        Err(_) => {
            warn!("shadowtls handshake relay panicked");
        }
    }
    backend.join();

    let add_state = seed_shadowtls_hmac(&config.password, &server_random, b"S")?;
    stream.set_read_timeout(None)?;
    ShadowTlsStream::new(stream, pending, verify_state, add_state).map_err(Into::into)
}

/// ShadowTLS connection handler.
pub(crate) fn handle_shadowtls_connection(
    stream: TcpStream,
    validator: Arc<MemoryValidator>,
    shadowtls_config: &ShadowTlsConfig,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} ShadowTLS connection");

    let mut shadowtls_stream = match accept_shadowtls_stream(stream, shadowtls_config) {
        Ok(stream) => stream,
        Err(err) => {
            debug!("{peer} ShadowTLS accept failed: {err}");
            return Err(err);
        }
    };
    info!("{peer} ShadowTLS auth OK");

    let mut first = vec![0u8; 8192];
    let n = loop {
        match shadowtls_stream.read(&mut first) {
            Ok(0) => return Err("connection closed before VLESS header".into()),
            Ok(n) => break n,
            Err(ref e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(e.into()),
        }
    };
    first.truncate(n);
    trace!("{peer} ShadowTLS read {n} bytes VLESS header");

    let VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    } = decode_vless_request(first, &validator, peer)?;
    let request = &decoded.header;
    let account = &request.user.account;
    let tap = wrongsv_metrics::MetricsTap::new(metrics, request.user.email.clone());
    let _conn_guard = tap.track_connection();

    log_vless_request(peer, request);
    validate_vless_command(request, use_vision)?;

    let resp_buf = response_header_buf(request)?;
    shadowtls_stream.write_all(&resp_buf)?;
    shadowtls_stream.flush()?;

    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_shadowtls_udp(shadowtls_stream, request, remaining_body, tap)?;
        debug!("{peer} ShadowTLS UDP relay finished");
        return Ok(());
    }

    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("{peer} connecting to target {target_addr}");
    let target = TcpStream::connect(&target_addr)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(60)))?;

    if use_vision {
        let user_sent_id = account.id.bytes();
        relay_shadowtls_vision(
            shadowtls_stream,
            target,
            user_sent_id,
            &account.testseed,
            remaining_body,
            tap,
        )?;
    } else {
        relay_shadowtls_raw(shadowtls_stream, target, remaining_body, tap)?;
    }
    debug!("{peer} ShadowTLS TCP relay finished");
    Ok(())
}

fn relay_shadowtls_raw(
    stream: ShadowTlsStream,
    mut target: TcpStream,
    initial_data: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    target.set_nodelay(true)?;

    if !initial_data.is_empty() {
        metrics.record_in(initial_data.len() as u64);
        target.write_all(&initial_data)?;
    }

    let (mut reader, mut writer) = stream.into_parts();
    let mut target_w = target.try_clone()?;
    let mut target_r = target;
    let metrics_up = metrics.clone();
    let metrics_down = metrics;

    let t1 = thread::spawn(move || {
        let mut buf = vec![0u8; RELAY_BUF];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    metrics_up.record_in(n as u64);
                    if target_w.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(ref e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(_) => break,
            }
        }
        let _ = target_w.shutdown(Shutdown::Write);
    });

    let t2 = thread::spawn(move || {
        let mut buf = vec![0u8; RELAY_BUF];
        loop {
            match target_r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    metrics_down.record_out(n as u64);
                    if writer.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(ref e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        let _ = writer.shutdown_write();
        let _ = target_r.shutdown(Shutdown::Write);
    });

    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

fn relay_shadowtls_vision(
    mut stream: ShadowTlsStream,
    mut target: TcpStream,
    user_sent_id: &[u8],
    testseed: &[u32],
    initial_data: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    let up_seed = if testseed.len() >= 4 {
        testseed.to_vec()
    } else {
        vec![900, 500, 900, 256]
    };
    let mut up_state = TrafficState::new(user_sent_id);
    let mut down_state = TrafficState::new(user_sent_id);
    let mut down_user_uuid: Option<[u8; 16]> = Some(down_state.user_uuid);

    if !initial_data.is_empty() {
        use wrongsv_vless::vision::xtls_unpadding;
        let unpadded = xtls_unpadding(&initial_data, &mut up_state, true);
        if !unpadded.is_empty() {
            metrics.record_in(unpadded.len() as u64);
            target.write_all(&unpadded)?;
        }
    }

    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut buf = [0u8; RELAY_BUF];
    loop {
        let downlink_done = loop {
            match target.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => {
                    metrics.record_out(n as u64);
                    let mut encoded = Vec::with_capacity(n + 256);
                    struct BufWriter<'a>(&'a mut Vec<u8>);
                    impl Write for BufWriter<'_> {
                        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                            self.0.extend_from_slice(data);
                            Ok(data.len())
                        }
                        fn flush(&mut self) -> io::Result<()> {
                            Ok(())
                        }
                    }

                    let mut writer = VisionWriter::new(
                        BufWriter(&mut encoded),
                        down_state.clone(),
                        false,
                        up_seed.clone(),
                    );
                    writer.user_uuid = down_user_uuid.take();
                    writer.write(&buf[..n])?;
                    writer.flush()?;
                    down_state = writer.state;
                    down_user_uuid = writer.user_uuid;

                    if !encoded.is_empty() {
                        stream.write_all(&encoded)?;
                    }
                    target.set_read_timeout(Some(Duration::from_millis(10)))?;
                }
                Err(ref e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    target.set_read_timeout(Some(Duration::from_secs(2)))?;
                    break false;
                }
                Err(e) => return Err(e.into()),
            }
        };

        let uplink_done = loop {
            match stream.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => {
                    let unpadded =
                        wrongsv_vless::vision::xtls_unpadding(&buf[..n], &mut up_state, true);
                    if !unpadded.is_empty() {
                        metrics.record_in(unpadded.len() as u64);
                        target.write_all(&unpadded)?;
                        target.set_read_timeout(Some(Duration::from_millis(10)))?;
                    }
                }
                Err(ref e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    break false;
                }
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break true,
                Err(e) => return Err(e.into()),
            }
        };

        if uplink_done {
            let _ = target.shutdown(Shutdown::Write);
        }
        if downlink_done {
            let _ = stream.shutdown_write();
            break;
        }
        if uplink_done && downlink_done {
            let _ = stream.shutdown_write();
            break;
        }
    }

    Ok(())
}

fn relay_shadowtls_udp(
    mut stream: ShadowTlsStream,
    request: &wrongsv_protocol::RequestHeader,
    remaining: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    if is_packetaddr_request(request) {
        debug!("ShadowTLS packetaddr UDP relay");
        stream.set_read_timeout(Some(Duration::from_millis(200)))?;
        return relay_packetaddr_udp_stream(&mut stream, remaining);
    }

    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("ShadowTLS UDP relay to {target_addr}");

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(&target_addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;

    let mut tls_buf = remaining;
    let mut udp_buf = [0u8; 65535];

    loop {
        let mut did_work = false;

        let mut tmp = [0u8; 8192];
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                tls_buf.extend_from_slice(&tmp[..n]);
                did_work = true;
            }
            Err(ref e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::UnexpectedEof
                ) => {}
            Err(_) => break,
        }

        while tls_buf.len() >= 2 {
            let len = u16::from_be_bytes([tls_buf[0], tls_buf[1]]) as usize;
            if tls_buf.len() < 2 + len {
                break;
            }
            let packet = tls_buf[2..2 + len].to_vec();
            tls_buf.drain(..2 + len);
            metrics.record_in(packet.len() as u64);
            socket.send(&packet)?;
            did_work = true;
        }

        match socket.recv(&mut udp_buf) {
            Ok(n) if n > 0 => {
                metrics.record_out(n as u64);
                stream.write_all(&(n as u16).to_be_bytes())?;
                stream.write_all(&udp_buf[..n])?;
                did_work = true;
            }
            Ok(_) => break,
            Err(ref e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }

        if !did_work {
            thread::sleep(Duration::from_millis(20));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client_hello(password: &str) -> Vec<u8> {
        let body_len = 2 + TLS_RANDOM_SIZE + 1 + TLS_SESSION_ID_SIZE;
        let mut frame = vec![0u8; TLS_HEADER_SIZE + 1 + 3 + body_len];
        frame[0] = HANDSHAKE;
        frame[1] = 3;
        frame[2] = 3;
        let record_len = frame.len() - TLS_HEADER_SIZE;
        frame[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
        frame[TLS_HEADER_SIZE] = CLIENT_HELLO;
        let handshake_len = body_len;
        frame[TLS_HEADER_SIZE + 1] = ((handshake_len >> 16) & 0xff) as u8;
        frame[TLS_HEADER_SIZE + 2] = ((handshake_len >> 8) & 0xff) as u8;
        frame[TLS_HEADER_SIZE + 3] = (handshake_len & 0xff) as u8;
        frame[TLS_HEADER_SIZE + 4] = 3;
        frame[TLS_HEADER_SIZE + 5] = 3;
        for (idx, byte) in frame[TLS_HEADER_SIZE + 6..TLS_HEADER_SIZE + 6 + TLS_RANDOM_SIZE]
            .iter_mut()
            .enumerate()
        {
            *byte = idx as u8;
        }
        frame[SESSION_ID_LENGTH_INDEX] = TLS_SESSION_ID_SIZE as u8;
        for (idx, byte) in frame[SESSION_ID_LENGTH_INDEX + 1..SESSION_ID_LENGTH_INDEX + 1 + 28]
            .iter_mut()
            .enumerate()
        {
            *byte = (idx as u8).wrapping_add(64);
        }

        let hmac_index = SESSION_ID_LENGTH_INDEX + 1 + TLS_SESSION_ID_SIZE - HMAC_SIZE;
        let mut hmac = new_shadowtls_hmac(password).unwrap();
        hmac.update(&frame[TLS_HEADER_SIZE..hmac_index]);
        hmac.update(&[0, 0, 0, 0]);
        hmac.update(&frame[hmac_index + HMAC_SIZE..]);
        let sum = hmac.finalize().into_bytes();
        frame[hmac_index..hmac_index + HMAC_SIZE].copy_from_slice(&sum[..HMAC_SIZE]);
        frame
    }

    #[test]
    fn test_parse_shadowtls_config_with_password() {
        let cfg = ShadowTlsServerConfig {
            password: "test-secret".into(),
            dest: Some("127.0.0.1:8080".into()),
            certificate: None,
            key: None,
        };
        let st = parse_shadowtls_config(&cfg).unwrap();
        assert_eq!(st.dest.as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(st.password, "test-secret");
    }

    #[test]
    fn test_parse_shadowtls_config_no_dest() {
        let cfg = ShadowTlsServerConfig {
            password: "test".into(),
            dest: None,
            certificate: None,
            key: None,
        };
        let st = parse_shadowtls_config(&cfg).unwrap();
        assert!(st.dest.is_none());
    }

    #[test]
    fn test_verify_client_hello_accepts_valid_hmac() {
        let frame = make_client_hello("shadow-pass");
        assert!(verify_client_hello(&frame, "shadow-pass").unwrap());
    }

    #[test]
    fn test_verify_client_hello_rejects_invalid_hmac() {
        let mut frame = make_client_hello("shadow-pass");
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        assert!(!verify_client_hello(&frame, "shadow-pass").unwrap());
    }

    #[test]
    fn test_shadowtls_application_data_roundtrip() {
        let server_random = [7u8; TLS_RANDOM_SIZE];
        let mut add_state = seed_shadowtls_hmac("secret", &server_random, b"S").unwrap();
        let mut verify_state = seed_shadowtls_hmac("secret", &server_random, b"S").unwrap();

        let frame = encode_shadowtls_application_data(b"hello-shadowtls", &mut add_state).unwrap();
        let payload = decode_shadowtls_application_data(&frame, &mut verify_state).unwrap();
        assert_eq!(payload, b"hello-shadowtls");
    }
}
