//! mKCP (VLESS + KCP) carrier.
//!
//! Implements xray's mKCP transport on the server side:
//!   - FNV1a-based authenticator (2-byte auth + 1-byte cmd prefix)
//!   - mKCP segment wrapper (DataSegment, AckSegment, CmdOnlySegment)
//!   - KCP reliable transport sessions multiplexed over a single UDP socket
//!   - VLESS decode, response, and relay over KCP byte streams

mod xray_session;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use sha2::Digest;
use tokio::sync::mpsc as tokio_mpsc;
use tracing::{debug, error, info, trace, warn};
use wrongsv_protocol::RequestCommand;

use crate::config::KcpServerConfig;

use super::*;
use xray_session::{
    SessionConfig as XraySessionConfig, SessionState as XraySessionState, XrayKcpSession, peek_conv,
};

// ── mKCP constants ─────────────────────────────────────────────────────

const MKCP_ORIGINAL_OVERHEAD: usize = 6;

// ── Config ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct KcpConfig {
    pub mtu: usize,
    pub tti: u32, // transmission interval in ms
    pub uplink_capacity: usize,
    pub downlink_capacity: usize,
    pub _read_buffer_size: usize,
    pub write_buffer_size: usize,
    packet_mask: KcpPacketMask,
}

pub(crate) fn parse_kcp_config(kc: &KcpServerConfig) -> Result<KcpConfig, String> {
    let mtu = kc.mtu.unwrap_or(1350);
    if !(576..=1460).contains(&mtu) {
        return Err(format!("kcp mtu must be in 576..=1460, got {mtu}"));
    }
    let tti = kc.tti.unwrap_or(50);
    if !(10..=100).contains(&tti) {
        return Err(format!("kcp tti must be in 10..=100, got {tti}"));
    }
    let packet_mask = match kc.seed.as_deref() {
        Some(seed) if !seed.is_empty() => {
            let digest = sha2::Sha256::digest(seed.as_bytes());
            let mut key = [0u8; 16];
            key.copy_from_slice(&digest[..16]);
            KcpPacketMask::Aes128Gcm { key }
        }
        _ => KcpPacketMask::Original,
    };
    Ok(KcpConfig {
        mtu,
        tti,
        uplink_capacity: kc.uplink_capacity.unwrap_or(5),
        downlink_capacity: kc.downlink_capacity.unwrap_or(20),
        _read_buffer_size: kc.read_buffer_size.unwrap_or(2 * 1024 * 1024),
        write_buffer_size: kc.write_buffer_size.unwrap_or(2 * 1024 * 1024),
        packet_mask,
    })
}

// ── mKCP packet mask ───────────────────────────────────────────────────

/// 32-bit FNV1a hash of a buffer.
fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn xorfwd(data: &mut [u8]) {
    for i in 4..data.len() {
        data[i] ^= data[i - 4];
    }
}

fn xorbkd(data: &mut [u8]) {
    for i in (4..data.len()).rev() {
        data[i] ^= data[i - 4];
    }
}

#[derive(Clone)]
enum KcpPacketMask {
    Original,
    Aes128Gcm { key: [u8; 16] },
}

impl KcpPacketMask {
    fn overhead(&self) -> usize {
        match self {
            Self::Original => MKCP_ORIGINAL_OVERHEAD,
            Self::Aes128Gcm { .. } => 16,
        }
    }

    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, io::Error> {
        match self {
            Self::Original => {
                let mut packet =
                    Vec::with_capacity(MKCP_ORIGINAL_OVERHEAD + plaintext.len() + 3);
                packet.extend_from_slice(&[0u8; MKCP_ORIGINAL_OVERHEAD]);
                packet[4..6].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
                packet.extend_from_slice(plaintext);
                let auth = fnv1a_32(&packet[4..]);
                packet[..4].copy_from_slice(&auth.to_be_bytes());
                let padded_len = if packet.len() % 4 == 0 {
                    packet.len()
                } else {
                    packet.len() + (4 - packet.len() % 4)
                };
                packet.resize(padded_len, 0);
                xorfwd(&mut packet);
                packet.truncate(MKCP_ORIGINAL_OVERHEAD + plaintext.len());
                Ok(packet)
            }
            Self::Aes128Gcm { key } => {
                use rand::RngCore;

                let cipher =
                    aes_gcm::Aes128Gcm::new_from_slice(key).expect("AES-GCM key length");
                let mut packet = vec![0u8; 12];
                rand::rngs::OsRng.fill_bytes(&mut packet);
                let nonce = aes_gcm::Nonce::from_slice(&packet[..12]);
                let mut ciphertext = plaintext.to_vec();
                let tag = cipher
                    .encrypt_in_place_detached(nonce, b"", &mut ciphertext)
                    .map_err(|e| io::Error::other(format!("mkcp wrap: {e}")))?;
                packet.extend_from_slice(&ciphertext);
                packet.extend_from_slice(tag.as_slice());
                Ok(packet)
            }
        }
    }

    fn unwrap(&self, packet: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::Original => {
                if packet.len() < MKCP_ORIGINAL_OVERHEAD {
                    return None;
                }
                let mut data = packet.to_vec();
                let padded_len = if data.len() % 4 == 0 {
                    data.len()
                } else {
                    data.len() + (4 - data.len() % 4)
                };
                data.resize(padded_len, 0);
                xorbkd(&mut data);
                let auth = u32::from_be_bytes(data[..4].try_into().ok()?);
                if fnv1a_32(&data[4..packet.len()]) != auth {
                    return None;
                }
                let length = u16::from_be_bytes(data[4..6].try_into().ok()?) as usize;
                if packet.len().checked_sub(MKCP_ORIGINAL_OVERHEAD)? != length {
                    return None;
                }
                Some(data[6..6 + length].to_vec())
            }
            Self::Aes128Gcm { key } => {
                if packet.len() < 12 + 16 {
                    return None;
                }
                let cipher =
                    aes_gcm::Aes128Gcm::new_from_slice(key).expect("AES-GCM key length");
                let nonce = aes_gcm::Nonce::from_slice(&packet[..12]);
                let split = packet.len() - 16;
                let mut plaintext = packet[12..split].to_vec();
                cipher
                    .decrypt_in_place_detached(
                        nonce,
                        b"",
                        &mut plaintext,
                        aes_gcm::Tag::from_slice(&packet[split..]),
                    )
                    .ok()?;
                Some(plaintext)
            }
        }
    }
}

// ── KCP session ────────────────────────────────────────────────────────

struct KcpSession {
    engine: XrayKcpSession,
    incoming_tx: mpsc::Sender<Vec<u8>>,
    /// Pending VLESS output — fed to kcp.send() in the update loop.
    vless_outgoing_rx: mpsc::Receiver<Vec<u8>>,
    udp_tx: tokio_mpsc::UnboundedSender<Vec<u8>>,
    started_at: Instant,
    last_update: Instant,
}

impl KcpSession {
    fn new(
        conv: u16,
        config: &KcpConfig,
        incoming_tx: mpsc::Sender<Vec<u8>>,
        vless_outgoing_rx: mpsc::Receiver<Vec<u8>>,
        udp_tx: tokio_mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        let engine = XrayKcpSession::new(XraySessionConfig {
            conv,
            mtu: config.mtu,
            tti: config.tti,
            uplink_capacity: config.uplink_capacity,
            downlink_capacity: config.downlink_capacity,
            write_buffer_size: config.write_buffer_size,
            packet_overhead: config.packet_mask.overhead(),
        });
        KcpSession {
            engine,
            incoming_tx,
            vless_outgoing_rx,
            udp_tx,
            started_at: Instant::now(),
            last_update: Instant::now(),
        }
    }

    fn current_ms(&self) -> u32 {
        self.started_at.elapsed().as_millis() as u32
    }
}

// ── Shared KCP state ───────────────────────────────────────────────────

struct KcpShared {
    sessions: HashMap<(SocketAddr, u16), Arc<Mutex<KcpSession>>>,
    config: KcpConfig,
    packet_mask: KcpPacketMask,
    socket: UdpSocket,
}

// ── Stream bridge (sync Read + Write over KCP) ────────────────────────

pub(crate) struct KcpRelayStream {
    incoming_rx: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    /// Send VLESS output through KCP (channel is read in update loop).
    vless_tx: mpsc::SyncSender<Vec<u8>>,
    eof: bool,
}

impl KcpRelayStream {
    fn new(incoming_rx: mpsc::Receiver<Vec<u8>>, vless_tx: mpsc::SyncSender<Vec<u8>>) -> Self {
        KcpRelayStream {
            incoming_rx,
            pending: Vec::new(),
            vless_tx,
            eof: false,
        }
    }

    /// Split into reader and writer for concurrent bidirectional relay.
    fn split(self) -> (KcpRelayReader, KcpRelayWriter) {
        (
            KcpRelayReader {
                incoming_rx: self.incoming_rx,
                pending: self.pending,
                eof: self.eof,
            },
            KcpRelayWriter {
                vless_tx: self.vless_tx,
            },
        )
    }
}

/// Read half of KcpRelayStream: KCP → target.
pub(crate) struct KcpRelayReader {
    incoming_rx: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    eof: bool,
}

impl Read for KcpRelayReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }
        if self.eof {
            return Ok(0);
        }
        match self.incoming_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(data) => {
                if data.len() <= buf.len() {
                    let n = data.len();
                    buf[..n].copy_from_slice(&data);
                    Ok(n)
                } else {
                    let n = buf.len();
                    buf[..n].copy_from_slice(&data[..n]);
                    self.pending.extend_from_slice(&data[n..]);
                    Ok(n)
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no KCP data"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.eof = true;
                Ok(0)
            }
        }
    }
}

/// Write half of KcpRelayStream: target → KCP.
pub(crate) struct KcpRelayWriter {
    vless_tx: mpsc::SyncSender<Vec<u8>>,
}

impl Write for KcpRelayWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.vless_tx.try_send(buf.to_vec()) {
            Ok(()) => Ok(buf.len()),
            Err(mpsc::TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "KCP send buffer full",
            )),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "KCP stream closed",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for KcpRelayStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }
        if self.eof {
            return Ok(0);
        }
        // Use recv_timeout to avoid blocking forever:
        // when download writes get WouldBlock and upload has no data yet,
        // a short timeout lets the loop retry the download direction.
        match self.incoming_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(data) => {
                if data.len() <= buf.len() {
                    let n = data.len();
                    buf[..n].copy_from_slice(&data);
                    Ok(n)
                } else {
                    let n = buf.len();
                    buf[..n].copy_from_slice(&data[..n]);
                    self.pending.extend_from_slice(&data[n..]);
                    Ok(n)
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no data from KCP",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.eof = true;
                Ok(0)
            }
        }
    }
}

impl Write for KcpRelayStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.eof {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "KCP stream closed",
            ));
        }
        // Use try_send for backpressure: returns WouldBlock when channel is full,
        // allowing the relay loop to service the upload direction.
        match self.vless_tx.try_send(buf.to_vec()) {
            Ok(()) => Ok(buf.len()),
            Err(mpsc::TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "KCP send buffer full",
            )),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "KCP stream closed",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ── Endpoint runner ────────────────────────────────────────────────────

pub(crate) async fn run_kcp_endpoint(
    listen: &str,
    config: KcpConfig,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    shutdown: super::ShutdownSignal,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = listen.parse()?;
    let socket = UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    info!("KCP endpoint listening on {addr}");

    let shared = Arc::new(Mutex::new(KcpShared {
        sessions: HashMap::new(),
        config: config.clone(),
        packet_mask: config.packet_mask.clone(),
        socket: socket.try_clone()?,
    }));

    // KCP update + VLESS consume task
    let update_shared = Arc::clone(&shared);
    let update_v = Arc::clone(&validator);
    let update_ks = kyber_sk;
    let update_tti = config.tti as u64;
    let update_shutdown = shutdown.clone();
    let update_handle = tokio::spawn(async move {
        run_kcp_update_loop(
            update_shared,
            update_v,
            update_ks,
            update_tti,
            update_shutdown,
        )
        .await;
    });

    // UDP recv loop
    let mut buf = [0u8; 2048];
    loop {
        if shutdown.is_shutdown_requested() {
            info!("KCP server stopped");
            break;
        }
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                let mut sh = shared.lock().unwrap();
                if let Some(data) = sh.packet_mask.unwrap(&buf[..n])
                    && let Some(kcp_conv) = peek_conv(&data)
                {
                    let key = (src, kcp_conv);
                    if let Some(session) = sh.sessions.get(&key) {
                        let mut s = session.lock().unwrap();
                        s.last_update = Instant::now();
                        let current = s.current_ms();
                        s.engine.input(&data, current);
                        while let Some(frame) = s.engine.take_received() {
                            let _ = s.incoming_tx.send(frame);
                        }
                    } else {
                        let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>();
                        let (vless_tx, vless_rx) = mpsc::sync_channel::<Vec<u8>>(8);
                        let (udp_tx, mut udp_rx) = tokio_mpsc::unbounded_channel::<Vec<u8>>();

                        let session = Arc::new(Mutex::new(KcpSession::new(
                            kcp_conv,
                            &sh.config,
                            incoming_tx,
                            vless_rx,
                            udp_tx,
                        )));
                        {
                            let mut guard = session.lock().unwrap();
                            let current = guard.current_ms();
                            guard.engine.input(&data, current);
                            while let Some(frame) = guard.engine.take_received() {
                                let _ = guard.incoming_tx.send(frame);
                            }
                        }

                        sh.sessions.insert(key, Arc::clone(&session));

                        let v = Arc::clone(&validator);
                        let ks = kyber_sk;
                        std::thread::spawn(move || {
                            let stream = KcpRelayStream::new(incoming_rx, vless_tx);
                            if let Err(e) = handle_vless_over_kcp(stream, v, ks, src) {
                                warn!("{src} KCP stream error: {e}");
                            }
                        });

                        let sock = sh.socket.try_clone().unwrap();
                        let packet_mask = sh.packet_mask.clone();
                        tokio::spawn(async move {
                            while let Some(raw_kcp_data) = udp_rx.recv().await {
                                let Ok(packet) = packet_mask.wrap(&raw_kcp_data) else {
                                    break;
                                };
                                loop {
                                    match sock.send_to(&packet, src) {
                                        Ok(_) => break,
                                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                            tokio::time::sleep(Duration::from_millis(1)).await;
                                        }
                                        Err(_) => break,
                                    }
                                }
                            }
                        });
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
            Err(e) => {
                error!("KCP recv error: {e}");
                break;
            }
        }
    }

    update_handle.abort();
    Ok(())
}

async fn run_kcp_update_loop(
    shared: Arc<Mutex<KcpShared>>,
    _validator: Arc<MemoryValidator>,
    _kyber_sk: Option<[u8; 64]>,
    tti_ms: u64,
    shutdown: super::ShutdownSignal,
) {
    let interval = Duration::from_millis(tti_ms);
    loop {
        if shutdown.is_shutdown_requested() {
            break;
        }
        tokio::time::sleep(interval).await;

        let mut sh = shared.lock().unwrap();
        let mut to_remove: Vec<(SocketAddr, u16)> = Vec::new();

        for (&key, session) in &sh.sessions {
            let mut s = session.lock().unwrap();
            let current = s.current_ms();

            // Drain app output into the session's chunk queue. The relay writer
            // side is already backpressured by the sync_channel, so this bounded
            // in-memory queue is enough to bridge larger writes into mKCP MSS chunks.
            loop {
                match s.vless_outgoing_rx.try_recv() {
                    Ok(data) => s.engine.enqueue_application_data(&data),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        s.engine.mark_application_write_closed(current);
                        break;
                    }
                }
            }

            let output_packets = s.engine.flush(current);
            for packet in output_packets {
                let _ = s.udp_tx.send(packet);
            }
            while let Some(frame) = s.engine.take_received() {
                let _ = s.incoming_tx.send(frame);
            }
            s.last_update = Instant::now();

            if matches!(s.engine.state(), XraySessionState::Terminated)
                || s.last_update.elapsed() > Duration::from_secs(30)
            {
                to_remove.push(key);
            }
        }

        for key in to_remove {
            sh.sessions.remove(&key);
        }
    }
}

// ── VLESS over KCP ─────────────────────────────────────────────────────

fn handle_vless_over_kcp(
    mut stream: KcpRelayStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    peer: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut first = vec![0u8; 8192];
    // Retry on WouldBlock — KCP data may not be available immediately
    let n = loop {
        match stream.read(&mut first) {
            Ok(0) => return Err("KCP closed before VLESS header".into()),
            Ok(n) => break n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e.into()),
        }
    };
    first.truncate(n);
    trace!("{peer} KCP read {} bytes VLESS header", first.len());

    let VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    } = decode_vless_request(first, &validator, peer)?;

    let request = &decoded.header;
    let account = &request.user.account;

    log_vless_request(peer, request);
    trace!(
        "{peer} KCP flow={} use_vision={use_vision}",
        decoded.addons.flow
    );
    handle_kyber_addons(peer, &decoded, kyber_sk);
    validate_vless_command(request, use_vision)?;

    let resp_buf = response_header_buf(request)?;
    // Retry loop: with try_send, write() may return WouldBlock if channel is backed up
    loop {
        match stream.write_all(&resp_buf) {
            Ok(()) => break,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e.into()),
        }
    }
    stream.flush()?;

    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_kcp_udp(&mut stream, request, remaining_body)?;
        debug!("{peer} KCP UDP relay finished");
        return Ok(());
    }

    let target = connect_tcp_target(&request.address, request.port)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;

    let (reader, writer) = stream.split();

    if use_vision {
        relay_kcp_vision(
            reader,
            writer,
            target,
            &decoded.user_sent_id,
            &account.testseed,
            remaining_body,
        )?;
    } else {
        relay_kcp_raw(reader, writer, target, remaining_body)?;
    }
    debug!("{peer} KCP relay finished");
    Ok(())
}

// ── KCP relay functions ─────────────────────────────────────────────────

fn relay_kcp_raw(
    mut reader: KcpRelayReader,
    mut writer: KcpRelayWriter,
    mut target: TcpStream,
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    target.set_nodelay(true)?;

    if !initial_data.is_empty() {
        target.write_all(&initial_data)?;
    }

    let mut t_read = target.try_clone()?;
    let mut t_write = target;

    // Upload: KCP reader → target
    let up = std::thread::spawn(move || {
        let mut buf = [0u8; 32768];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = t_write.write_all(&buf[..n]) {
                        debug!("KCP upload write error: {e}");
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    debug!("KCP upload read error: {e}");
                    break;
                }
            }
        }
        let _ = t_write.shutdown(std::net::Shutdown::Write);
    });

    // Download: target → KCP writer
    loop {
        let mut buf = [0u8; 32768];
        match t_read.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                // Retry on WouldBlock — write_all would drop data since
                // the underlying try_send doesn't buffer unsent bytes.
                let mut written = 0;
                while written < n {
                    match writer.write(&buf[written..n]) {
                        Ok(w) => written += w,
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => {
                            debug!("KCP download write error: {e}");
                            break;
                        }
                    }
                }
                if written < n {
                    break; // write error, exit
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                debug!("KCP download read error: {e}");
                break;
            }
        }
    }

    up.join().ok();
    Ok(())
}

fn relay_kcp_vision(
    reader: KcpRelayReader,
    writer: KcpRelayWriter,
    mut target: TcpStream,
    user_sent_id: &[u8],
    testseed: &[u32],
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Re-bundle reader and writer for the sequential vision relay
    // (vision has shared state, so concurrent threads are harder)
    let mut client = KcpRelayStream {
        incoming_rx: reader.incoming_rx,
        pending: reader.pending,
        vless_tx: writer.vless_tx,
        eof: reader.eof,
    };
    let up_seed = if testseed.len() >= 4 {
        testseed.to_vec()
    } else {
        vec![900, 500, 900, 256]
    };
    let mut up_state = wrongsv_vless::vision::TrafficState::new(user_sent_id);
    let mut down_state = wrongsv_vless::vision::TrafficState::new(user_sent_id);
    let mut down_user_uuid: Option<[u8; 16]> = Some(down_state.user_uuid);

    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_millis(50)))?;
    let mut buf = [0u8; 32768];

    if !initial_data.is_empty() {
        let unpadded = wrongsv_vless::vision::xtls_unpadding(&initial_data, &mut up_state, true);
        if !unpadded.is_empty() {
            target.write_all(&unpadded)?;
            target.set_read_timeout(Some(Duration::from_millis(10)))?;
        }
    }

    loop {
        let down_done = loop {
            match target.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => {
                    let mut encoded = Vec::with_capacity(n + 256);
                    {
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
                        let mut w = wrongsv_vless::vision::VisionWriter::new(
                            BufWriter(&mut encoded),
                            down_state.clone(),
                            false,
                            up_seed.clone(),
                        );
                        w.user_uuid = down_user_uuid.take();
                        w.write(&buf[..n])?;
                        w.flush()?;
                        down_state = w.state;
                        down_user_uuid = w.user_uuid;
                    }
                    if !encoded.is_empty() {
                        match client.write_all(&encoded) {
                            Ok(()) => {}
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                // KCP congested — break to try upload side
                                target.set_read_timeout(Some(Duration::from_millis(50)))?;
                                break false;
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                    target.set_read_timeout(Some(Duration::from_millis(10)))?;
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    target.set_read_timeout(Some(Duration::from_millis(50)))?;
                    break false;
                }
                Err(e) => return Err(e.into()),
            }
        };

        let up_done = loop {
            match client.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => {
                    let unpadded =
                        wrongsv_vless::vision::xtls_unpadding(&buf[..n], &mut up_state, true);
                    if !unpadded.is_empty() {
                        target.write_all(&unpadded)?;
                        target.set_read_timeout(Some(Duration::from_millis(10)))?;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break false,
                Err(e) => return Err(e.into()),
            }
        };

        if up_done {
            let _ = target.shutdown(std::net::Shutdown::Write);
        }
        if down_done {
            break;
        }
        if up_done && down_done {
            break;
        }
    }
    Ok(())
}

fn relay_kcp_udp(
    client: &mut KcpRelayStream,
    request: &wrongsv_protocol::RequestHeader,
    remaining: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Cursor, ErrorKind};
    use wrongsv_vless_encoding::{LengthPacketReader, LengthPacketWriter, PacketReadError};

    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("KCP UDP relay to {target_addr}");

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(&target_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut buf = [0u8; 65535];

    if !remaining.is_empty() {
        let mut reader = LengthPacketReader::new(Cursor::new(&remaining));
        while let Ok(pkt) = reader.read_packet() {
            socket.send(&pkt)?;
        }
    }

    loop {
        let kcp_data = {
            let mut tmp = [0u8; 65535];
            match client.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    let mut reader = LengthPacketReader::new(Cursor::new(&tmp[..n]));
                    let mut pkts = Vec::new();
                    loop {
                        match reader.read_packet() {
                            Ok(pkt) => pkts.push(pkt),
                            Err(PacketReadError::Io(ref e))
                                if e.kind() == ErrorKind::UnexpectedEof =>
                            {
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                    Some(pkts)
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => None,
                Err(e) => return Err(e.into()),
            }
        };

        if let Some(pkts) = kcp_data {
            for pkt in pkts {
                socket.send(&pkt)?;
            }
        }

        match socket.recv(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let mut packet = Vec::with_capacity(n + 2);
                LengthPacketWriter::new(&mut packet).write_packet(&buf[..n])?;
                client.write_all(&packet)?;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a_known_values() {
        // FNV1a-32 test vectors
        assert_eq!(fnv1a_32(b""), 0x811c9dc5);
        assert_eq!(fnv1a_32(b"a"), 0xe40c292c);
        assert_eq!(fnv1a_32(b"foobar"), 0xbf9cf968);
    }

    #[test]
    fn test_kcp_original_mask_roundtrip() {
        let mask = KcpPacketMask::Original;
        let data = b"hello kcp";
        let packet = mask.wrap(data).unwrap();
        assert_eq!(mask.unwrap(&packet).unwrap(), data);
    }

    #[test]
    fn test_kcp_aes128gcm_mask_roundtrip() {
        let digest = sha2::Sha256::digest(b"right-seed");
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest[..16]);
        let mask = KcpPacketMask::Aes128Gcm { key };
        let packet = mask.wrap(b"data").unwrap();
        assert_eq!(mask.unwrap(&packet).unwrap(), b"data");
    }

    #[test]
    fn test_kcp_aes128gcm_mask_rejects_wrong_key() {
        let digest1 = sha2::Sha256::digest(b"right-seed");
        let digest2 = sha2::Sha256::digest(b"wrong-seed");
        let mut key1 = [0u8; 16];
        let mut key2 = [0u8; 16];
        key1.copy_from_slice(&digest1[..16]);
        key2.copy_from_slice(&digest2[..16]);
        let packet = KcpPacketMask::Aes128Gcm { key: key1 }
            .wrap(b"data")
            .unwrap();
        assert!(KcpPacketMask::Aes128Gcm { key: key2 }
            .unwrap(&packet)
            .is_none());
    }

    #[test]
    fn parse_default_kcp_config() {
        let cfg = KcpServerConfig {
            seed: None,
            mtu: None,
            tti: None,
            header_size: None,
            uplink_capacity: None,
            downlink_capacity: None,
            read_buffer_size: None,
            write_buffer_size: None,
        };
        let kc = parse_kcp_config(&cfg).unwrap();
        assert_eq!(kc.mtu, 1350);
        assert_eq!(kc.tti, 50);
        assert!(matches!(kc.packet_mask, KcpPacketMask::Original));
    }

    #[test]
    fn parse_custom_kcp_config() {
        let cfg = KcpServerConfig {
            seed: Some("my-secret".into()),
            mtu: Some(1400),
            tti: Some(20),
            header_size: Some(25),
            uplink_capacity: None,
            downlink_capacity: None,
            read_buffer_size: None,
            write_buffer_size: None,
        };
        let kc = parse_kcp_config(&cfg).unwrap();
        assert_eq!(kc.mtu, 1400);
        assert_eq!(kc.tti, 20);
        assert!(matches!(kc.packet_mask, KcpPacketMask::Aes128Gcm { .. }));
    }
}
