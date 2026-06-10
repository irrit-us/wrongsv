//! mKCP (VLESS + KCP) carrier.
//!
//! Implements xray's mKCP transport on the server side:
//!   - FNV1a-based authenticator (2-byte auth + 1-byte cmd prefix)
//!   - mKCP segment wrapper (DataSegment, AckSegment, CmdOnlySegment)
//!   - KCP reliable transport sessions multiplexed over a single UDP socket
//!   - VLESS decode, response, and relay over KCP byte streams

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ::kcp::Kcp;
use tokio::sync::mpsc as tokio_mpsc;
use tracing::{debug, error, info, trace, warn};
use wrongsv_protocol::RequestCommand;

use crate::config::KcpServerConfig;

use super::*;

// ── mKCP constants ─────────────────────────────────────────────────────

/// 2-byte auth + 1-byte command overhead per mKCP segment.
const MKCP_AUTH_OVERHEAD: usize = 3;

const CMD_DATA: u8 = 1;
#[allow(dead_code)]
const CMD_ACK: u8 = 0;
const CMD_TERMINATE: u8 = 2;
// const CMD_PING: u8 = 3;

// ── Config ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct KcpConfig {
    pub seed: String,
    pub mtu: usize,
    pub tti: u32, // transmission interval in ms
    #[allow(dead_code)]
    pub header_size: usize, // mKCP segment wrapper overhead
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
    let header_size = kc.header_size.unwrap_or(MKCP_AUTH_OVERHEAD + 16); // auth + DataSegment overhead
    Ok(KcpConfig {
        seed: kc.seed.clone().unwrap_or_default(),
        mtu,
        tti,
        header_size,
    })
}

// ── mKCP authenticator ─────────────────────────────────────────────────

/// 32-bit FNV1a hash of a buffer.
fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// mKCP seal: prepend 2-byte auth and 1-byte command.
fn mkcp_seal(seed: &str, cmd: u8, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(3 + data.len());
    // Compute auth = FNV1a(seed + cmd + data) truncated to 2 bytes
    let mut auth_input = Vec::with_capacity(seed.len() + 1 + data.len());
    auth_input.extend_from_slice(seed.as_bytes());
    auth_input.push(cmd);
    auth_input.extend_from_slice(data);
    let auth = fnv1a_32(&auth_input) as u16;
    packet.extend_from_slice(&auth.to_be_bytes());
    packet.push(cmd);
    packet.extend_from_slice(data);
    packet
}

/// mKCP open: verify 2-byte auth and extract data after command byte.
/// Returns `Some(data)` on success, `None` if auth check fails.
fn mkcp_open(seed: &str, packet: &[u8]) -> Option<(u8, Vec<u8>)> {
    if packet.len() < 3 {
        return None;
    }
    let auth = u16::from_be_bytes([packet[0], packet[1]]);
    let cmd = packet[2];
    let data = &packet[3..];

    let mut auth_input = Vec::with_capacity(seed.len() + 1 + data.len());
    auth_input.extend_from_slice(seed.as_bytes());
    auth_input.push(cmd);
    auth_input.extend_from_slice(data);
    let expected = fnv1a_32(&auth_input) as u16;
    if auth != expected {
        return None;
    }
    Some((cmd, data.to_vec()))
}

// ── KCP output channel ─────────────────────────────────────────────────

/// A `Write` impl that sends KCP output segments through a channel.
struct ChanWriter {
    tx: tokio_mpsc::UnboundedSender<Vec<u8>>,
}

impl Write for ChanWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ── KCP session ────────────────────────────────────────────────────────

struct KcpSession {
    kcp: Kcp<ChanWriter>,
    incoming_tx: mpsc::SyncSender<Vec<u8>>,
    /// Pending VLESS output — fed to kcp.send() in the update loop.
    vless_outgoing_rx: mpsc::Receiver<Vec<u8>>,
    last_update: Instant,
}

impl KcpSession {
    fn new(
        conv: u32,
        output: ChanWriter,
        incoming_tx: mpsc::SyncSender<Vec<u8>>,
        vless_outgoing_rx: mpsc::Receiver<Vec<u8>>,
        mtu: usize,
    ) -> Self {
        let mut kcp = Kcp::new(conv, output);
        let _ = kcp.set_mtu(mtu);
        // nodelay(nodelay, interval, resend, nc)
        kcp.set_nodelay(true, 10, 2, true);
        kcp.set_wndsize(128, 256);
        KcpSession {
            kcp,
            incoming_tx,
            vless_outgoing_rx,
            last_update: Instant::now(),
        }
    }
}

// ── Shared KCP state ───────────────────────────────────────────────────

struct KcpShared {
    sessions: HashMap<(SocketAddr, u32), Arc<Mutex<KcpSession>>>,
    seed: String,
    mtu: usize,
    socket: UdpSocket,
}

// ── Stream bridge (sync Read + Write over KCP) ────────────────────────

pub(crate) struct KcpRelayStream {
    incoming_rx: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    /// Send VLESS output through KCP (channel is read in update loop).
    vless_tx: mpsc::SyncSender<Vec<u8>>,
    eof: bool,
}

impl KcpRelayStream {
    fn new(incoming_rx: Receiver<Vec<u8>>, vless_tx: mpsc::SyncSender<Vec<u8>>) -> Self {
        KcpRelayStream {
            incoming_rx,
            pending: Vec::new(),
            vless_tx,
            eof: false,
        }
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
        match self.incoming_rx.recv() {
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
            Err(_) => {
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
        // Route VLESS output through KCP (kcp.send() called in update loop)
        self.vless_tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "KCP stream closed"))?;
        Ok(buf.len())
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
        seed: config.seed.clone(),
        mtu: config.mtu,
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
                if let Some((cmd, data)) = mkcp_open(&sh.seed, &buf[..n]) {
                    if cmd == CMD_DATA && data.len() >= 4 {
                        // Extract KCP conversation ID from the raw KCP header
                        // (first 4 bytes of KCP segment = conv, little-endian)
                        let kcp_conv = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                        let kcp_data = &data; // entire data is the KCP segment

                        let key = (src, kcp_conv);
                        if let Some(session) = sh.sessions.get(&key) {
                            let mut s = session.lock().unwrap();
                            s.last_update = Instant::now();
                            let _ = s.kcp.input(kcp_data);
                        } else {
                            // New KCP session — create one with VLESS relay
                            let session_mtu = sh.mtu;
                            let (incoming_tx, incoming_rx) = mpsc::sync_channel::<Vec<u8>>(64);
                            // Channel: VLESS handler → KCP send
                            let (vless_tx, vless_rx) = mpsc::sync_channel::<Vec<u8>>(64);
                            // Channel: KCP output → UDP sender
                            let (udp_tx, mut udp_rx) = tokio_mpsc::unbounded_channel::<Vec<u8>>();

                            let chan_writer = ChanWriter { tx: udp_tx };
                            let session = Arc::new(Mutex::new(KcpSession::new(
                                kcp_conv,
                                chan_writer,
                                incoming_tx,
                                vless_rx,
                                session_mtu,
                            )));
                            let _ = session.lock().unwrap().kcp.input(kcp_data);

                            sh.sessions.insert(key, Arc::clone(&session));

                            // Spawn VLESS handler thread
                            let v = Arc::clone(&validator);
                            let ks = kyber_sk;
                            std::thread::spawn(move || {
                                let mut stream = KcpRelayStream::new(incoming_rx, vless_tx);
                                if let Err(e) = handle_vless_over_kcp(&mut stream, v, ks, src) {
                                    warn!("{src} KCP stream error: {e}");
                                }
                                // Dropping stream drops vless_tx → signals update loop
                            });

                            // Spawn KCP output → UDP send task
                            let sock = sh.socket.try_clone().unwrap();
                            let send_seed = sh.seed.clone();
                            tokio::spawn(async move {
                                while let Some(raw_kcp_data) = udp_rx.recv().await {
                                    let packet = mkcp_seal(&send_seed, CMD_DATA, &raw_kcp_data);
                                    let _ = sock.send_to(&packet, src);
                                }
                                // KCP session removed
                            });
                        }
                    } else if cmd == CMD_TERMINATE {
                        // Remove session
                        if data.len() >= 4 {
                            let kcp_conv = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                            let key = (src, kcp_conv);
                            sh.sessions.remove(&key);
                        }
                    }
                    // ACK and PING are handled by the KCP layer internally
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
    let mut tick = 0u32;
    let interval = Duration::from_millis(tti_ms);
    loop {
        if shutdown.is_shutdown_requested() {
            break;
        }
        tokio::time::sleep(interval).await;
        tick += tti_ms as u32;

        let mut sh = shared.lock().unwrap();
        let mut to_remove: Vec<(SocketAddr, u32)> = Vec::new();

        for (&key, session) in &sh.sessions {
            let mut s = session.lock().unwrap();
            let _ = s.kcp.update(tick);
            // Check if KCP session is dead (no activity for 30 seconds)
            if s.last_update.elapsed() > Duration::from_secs(30) {
                to_remove.push(key);
            }
        }

        for key in to_remove {
            sh.sessions.remove(&key);
        }

        // Feed VLESS output through KCP.send() and deliver KCP.recv() data
        for (&_key, session) in &sh.sessions {
            let mut s = session.lock().unwrap();
            // Feed pending VLESS output into KCP
            let mut had_output = false;
            while let Ok(data) = s.vless_outgoing_rx.try_recv() {
                let _ = s.kcp.send(&data);
                had_output = true;
            }
            // Deliver received KCP data to VLESS handler
            let mut rbuf = [0u8; 65536];
            loop {
                match s.kcp.recv(&mut rbuf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let data = rbuf[..n].to_vec();
                        let _ = s.incoming_tx.send(data);
                        had_output = true;
                    }
                }
            }
            if had_output {
                s.last_update = Instant::now();
            }
        }
    }
}

// ── VLESS over KCP ─────────────────────────────────────────────────────

fn handle_vless_over_kcp(
    stream: &mut KcpRelayStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    peer: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut first = vec![0u8; 8192];
    let n = stream.read(&mut first)?;
    if n == 0 {
        return Err("KCP closed before VLESS header".into());
    }
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
    stream.write_all(&resp_buf)?;

    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_kcp_udp(stream, request, remaining_body)?;
        debug!("{peer} KCP UDP relay finished");
        return Ok(());
    }

    let target = connect_tcp_target(&request.address, request.port)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;

    if use_vision {
        relay_kcp_vision(
            stream,
            target,
            &decoded.user_sent_id,
            &account.testseed,
            remaining_body,
        )?;
    } else {
        relay_kcp_raw(stream, target, remaining_body)?;
    }
    debug!("{peer} KCP relay finished");
    Ok(())
}

// ── KCP relay functions ─────────────────────────────────────────────────

fn relay_kcp_raw(
    client: &mut KcpRelayStream,
    mut target: TcpStream,
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 32768];
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(2)))?;

    if !initial_data.is_empty() {
        target.write_all(&initial_data)?;
        target.set_read_timeout(Some(Duration::from_millis(10)))?;
    }

    loop {
        match target.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                client.write_all(&buf[..n])?;
                target.set_read_timeout(Some(Duration::from_millis(10)))?;
                continue;
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                target.set_read_timeout(Some(Duration::from_secs(2)))?;
            }
            Err(e) => return Err(e.into()),
        }

        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                target.write_all(&buf[..n])?;
                target.set_read_timeout(Some(Duration::from_millis(10)))?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
    }
    let _ = target.shutdown(std::net::Shutdown::Write);
    Ok(())
}

fn relay_kcp_vision(
    client: &mut KcpRelayStream,
    mut target: TcpStream,
    user_sent_id: &[u8],
    testseed: &[u32],
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let up_seed = if testseed.len() >= 4 {
        testseed.to_vec()
    } else {
        vec![900, 500, 900, 256]
    };
    let mut up_state = wrongsv_vless::vision::TrafficState::new(user_sent_id);
    let mut down_state = wrongsv_vless::vision::TrafficState::new(user_sent_id);
    let mut down_user_uuid: Option<[u8; 16]> = Some(down_state.user_uuid);

    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(2)))?;
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
                        client.write_all(&encoded)?;
                    }
                    target.set_read_timeout(Some(Duration::from_millis(10)))?;
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    target.set_read_timeout(Some(Duration::from_secs(2)))?;
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
    fn test_mkcp_seal_open_roundtrip() {
        let seed = "test-seed";
        let cmd = CMD_DATA;
        let data = b"hello kcp";

        let packet = mkcp_seal(seed, cmd, data);
        assert_eq!(packet.len(), 3 + data.len());
        assert_eq!(packet[2], cmd);

        let result = mkcp_open(seed, &packet);
        assert!(result.is_some());
        let (parsed_cmd, parsed_data) = result.unwrap();
        assert_eq!(parsed_cmd, cmd);
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn test_mkcp_auth_rejects_wrong_seed() {
        let packet = mkcp_seal("right-seed", CMD_DATA, b"data");
        assert!(mkcp_open("wrong-seed", &packet).is_none());
    }

    #[test]
    fn test_mkcp_auth_rejects_corrupted() {
        let mut packet = mkcp_seal("seed", CMD_DATA, b"data");
        packet[0] ^= 1; // flip one auth byte
        assert!(mkcp_open("seed", &packet).is_none());
    }

    #[test]
    fn test_mkcp_short_packet() {
        assert!(mkcp_open("seed", b"ab").is_none()); // too short
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
        assert_eq!(kc.seed, "");
        assert_eq!(kc.mtu, 1350);
        assert_eq!(kc.tti, 50);
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
        assert_eq!(kc.seed, "my-secret");
        assert_eq!(kc.mtu, 1400);
        assert_eq!(kc.tti, 20);
        assert_eq!(kc.header_size, 25);
    }
}
