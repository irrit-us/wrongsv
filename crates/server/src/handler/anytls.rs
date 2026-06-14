use std::io::{self, Read, Result as IoResult, Write};
use std::net::{Shutdown, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::{debug, info, trace, warn};
use wrongsv_protocol::{RequestCommand, RequestHeader};
use wrongsv_vless::vision::{TrafficState, VisionWriter};
use wrongsv_vless::{MemoryValidator, Validator};

use crate::config::AnyTlsServerConfig;

use super::*;

pub(crate) fn parse_anytls_config(
    ac: &AnyTlsServerConfig,
) -> Result<wrongsv_anytls::AnyTlsConfig, String> {
    use sha2::{Digest, Sha256};
    let password_sha256: [u8; 32] = Sha256::digest(ac.password.as_bytes()).into();

    let (cert_pem, key_pem) = match (&ac.certificate, &ac.key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => {
            let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                .map_err(|e| format!("anytls cert: {e}"))?;
            (cert, key)
        }
    };

    let tls_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
        .map_err(|e| format!("anytls tls: {e}"))?;

    let padding_scheme = ac
        .padding_scheme
        .as_deref()
        .and_then(|s| wrongsv_anytls::PaddingScheme::parse(s.as_bytes()));

    Ok(wrongsv_anytls::AnyTlsConfig {
        password_sha256,
        tls_config: std::sync::Arc::new(tls_config),
        dest: ac.dest.clone(),
        padding_scheme,
    })
}

pub(crate) fn handle_anytls_connection(
    stream: TcpStream,
    validator: Arc<MemoryValidator>,
    anytls_config: &wrongsv_anytls::AnyTlsConfig,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} AnyTLS connection");

    // AnyTLS accept: TLS handshake + password auth
    let tls_stream = match wrongsv_anytls::accept_anytls(stream, anytls_config) {
        Ok(tls) => tls,
        Err(accept_err) => {
            debug!("{peer} AnyTLS auth failed, fallback");
            if let Some(ref dest) = anytls_config.dest {
                wrongsv_anytls::anytls_fallback(accept_err.stream, accept_err.buffered_data, dest)?;
                return Ok(());
            }
            return Err(accept_err.error.into());
        }
    };
    info!("{peer} AnyTLS handshake complete");

    let fallback_email = {
        let users = validator.get_all();
        if users.len() == 1 {
            users[0].email.clone()
        } else {
            String::new()
        }
    };

    // Protocol detection: read first post-auth byte
    let (mut conn, mut stream_sock) = tls_stream.into_parts();
    let (proto, first_byte) =
        wrongsv_anytls::detect_post_auth_protocol(&mut conn, &mut stream_sock)?;

    if proto == wrongsv_anytls::PostAuthProtocol::SingAnyTls {
        return handle_sing_anytls_session(
            conn,
            stream_sock,
            peer,
            validator,
            metrics,
            fallback_email,
        );
    }

    // VLESS path: reconstruct AnyTlsStream and read the full header.
    // Pre-allocate buffer, put first_byte at position 0, read the rest.
    let mut tls_stream = wrongsv_anytls::AnyTlsStream::from_parts(conn, stream_sock);

    let mut first = vec![0u8; 8192];
    first[0] = first_byte;
    // Blocking read: AnyTlsStream::read() is non-blocking (returns WouldBlock
    // when no TLS plaintext is available), so we loop with read_tls on the
    // underlying socket until the VLESS header arrives.  This is critical over
    // high-latency paths where application data may not have arrived yet.
    let extra = loop {
        match tls_stream.read(&mut first[1..]) {
            Ok(n) => break n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                let (conn, sock) = tls_stream.get_mut();
                match conn.read_tls(sock) {
                    Ok(0) => {
                        return Err("connection closed before VLESS header".into());
                    }
                    Ok(_) => {
                        conn.process_new_packets()
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        continue;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        }
    };
    first.truncate(1 + extra);
    let n = first.len();
    trace!("{peer} AnyTLS read {n} bytes VLESS header");

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
    let (read_conn, write_conn) = tls_stream.get_mut();
    read_conn.writer().write_all(&resp_buf)?;
    while read_conn.wants_write() {
        read_conn.write_tls(write_conn)?;
    }

    // UDP relay (AnyTLS)
    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_anytls_udp(tls_stream, request, remaining_body, tap)?;
        debug!("{peer} AnyTLS UDP relay finished");
        return Ok(());
    }

    // Connect to target
    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("{peer} connecting to target {target_addr}");
    let target = TcpStream::connect(&target_addr)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(60)))?;

    if use_vision {
        let user_sent_id = account.id.bytes();
        relay_anytls_vision(
            tls_stream,
            target,
            user_sent_id,
            &account.testseed,
            remaining_body,
            tap,
        )?;
    } else {
        relay_anytls_raw(tls_stream, target, remaining_body, tap)?;
    }
    debug!("{peer} TCP relay finished");
    Ok(())
}

// ── sing-anytls session handler ─────────────────────────────────────────────

pub(crate) fn handle_sing_anytls_session(
    mut conn: rustls::ServerConnection,
    mut stream_sock: TcpStream,
    peer: std::net::SocketAddr,
    validator: Arc<MemoryValidator>,
    metrics: Arc<wrongsv_metrics::Registry>,
    fallback_email: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use wrongsv_anytls::session::{self, SessionWriter, WriteJob};

    let settings = session::complete_settings_handshake(&mut conn, &mut stream_sock)?;
    info!(
        "{peer} sing-anytls session from {} v{}",
        settings.client_name, settings.version
    );

    let (write_tx, write_rx) = std::sync::mpsc::channel::<WriteJob>();
    let writer = SessionWriter::new(write_tx);

    session::session_reader_loop(
        conn,
        stream_sock,
        write_rx,
        writer.clone(),
        move |stream, w| {
            handle_sing_stream(
                stream,
                w,
                peer,
                validator.clone(),
                Arc::clone(&metrics),
                fallback_email.clone(),
            );
        },
    )?;

    info!("{peer} sing-anytls session ended");
    Ok(())
}

pub(crate) fn handle_sing_stream(
    mut stream: wrongsv_anytls::stream::SingStream,
    writer: wrongsv_anytls::session::SessionWriter,
    peer: std::net::SocketAddr,
    validator: Arc<MemoryValidator>,
    metrics: Arc<wrongsv_metrics::Registry>,
    fallback_email: String,
) {
    let sid = stream.id;

    let first_data = match stream.read_chunk() {
        Some(d) => d,
        None => {
            let _ = writer.send_fin(sid);
            return;
        }
    };

    if first_data.is_empty() {
        let _ = writer.send_synack_error(sid, "empty stream");
        return;
    }

    // Protocol detection: first byte determines the addressing scheme.
    // 0x00 = VLESS header (anytls-as-transport mode)
    // 0x01/0x03/0x04 = SOCKS5 address (standalone anytls protocol)
    let result = if first_data[0] == 0x00 {
        handle_sing_stream_vless(stream, writer, first_data, peer, validator, metrics)
    } else {
        handle_sing_stream_socks(stream, writer, first_data, peer, metrics, fallback_email)
    };

    if let Err(e) = result {
        warn!("{peer} sing stream sid={sid}: {e}");
    }
}

pub(crate) fn handle_sing_stream_socks(
    stream: wrongsv_anytls::stream::SingStream,
    writer: wrongsv_anytls::session::SessionWriter,
    first_data: Vec<u8>,
    peer: std::net::SocketAddr,
    metrics: Arc<wrongsv_metrics::Registry>,
    fallback_email: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let sid = stream.id;

    let (target_addr, target_port, consumed) = wrongsv_anytls::socks::parse_socks_addr(&first_data)
        .ok_or_else(|| "invalid SOCKS5 address in first PSH".to_string())?;

    let addr_str = format!("{}:{}", target_addr, target_port);
    info!("{peer} sing-anytls SOCKS5 sid={sid} -> {addr_str}");

    let target = TcpStream::connect(&addr_str)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(60)))?;

    // Send SYNACK after successful target connection
    writer.send_synack(sid)?;

    // If there's data after the SOCKS5 address, forward it to target
    let remaining = if consumed < first_data.len() {
        first_data[consumed..].to_vec()
    } else {
        Vec::new()
    };
    let tap = wrongsv_metrics::MetricsTap::new(metrics, fallback_email);
    let _conn_guard = tap.track_connection();

    relay_sing_raw(stream, writer, target, remaining, tap)?;
    Ok(())
}

pub(crate) fn handle_sing_stream_vless(
    stream: wrongsv_anytls::stream::SingStream,
    writer: wrongsv_anytls::session::SessionWriter,
    first_data: Vec<u8>,
    peer: std::net::SocketAddr,
    validator: Arc<MemoryValidator>,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sid = stream.id;

    let VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    } = decode_vless_request(first_data, &validator, peer)?;
    let request = &decoded.header;
    let account = &request.user.account;
    let tap = wrongsv_metrics::MetricsTap::new(metrics, request.user.email.clone());
    let _conn_guard = tap.track_connection();

    info!(
        "{peer} sing-anytls {} {} -> {}:{}",
        if request.command == RequestCommand::Tcp {
            "TCP"
        } else {
            "UDP"
        },
        request.user.email,
        request.address,
        request.port,
    );

    if request.command == RequestCommand::Udp && use_vision {
        writer.send_synack_error(sid, "Vision does not support UDP")?;
        return Ok(());
    }

    // Send VLESS response header via PSH
    let resp_buf = response_header_buf(request)?;

    writer.send_synack(sid)?;
    if !resp_buf.is_empty() {
        writer.send_psh(sid, &resp_buf)?;
    }
    info!(
        "{peer} sing-anytls SYNACK sent sid={sid}, resp_len={}",
        resp_buf.len()
    );

    if request.command == RequestCommand::Udp {
        if !account.udp {
            writer.send_fin(sid)?;
            return Ok(());
        }
        relay_sing_udp(stream, writer, request, remaining_body)?;
        return Ok(());
    }

    // Connect to target
    let target_addr = format!("{}:{}", request.address, request.port);
    let target = TcpStream::connect(&target_addr)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(60)))?;

    if use_vision {
        let user_sent_id = account.id.bytes();
        relay_sing_vision(
            stream,
            writer,
            target,
            user_sent_id,
            &account.testseed,
            remaining_body,
            tap,
        )?;
    } else {
        relay_sing_raw(stream, writer, target, remaining_body, tap)?;
    }

    debug!("{peer} sing-anytls stream sid={sid} relay finished");
    Ok(())
}
pub(crate) fn relay_sing_raw(
    mut stream: wrongsv_anytls::stream::SingStream,
    writer: wrongsv_anytls::session::SessionWriter,
    mut target: TcpStream,
    initial_data: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    let sid = stream.id;
    let mut buf = [0u8; 32768];
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(2)))?;

    if !initial_data.is_empty() {
        metrics.record_in(initial_data.len() as u64);
        target.write_all(&initial_data)?;
    }

    loop {
        // Target → client (PSH frames)
        match target.read(&mut buf) {
            Ok(0) => {
                let _ = writer.send_fin(sid);
                break;
            }
            Ok(n) => {
                metrics.record_out(n as u64);
                writer.send_psh(sid, &buf[..n])?;
                target.set_read_timeout(Some(Duration::from_millis(10)))?;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                target.set_read_timeout(Some(Duration::from_secs(2)))?;
            }
            Err(e) => return Err(e.into()),
        }

        // Client → target (from SingStream channel)
        match stream.try_read_chunk() {
            Some(data) => {
                metrics.record_in(data.len() as u64);
                target.write_all(&data)?;
                target.set_read_timeout(Some(Duration::from_millis(10)))?;
            }
            None if stream.is_closed() => {
                let _ = writer.send_fin(sid);
                let _ = target.shutdown(Shutdown::Write);
                break;
            }
            None => {}
        }
    }

    let _ = target.shutdown(Shutdown::Write);
    Ok(())
}

pub(crate) fn relay_sing_vision(
    mut stream: wrongsv_anytls::stream::SingStream,
    writer: wrongsv_anytls::session::SessionWriter,
    mut target: TcpStream,
    user_sent_id: &[u8],
    testseed: &[u32],
    initial_data: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    let sid = stream.id;
    let up_seed = if testseed.len() >= 4 {
        testseed.to_vec()
    } else {
        vec![900, 500, 900, 256]
    };
    let mut up_state = TrafficState::new(user_sent_id);
    let mut down_state = TrafficState::new(user_sent_id);
    let mut down_user_uuid: Option<[u8; 16]> = Some(down_state.user_uuid);

    if !initial_data.is_empty() {
        let unpadded = wrongsv_vless::vision::xtls_unpadding(&initial_data, &mut up_state, true);
        if !unpadded.is_empty() {
            metrics.record_in(unpadded.len() as u64);
            target.write_all(&unpadded)?;
        }
    }

    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut buf = [0u8; 32768];
    loop {
        // Downlink: target → Vision encode → PSH
        let downlink_done = loop {
            match target.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => {
                    metrics.record_out(n as u64);
                    let mut encoded = Vec::with_capacity(n + 256);
                    {
                        struct BufWriter<'a>(&'a mut Vec<u8>);
                        impl Write for BufWriter<'_> {
                            fn write(&mut self, data: &[u8]) -> IoResult<usize> {
                                self.0.extend_from_slice(data);
                                Ok(data.len())
                            }
                            fn flush(&mut self) -> IoResult<()> {
                                Ok(())
                            }
                        }
                        let mut w = VisionWriter::new(
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
                        writer.send_psh(sid, &encoded)?;
                    }
                    target.set_read_timeout(Some(Duration::from_millis(10)))?;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    target.set_read_timeout(Some(Duration::from_secs(2)))?;
                    break false;
                }
                Err(e) => return Err(e.into()),
            }
        };

        // Uplink: SingStream → Vision decode → target
        let mut uplink_done = false;
        loop {
            match stream.try_read_chunk() {
                Some(data) => {
                    let unpadded =
                        wrongsv_vless::vision::xtls_unpadding(&data, &mut up_state, true);
                    if !unpadded.is_empty() {
                        metrics.record_in(unpadded.len() as u64);
                        target.write_all(&unpadded)?;
                        target.set_read_timeout(Some(Duration::from_millis(10)))?;
                    }
                }
                None if stream.is_closed() => {
                    uplink_done = true;
                    break;
                }
                None => break,
            }
        }

        if uplink_done {
            let _ = writer.send_fin(sid);
            break;
        }
        if downlink_done {
            let _ = writer.send_fin(sid);
            break;
        }
    }

    let _ = target.shutdown(Shutdown::Write);
    Ok(())
}

pub(crate) fn relay_sing_udp(
    _stream: wrongsv_anytls::stream::SingStream,
    writer: wrongsv_anytls::session::SessionWriter,
    _request: &RequestHeader,
    _remaining: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    // UDP over sing-anytls streams is not yet implemented.
    // Signal to the client that we can't handle this.
    let _ = writer.send_fin(_stream.id);
    Ok(())
}
// ── Two-thread TLS relay helpers ────────────────────────────────────────────
//
// The single-threaded alternating loop hits a throughput wall on high-latency
// paths because read_tls(10ms) WouldBlocks before tunnel data arrives
// (RTT > 100ms).  relay_raw solves this with two blocking threads.
//
// We replicate that here: one thread for client→target, one for
// target→client.  To avoid holding the Mutex<ServerConnection> during
// socket I/O we:
//
//   reader: sock.read(raw) → lock → read_tls(PreReadBuf) → decrypt → unlock → target.write
//   writer: target.read(plain) → lock → encrypt → write_tls(VecWriter) → unlock → sock.write(tls_out)
//
// The lock is held only for CPU work (TLS encrypt/decrypt), not for socket I/O.

/// Accumulates raw bytes from multiple socket reads so `read_tls` can
/// consume complete TLS records even when TCP segments arrive fragmented.
/// Returns `WouldBlock` when empty to signal "need more data from socket".
struct ReadBuf {
    data: Vec<u8>,
    pos: usize,
}

impl ReadBuf {
    fn new() -> Self {
        Self {
            data: Vec::with_capacity(RELAY_BUF),
            pos: 0,
        }
    }

    fn extend(&mut self, bytes: &[u8]) {
        // Drop already-consumed bytes before appending.
        if self.pos > 0 {
            self.data.drain(..self.pos);
            self.pos = 0;
        }
        self.data.extend_from_slice(bytes);
    }
}

impl Read for ReadBuf {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let avail = self.data.len().saturating_sub(self.pos);
        if avail == 0 {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "buffer empty"));
        }
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Collects `write_tls` output into a `Vec` so the lock isn't held during
/// blocking socket writes.
struct VecWriter<'a>(&'a mut Vec<u8>);

impl Write for VecWriter<'_> {
    fn write(&mut self, data: &[u8]) -> IoResult<usize> {
        self.0.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

const RELAY_BUF: usize = 32768;

pub(crate) fn relay_anytls_raw(
    tls: wrongsv_anytls::AnyTlsStream,
    mut target: TcpStream,
    initial_data: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    target.set_nodelay(true)?;

    if !initial_data.is_empty() {
        metrics.record_in(initial_data.len() as u64);
        target.write_all(&initial_data)?;
    }

    // Split TLS stream into connection state + socket, then clone the
    // socket so reader and writer get independent file descriptors.
    let (conn, stream) = tls.into_parts();
    let mut stream_read = stream.try_clone()?;
    let mut stream_write = stream;

    let tls_conn = Arc::new(Mutex::new(conn));

    let mut target_w = target.try_clone()?;
    let mut target_r = target;

    let metrics_up = metrics.clone();
    let metrics_down = metrics;

    // ── Reader thread: client → target ──────────────────────────────────
    let tls_reader = Arc::clone(&tls_conn);
    let t1 = thread::spawn(move || {
        let mut raw = vec![0u8; RELAY_BUF];
        let mut plain = vec![0u8; RELAY_BUF];
        let mut rbuf = ReadBuf::new();
        loop {
            // Block on socket read — no lock held.
            match stream_read.read(&mut raw) {
                Ok(0) => break,
                Ok(n) => {
                    rbuf.extend(&raw[..n]);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => break,
            }

            // Feed accumulated bytes to TLS.  If a complete TLS record hasn't
            // arrived yet (WouldBlock), loop back to read more from the socket.
            loop {
                let mut conn = match tls_reader.lock() {
                    Ok(c) => c,
                    Err(_) => return,
                };
                match conn.read_tls(&mut rbuf) {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // Not enough bytes for a complete TLS record — read
                        // more from the socket in the outer loop.
                        break;
                    }
                    Err(_) => return,
                }
                if conn.process_new_packets().is_err() {
                    return;
                }
                // Drain all decrypted plaintext records.
                loop {
                    match conn.reader().read(&mut plain) {
                        Ok(0) => break,
                        Ok(m) => {
                            drop(conn); // release lock before target I/O
                            metrics_up.record_in(m as u64);
                            if target_w.write_all(&plain[..m]).is_err() {
                                return;
                            }
                            conn = match tls_reader.lock() {
                                Ok(c) => c,
                                Err(_) => return,
                            };
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
                drop(conn);
                // Try more TLS records from the buffer before going
                // back to the socket for more raw bytes.
                continue;
            }
        }
        let _ = target_w.shutdown(Shutdown::Write);
    });

    // ── Writer thread: target → client ──────────────────────────────────
    let tls_writer = Arc::clone(&tls_conn);
    let t2 = thread::spawn(move || {
        let mut buf = vec![0u8; RELAY_BUF];
        let mut tls_out = Vec::with_capacity(RELAY_BUF + 16384);
        loop {
            match target_r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    metrics_down.record_out(n as u64);
                    // Encrypt inside the lock (CPU-only, lock held briefly).
                    let mut conn = match tls_writer.lock() {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    if conn.writer().write_all(&buf[..n]).is_err() {
                        break;
                    }
                    tls_out.clear();
                    while conn.wants_write() {
                        let mut vw = VecWriter(&mut tls_out);
                        if conn.write_tls(&mut vw).is_err() {
                            break;
                        }
                    }
                    drop(conn); // release lock before socket I/O
                    if !tls_out.is_empty() {
                        if stream_write.write_all(&tls_out).is_err() {
                            break;
                        }
                        let _ = stream_write.flush();
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => break,
            }
        }
        // Send TLS close_notify (inside lock) then flush to socket.
        if let Ok(mut conn) = tls_writer.lock() {
            conn.send_close_notify();
            tls_out.clear();
            while conn.wants_write() {
                let mut vw = VecWriter(&mut tls_out);
                if conn.write_tls(&mut vw).is_err() {
                    break;
                }
            }
            drop(conn);
            if !tls_out.is_empty() {
                let _ = stream_write.write_all(&tls_out);
            }
        }
        let _ = target_r.shutdown(Shutdown::Write);
    });

    t1.join().ok();
    t2.join().ok();
    Ok(())
}

pub(crate) fn relay_anytls_vision(
    mut tls: wrongsv_anytls::AnyTlsStream,
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
    let (conn, stream) = tls.get_mut();
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut buf = [0u8; 32768];
    loop {
        // Downlink: target → Vision encode → TLS
        let downlink_done = loop {
            match target.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => {
                    metrics.record_out(n as u64);
                    let mut encoded = Vec::with_capacity(n + 256);
                    {
                        use wrongsv_vless::vision::VisionWriter;
                        struct BufWriter<'a>(&'a mut Vec<u8>);
                        impl Write for BufWriter<'_> {
                            fn write(&mut self, data: &[u8]) -> IoResult<usize> {
                                self.0.extend_from_slice(data);
                                Ok(data.len())
                            }
                            fn flush(&mut self) -> IoResult<()> {
                                Ok(())
                            }
                        }
                        let mut w = VisionWriter::new(
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
                        conn.writer().write_all(&encoded)?;
                        while conn.wants_write() {
                            conn.write_tls(stream)?;
                        }
                    }
                    target.set_read_timeout(Some(Duration::from_millis(10)))?;
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    target.set_read_timeout(Some(Duration::from_secs(2)))?;
                    break false;
                }
                Err(e) => return Err(e.into()),
            }
        };

        // Uplink: TLS → Vision decode → target
        let uplink_done = loop {
            match conn.read_tls(stream) {
                Ok(0) => break true,
                Ok(_) => {
                    conn.process_new_packets()
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                    loop {
                        match conn.reader().read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let unpadded = wrongsv_vless::vision::xtls_unpadding(
                                    &buf[..n],
                                    &mut up_state,
                                    true,
                                );
                                if !unpadded.is_empty() {
                                    metrics.record_in(unpadded.len() as u64);
                                    target.write_all(&unpadded)?;
                                    target.set_read_timeout(Some(Duration::from_millis(10)))?;
                                }
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break false,
                Err(e) => return Err(e.into()),
            }
        };

        if uplink_done {
            // Client is done sending. Shut down target's write side so
            // the echo server sees EOF and closes, which will trigger
            // downlink_done in the next iteration. Don't break here —
            // the downlink still needs to flush the response.
            let _ = target.shutdown(Shutdown::Write);
            // Clear uplink_done so we continue looping for downlink flush
        }
        if downlink_done {
            conn.send_close_notify();
            while conn.wants_write() {
                conn.write_tls(stream)?;
            }
            break;
        }
        // Safety: if both sides are done (uplink closed, target drained),
        // don't spin forever
        if uplink_done && downlink_done {
            conn.send_close_notify();
            while conn.wants_write() {
                conn.write_tls(stream)?;
            }
            break;
        }
    }
    Ok(())
}

pub(crate) fn relay_anytls_udp(
    mut tls: wrongsv_anytls::AnyTlsStream,
    request: &RequestHeader,
    remaining: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    if is_packetaddr_request(request) {
        debug!("AnyTLS packetaddr UDP relay");
        tls.get_mut()
            .1
            .set_read_timeout(Some(Duration::from_millis(200)))?;
        return relay_packetaddr_udp_stream(&mut tls, remaining);
    }

    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("AnyTLS UDP relay to {target_addr}");

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(&target_addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;

    let mut tls_buf = remaining;
    let mut udp_buf = [0u8; 65535];

    let (conn, stream) = tls.get_mut();

    loop {
        let mut did_work = false;

        let mut tmp = [0u8; 8192];
        match conn.reader().read(&mut tmp) {
            Ok(n) if n > 0 => {
                tls_buf.extend_from_slice(&tmp[..n]);
                did_work = true;
            }
            Ok(_) => match conn.read_tls(stream) {
                Ok(0) => break,
                Ok(_) => {
                    conn.process_new_packets()
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                    continue;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                match conn.read_tls(stream) {
                    Ok(0) => break,
                    Ok(_) => {
                        conn.process_new_packets()
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        continue;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
            }
            Err(_) => break,
        }

        while tls_buf.len() >= 2 {
            let len = u16::from_be_bytes([tls_buf[0], tls_buf[1]]) as usize;
            if tls_buf.len() < 2 + len {
                break;
            }
            let pkt = tls_buf[2..2 + len].to_vec();
            tls_buf.drain(..2 + len);
            metrics.record_in(pkt.len() as u64);
            socket.send(&pkt)?;
            did_work = true;
        }

        match socket.recv(&mut udp_buf) {
            Ok(n) if n > 0 => {
                metrics.record_out(n as u64);
                conn.writer().write_all(&(n as u16).to_be_bytes())?;
                conn.writer().write_all(&udp_buf[..n])?;
                while conn.wants_write() {
                    conn.write_tls(stream)?;
                }
                did_work = true;
            }
            Ok(_) => break,
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }

        if !did_work {
            thread::sleep(Duration::from_millis(20));
        }
    }
    Ok(())
}

// ── WebSocket relay functions ─────────────────────────────────────────────────
