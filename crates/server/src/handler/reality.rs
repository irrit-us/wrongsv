use std::io::{Read, Result as IoResult, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::{debug, info, trace};
use wrongsv_protocol::{RequestCommand, RequestHeader};
use wrongsv_vless::MemoryValidator;
use wrongsv_vless::vision::{TrafficState, VisionReader, VisionWriter};

use crate::config::RealityServerConfig;

use super::*;

pub(crate) fn parse_reality_config(
    rc: &RealityServerConfig,
) -> Result<wrongsv_reality::RealityConfig, String> {
    let private_key =
        decode_hex::<32>(&rc.private_key).map_err(|e| format!("reality.private_key: {e}"))?;
    let short_ids: Result<Vec<[u8; 4]>, _> =
        rc.short_ids.iter().map(|s| decode_hex::<4>(s)).collect();
    let short_ids = short_ids.map_err(|e| format!("reality.short_ids: {e}"))?;
    let cert_material = wrongsv_reality::cert::build_cert_material()
        .map_err(|e| format!("reality cert material: {e}"))?;
    Ok(wrongsv_reality::RealityConfig::new(
        private_key,
        short_ids,
        rc.max_time_diff,
        cert_material,
        rc.dest.clone(),
    ))
}
pub(crate) fn handle_reality_connection(
    stream: TcpStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    reality_config: &wrongsv_reality::RealityConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} REALITY connection");

    // REALITY accept: parse ClientHello, authenticate, generate cert
    let mut tls_stream = match wrongsv_reality::accept_reality(stream, reality_config) {
        Ok(tls) => tls,
        Err(accept_err) => {
            debug!(
                "{peer} REALITY auth failed: {} — spider fallback",
                accept_err.error
            );
            if let Some(ref dest) = reality_config.dest {
                wrongsv_reality::spider_fallback(
                    accept_err.stream,
                    accept_err.buffered_data,
                    dest,
                )?;
                return Ok(());
            }
            return Err(accept_err.error.into());
        }
    };
    wrongsv_reality::complete_handshake(&mut tls_stream)?;
    info!("{peer} REALITY handshake complete");

    // Read VLESS header from TLS stream
    trace!("{peer} reading VLESS header from TLS...");
    let mut first = vec![0u8; 8192];
    let (read_conn, write_conn) = tls_stream.get_mut();
    loop {
        let result = read_conn.reader().read(&mut first);
        match result {
            Ok(0) => {
                let n = read_conn.read_tls(write_conn)?;
                if n == 0 {
                    return Err("connection closed before VLESS header".into());
                }
                read_conn
                    .process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            }
            Ok(n) => {
                first.truncate(n);
                break;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let n = read_conn.read_tls(write_conn)?;
                if n == 0 {
                    return Err("connection closed before VLESS header".into());
                }
                read_conn
                    .process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            }
            Err(e) => return Err(e.into()),
        }
    }

    let n = first.len();
    trace!("{peer} REALITY read {n} bytes VLESS header");

    let VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    } = decode_vless_request(first, &validator, peer)?;

    let request = &decoded.header;
    let account = &request.user.account;

    log_vless_request(peer, request);
    trace!(
        "{peer} flow={} use_vision={use_vision}",
        decoded.addons.flow
    );
    handle_kyber_addons(peer, &decoded, kyber_sk);
    validate_vless_command(request, use_vision)?;

    let resp_buf = response_header_buf(request)?;
    read_conn.writer().write_all(&resp_buf)?;
    // Flush TLS
    while read_conn.wants_write() {
        read_conn.write_tls(write_conn)?;
    }

    // UDP relay (REALITY)
    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_reality_udp(tls_stream, request, remaining_body)?;
        debug!("{peer} REALITY UDP relay finished");
        return Ok(());
    }

    // Connect to target
    let target_addr = format!("{}:{}", request.address, request.port);
    trace!("{peer} connecting to target {target_addr}");
    let addr = target_addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("DNS resolution failed for {target_addr}"))?;
    let target = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;
    trace!("{peer} connected to target");

    if use_vision {
        trace!(
            "{peer} starting REALITY Vision relay (initial={}B)",
            remaining_body.len()
        );
        relay_reality_vision(
            tls_stream,
            target,
            &decoded.user_sent_id,
            &account.testseed,
            remaining_body,
        )?;
    } else {
        trace!(
            "{peer} starting REALITY raw relay (initial={}B)",
            remaining_body.len()
        );
        relay_reality(tls_stream, target, remaining_body)?;
    }
    trace!("{peer} REALITY relay finished");

    Ok(())
}

pub(crate) fn relay_reality(
    mut tls: wrongsv_reality::RealityTlsStream,
    mut target: TcpStream,
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    trace!("relay_reality: start, initial_data={}B", initial_data.len());
    let mut buf = [0u8; 32768];
    target.set_read_timeout(Some(Duration::from_secs(1)))?;

    if !initial_data.is_empty() {
        target.write_all(&initial_data)?;
        trace!(
            "relay_reality: wrote {}B initial data to target",
            initial_data.len()
        );
    }

    let (conn, stream) = tls.get_mut();
    stream
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(1)))?;

    let mut c2t_bytes: u64 = 0;
    let mut t2c_bytes: u64 = 0;

    loop {
        // Client → Target: read TLS records, then drain plaintext
        match conn.read_tls(stream) {
            Ok(0) => {
                trace!("relay_reality: client EOF (c2t={c2t_bytes} t2c={t2c_bytes})");
                break;
            }
            Ok(_) => {
                conn.process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                loop {
                    match conn.reader().read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            target.write_all(&buf[..n])?;
                            c2t_bytes += n as u64;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }

        // Target → Client: read from target, encrypt and send to client
        match target.read(&mut buf) {
            Ok(0) => {
                trace!("relay_reality: target EOF (c2t={c2t_bytes} t2c={t2c_bytes})");
                break;
            }
            Ok(n) => {
                conn.writer().write_all(&buf[..n])?;
                while conn.wants_write() {
                    conn.write_tls(stream)?;
                }
                t2c_bytes += n as u64;
            }
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e.into()),
        }
    }

    conn.send_close_notify();
    while conn.wants_write() {
        conn.write_tls(stream)?;
    }
    stream.get_mut().shutdown(std::net::Shutdown::Write)?;
    trace!("relay_reality: finished (c2t={c2t_bytes} t2c={t2c_bytes})");
    Ok(())
}

/// Thin `Read` handle for a mutex-protected TLS stream.
///
/// Two of these can operate concurrently: one in the uplink thread
/// (client→target) and one in the downlink thread (target→client).
/// Each thread locks only for the duration of the I/O call.
pub(crate) struct TlsReadHandle<R> {
    inner: Arc<Mutex<R>>,
}

impl<R: Read> Read for TlsReadHandle<R> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .read(buf)
    }
}

/// Thin `Write` handle for a mutex-protected TLS stream.
pub(crate) struct TlsWriteHandle<W> {
    inner: Arc<Mutex<W>>,
}

impl<W: Write> Write for TlsWriteHandle<W> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).flush()
    }
}

/// Vision-aware relay for REALITY TLS connections.
///
/// Mirrors `relay_vision` but the client side is a `RealityTlsStream` instead
/// of a raw `TcpStream`. The TLS stream is shared via `Arc<Mutex<>>` so the
/// two Vision threads (uplink and downlink) can read and write concurrently.
pub(crate) fn relay_reality_vision(
    mut tls: wrongsv_reality::RealityTlsStream,
    target: TcpStream,
    user_sent_id: &[u8],
    testseed: &[u32],
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Blocking client TCP with 1s timeout — inherited from listener's
    // non-blocking mode via Linux socket propagation.
    {
        let (_, stream) = tls.get_mut();
        stream.get_mut().set_nonblocking(false)?;
        stream
            .get_mut()
            .set_read_timeout(Some(Duration::from_secs(1)))?;
    }

    let tls = Arc::new(Mutex::new(tls));
    let t_read = target.try_clone()?;
    let t_write = target;

    let mut up_state = TrafficState::new(user_sent_id);
    let up_seed = if testseed.len() >= 4 {
        testseed.to_vec()
    } else {
        vec![900, 500, 900, 256]
    };

    let tls1 = Arc::clone(&tls);
    let t1 = thread::spawn(move || {
        let mut tgt = t_write;
        if !initial_data.is_empty() {
            use wrongsv_vless::vision::xtls_unpadding;
            let mut init_state = up_state.clone();
            let unpadded = xtls_unpadding(&initial_data, &mut init_state, true);
            if !unpadded.is_empty() && tgt.write_all(&unpadded).is_err() {
                let _ = tgt.shutdown(Shutdown::Write);
                return;
            }
            up_state = init_state;
        }
        let inner = TlsReadHandle::<wrongsv_reality::RealityTlsStream> { inner: tls1 };
        let mut reader = VisionReader::new(inner, up_state, true);
        let mut buf = [0u8; 32768];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tgt.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                Err(_) => break,
            }
        }
        let _ = tgt.shutdown(Shutdown::Write);
    });

    let down_state = TrafficState::new(user_sent_id);
    let t2 = thread::spawn(move || {
        let inner = TlsWriteHandle::<wrongsv_reality::RealityTlsStream> { inner: tls };
        let mut writer = VisionWriter::new(inner, down_state, false, up_seed);
        let mut buf = [0u8; 32768];
        let mut tgt = t_read;
        loop {
            match tgt.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if writer.write(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => break,
            }
        }
        writer.flush().ok();
        let _ = tgt.shutdown(Shutdown::Write);
    });

    t1.join().ok();
    t2.join().ok();
    Ok(())
}

pub(crate) fn relay_reality_udp(
    mut tls: wrongsv_reality::RealityTlsStream,
    request: &RequestHeader,
    remaining: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    if is_packetaddr_request(request) {
        debug!("REALITY packetaddr UDP relay");
        tls.get_mut()
            .1
            .get_mut()
            .set_read_timeout(Some(Duration::from_millis(200)))?;
        return relay_packetaddr_udp_stream(&mut tls, remaining);
    }

    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("REALITY UDP relay to {target_addr}");

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(&target_addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;

    // Accumulate TLS plaintext here, starting with any pipelined bytes from
    // the initial header read. Complete length-prefixed packets are drained
    // and forwarded to the UDP target.
    let mut tls_buf = remaining;
    let mut udp_buf = [0u8; 65535];

    loop {
        let mut did_work = false;

        // Try to read more plaintext from TLS (non-blocking via WouldBlock)
        let mut tmp = [0u8; 8192];
        match tls.read(&mut tmp) {
            Ok(n) => {
                if n > 0 {
                    tls_buf.extend_from_slice(&tmp[..n]);
                    did_work = true;
                } else {
                    break; // TLS EOF
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }

        // Drain complete length-prefixed packets from the buffer
        while tls_buf.len() >= 2 {
            let len = u16::from_be_bytes([tls_buf[0], tls_buf[1]]) as usize;
            if tls_buf.len() < 2 + len {
                break;
            }
            let pkt = tls_buf[2..2 + len].to_vec();
            tls_buf.drain(..2 + len);
            socket.send(&pkt)?;
            did_work = true;
        }

        // UDP → Client: read response, write length-prefixed to TLS
        match socket.recv(&mut udp_buf) {
            Ok(n) => {
                if n > 0 {
                    tls.write_all(&(n as u16).to_be_bytes())?;
                    tls.write_all(&udp_buf[..n])?;
                    tls.flush()?;
                    did_work = true;
                } else {
                    break;
                }
            }
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
