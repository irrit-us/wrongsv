use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
use wrongsv_uuid::Uuid;
use wrongsv_vless::vision::{TrafficState, VisionReader, VisionWriter};
use wrongsv_vless::{MemoryValidator, Validator, XRV};
use wrongsv_vless_encoding::{
    self as encoding, Addons, LengthPacketReader, LengthPacketWriter, PacketReadError,
};

use crate::config::{Config, RealityServerConfig};

/// Decode a hex string into a fixed-size byte array.
fn decode_hex<const N: usize>(hex: &str) -> Result<[u8; N], String> {
    let hex = hex.trim();
    if hex.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, hex.len()));
    }
    let mut bytes = [0u8; N];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(chunk[0]).ok_or_else(|| format!("invalid hex at position {}", i * 2))?;
        let lo =
            hex_val(chunk[1]).ok_or_else(|| format!("invalid hex at position {}", i * 2 + 1))?;
        bytes[i] = hi << 4 | lo;
    }
    Ok(bytes)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_reality_config(
    rc: &RealityServerConfig,
) -> Result<wrongsv_reality::RealityConfig, String> {
    let private_key =
        decode_hex::<32>(&rc.private_key).map_err(|e| format!("reality.private_key: {e}"))?;
    let short_ids: Result<Vec<[u8; 8]>, _> =
        rc.short_ids.iter().map(|s| decode_hex::<8>(s)).collect();
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

pub struct InboundServer {
    config: Config,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    reality_config: Option<wrongsv_reality::RealityConfig>,
}

impl InboundServer {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        config.validate()?;
        let kyber_sk = match &config.kyber_secret_key {
            Some(hex) => Some(decode_hex::<64>(hex).map_err(|e| format!("kyber_secret_key: {e}"))?),
            None => None,
        };
        let reality_config = match &config.reality {
            Some(rc) => Some(parse_reality_config(rc)?),
            None => None,
        };
        let validator = Arc::new(MemoryValidator::new());
        for user in &config.users {
            let uuid = Uuid::parse_string(&user.id)?;
            let flow = if user.flow.is_empty() {
                config.flow.clone().unwrap_or_default()
            } else {
                user.flow.clone()
            };
            let mu = MemoryUser {
                account: MemoryAccount {
                    id: ID::new(uuid),
                    flow,
                    encryption: user.encryption.clone(),
                    udp: user.udp,
                    xor_mode: 0,
                    seconds: 0,
                    padding: String::new(),
                    testpre: 0,
                    testseed: vec![],
                },
                email: user.email.clone(),
                level: 0,
            };
            validator.add(mu)?;
        }
        Ok(InboundServer {
            config,
            validator,
            kyber_sk,
            reality_config,
        })
    }

    /// Run the server loop. Returns on fatal error or graceful shutdown (SIGINT/SIGTERM).
    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.config.listen)?;
        listener.set_nonblocking(true)?;
        info!("VLESS server listening on {}", self.config.listen);

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        if let Err(e) = ctrlc::set_handler(move || {
            if r.load(Ordering::SeqCst) {
                eprintln!("received interrupt signal, shutting down gracefully...");
                info!("received interrupt signal, shutting down gracefully...");
                r.store(false, Ordering::SeqCst);
            } else {
                eprintln!("second interrupt — forcing exit");
                std::process::exit(1);
            }
        }) {
            // MultipleHandlers is non-fatal (multi-instance tests, hot-reload)
            if !matches!(e, ctrlc::Error::MultipleHandlers) {
                return Err(format!("failed to set Ctrl-C handler: {e}").into());
            }
        }

        let validator = Arc::clone(&self.validator);
        let kyber_sk = self.kyber_sk;
        let reality_config = self.reality_config.clone();

        loop {
            if !running.load(Ordering::SeqCst) {
                info!("server stopped");
                break;
            }
            match listener.accept() {
                Ok((stream, addr)) => {
                    debug!("accepted connection from {}", addr);
                    let v = Arc::clone(&validator);
                    let rc = reality_config.clone();
                    thread::spawn(move || {
                        let result = if let Some(ref rc) = rc {
                            handle_reality_connection(stream, v, kyber_sk, rc)
                        } else {
                            handle_connection(stream, v, kyber_sk)
                        };
                        if let Err(e) = result {
                            warn!("connection error: {}", e);
                        }
                        trace!("connection thread finished");
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(200));
                    continue;
                }
                Err(e) => {
                    error!("accept error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }
}

fn handle_connection(
    mut stream: TcpStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} new connection");
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    // Read first chunk from connection
    let mut first = vec![0u8; 8192];
    let n = stream.read(&mut first)?;
    first.truncate(n);
    trace!("{peer} read {n} bytes");

    if n < 18 {
        debug!("{peer} connection too short ({n} bytes), dropping");
        return Err("connection too short for VLESS header".into());
    }

    // Decode the VLESS request header, capturing any remaining body bytes
    let (decoded, remaining_body) = {
        let v = validator.clone();
        let mut cursor = std::io::Cursor::new(first);
        let decoded = encoding::decode_request_header(&mut cursor, move |id| v.get(id))?;
        let pos = cursor.position() as usize;
        let inner = cursor.into_inner();
        let remaining = if pos < inner.len() {
            inner[pos..].to_vec()
        } else {
            Vec::new()
        };
        (decoded, remaining)
    };

    let request = &decoded.header;
    let account = &request.user.account;

    info!(
        "{} {} {} -> {}:{}",
        peer,
        if request.command == RequestCommand::Tcp {
            "TCP"
        } else {
            "UDP"
        },
        request.user.email,
        request.address,
        request.port,
    );

    // Check flow
    let use_vision = decoded.addons.flow == XRV && account.flow == XRV;
    trace!(
        "{peer} flow={} use_vision={use_vision}",
        decoded.addons.flow
    );

    // Kyber session-key decapsulation
    if !decoded.addons.kyber_ct.is_empty() {
        if let Some(sk) = kyber_sk {
            match wrongsv_kyber::decapsulate(&sk, &decoded.addons.kyber_ct) {
                Ok(_shared_secret) => {
                    info!(
                        "{} Kyber session established (ML-KEM-512, ss={} bytes)",
                        peer,
                        wrongsv_kyber::SS_SIZE,
                    );
                    // TODO: derive AeadKey from shared_secret, wrap streams in CommonConn
                }
                Err(e) => {
                    warn!("{} Kyber decapsulation failed: {}", peer, e);
                }
            }
        } else {
            debug!(
                "{} client sent kyber_ct but server has no kyber_secret_key configured",
                peer
            );
        }
    }

    // UDP+Vision is unsupported (xray-core also rejects this combination)
    if request.command == RequestCommand::Udp && use_vision {
        return Err("XTLS Vision does not support UDP".into());
    }

    // Send response header
    let response_addons = Addons {
        flow: String::new(),
        ..Default::default()
    };
    let mut resp_buf = bytes::BytesMut::new();
    encoding::encode_response_header(&mut resp_buf, request, &response_addons)?;
    stream.write_all(&resp_buf)?;

    // UDP relay
    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_udp(stream, request, remaining_body)?;
        debug!("{peer} UDP relay finished");
        return Ok(());
    }

    // Connect to target
    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("{peer} connecting to target {target_addr}");
    let target = TcpStream::connect_timeout(&target_addr.parse()?, Duration::from_secs(10))?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;
    trace!("{peer} connected to target");

    // Clear read timeout for the rest of the connection
    stream.set_read_timeout(None)?;

    if use_vision {
        trace!("{peer} starting vision relay");
        relay_vision(stream, target, &decoded.user_sent_id, &account.testseed)?;
    } else {
        trace!("{peer} starting raw relay");
        relay_raw(stream, target)?;
    }
    debug!("{peer} relay finished");

    Ok(())
}

fn handle_reality_connection(
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
            debug!("{peer} REALITY auth failed, spider fallback");
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
    let mut first = vec![0u8; 8192];
    let (read_conn, write_conn) = tls_stream.get_mut();
    // Read initial bytes — try TLS first
    loop {
        match read_conn.reader().read(&mut first) {
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
                return Err("REALITY: no data after handshake".into());
            }
            Err(e) => return Err(e.into()),
        }
    }

    let n = first.len();
    trace!("{peer} REALITY read {n} bytes VLESS header");

    if n < 18 {
        debug!("{peer} connection too short ({n} bytes), dropping");
        return Err("connection too short for VLESS header".into());
    }

    // Decode VLESS header, capturing remaining body bytes
    let (decoded, remaining_body) = {
        let v = validator.clone();
        let mut cursor = std::io::Cursor::new(first);
        let decoded = encoding::decode_request_header(&mut cursor, move |id| v.get(id))?;
        let pos = cursor.position() as usize;
        let inner = cursor.into_inner();
        let remaining = if pos < inner.len() {
            inner[pos..].to_vec()
        } else {
            Vec::new()
        };
        (decoded, remaining)
    };

    let request = &decoded.header;
    let account = &request.user.account;

    info!(
        "{} {} {} -> {}:{}",
        peer,
        if request.command == RequestCommand::Tcp {
            "TCP"
        } else {
            "UDP"
        },
        request.user.email,
        request.address,
        request.port,
    );

    let use_vision = decoded.addons.flow == XRV && account.flow == XRV;
    trace!(
        "{peer} flow={} use_vision={use_vision}",
        decoded.addons.flow
    );

    // Kyber decapsulation
    if !decoded.addons.kyber_ct.is_empty() {
        if let Some(sk) = kyber_sk {
            match wrongsv_kyber::decapsulate(&sk, &decoded.addons.kyber_ct) {
                Ok(_shared_secret) => {
                    info!(
                        "{peer} Kyber session established (ML-KEM-512, ss={} bytes)",
                        wrongsv_kyber::SS_SIZE
                    );
                }
                Err(e) => {
                    warn!("{peer} Kyber decapsulation failed: {}", e);
                }
            }
        } else {
            debug!("{peer} client sent kyber_ct but server has no kyber_secret_key configured");
        }
    }

    // UDP+Vision is unsupported
    if request.command == RequestCommand::Udp && use_vision {
        return Err("XTLS Vision does not support UDP".into());
    }

    // Send response header
    let response_addons = Addons {
        flow: String::new(),
        ..Default::default()
    };
    let mut resp_buf = bytes::BytesMut::new();
    encoding::encode_response_header(&mut resp_buf, request, &response_addons)?;
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
    debug!("{peer} connecting to target {target_addr}");
    let target = TcpStream::connect_timeout(&target_addr.parse()?, Duration::from_secs(10))?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;
    trace!("{peer} connected to target");

    if use_vision {
        debug!("{peer} REALITY+Vision relay not yet wired, falling through");
    }
    // Relay: client is TLS, target is raw TCP
    relay_reality(tls_stream, target)?;
    debug!("{peer} REALITY relay finished");

    Ok(())
}

fn relay_reality(
    mut tls: wrongsv_reality::RealityTlsStream,
    mut target: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    // Simple sequential relay: read from client → write to target,
    // then read from target → write to client. Repeat.
    let mut buf = [0u8; 8192];
    target.set_read_timeout(Some(Duration::from_secs(1)))?;
    let (conn, stream) = tls.get_mut();
    loop {
        // Client → Target: try to read plaintext from TLS
        match conn.reader().read(&mut buf) {
            Ok(0) => {
                // No decrypted data — read more TLS records
                match conn.read_tls(stream) {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        conn.process_new_packets()
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        continue;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No data from client, check target
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(n) => {
                target.write_all(&buf[..n])?;
                continue;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }

        // Target → Client: try to read from target
        match target.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                conn.writer().write_all(&buf[..n])?;
                // Flush TLS
                while conn.wants_write() {
                    conn.write_tls(stream)?;
                }
            }
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn relay_reality_udp(
    mut tls: wrongsv_reality::RealityTlsStream,
    request: &RequestHeader,
    remaining: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
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

fn relay_raw(
    mut client: TcpStream,
    mut target: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut c2 = client.try_clone()?;
    let mut t2 = target.try_clone()?;

    let t1 = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match c2.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = t2.write_all(&buf[..n]) {
                        debug!("write error client->target: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    debug!("read error client: {}", e);
                    break;
                }
            }
        }
        let _ = t2.shutdown(Shutdown::Write);
    });

    let t2 = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match target.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = client.write_all(&buf[..n]) {
                        debug!("write error target->client: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    debug!("read error target: {}", e);
                    break;
                }
            }
        }
        let _ = client.shutdown(Shutdown::Write);
    });

    t1.join().ok();
    t2.join().ok();
    Ok(())
}

fn relay_udp(
    client: TcpStream,
    request: &RequestHeader,
    remaining: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let target_addr = format!("{}:{}", request.address, request.port);
    debug!(
        "UDP relay to {target_addr}, {} remaining bytes",
        remaining.len()
    );

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0")?);
    socket.connect(&target_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    let c_read = client.try_clone()?;
    c_read.set_read_timeout(Some(Duration::from_secs(30)))?;
    let c_write = client;

    let done = Arc::new(AtomicBool::new(false));
    let done1 = Arc::clone(&done);
    let done2 = Arc::clone(&done);

    let udp_send = Arc::clone(&socket);
    let t1 = thread::spawn(move || {
        let chained = std::io::Cursor::new(remaining).chain(c_read);
        let mut reader = LengthPacketReader::new(chained);
        loop {
            if done1.load(Ordering::SeqCst) {
                break;
            }
            match reader.read_packet() {
                Ok(pkt) => {
                    if udp_send.send(&pkt).is_err() {
                        break;
                    }
                }
                Err(PacketReadError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(_) => break,
            }
        }
        done1.store(true, Ordering::SeqCst);
    });

    let udp_recv = Arc::clone(&socket);
    let t2 = thread::spawn(move || {
        let mut writer = LengthPacketWriter::new(c_write);
        let mut buf = [0u8; 65535];
        loop {
            if done2.load(Ordering::SeqCst) {
                break;
            }
            match udp_recv.recv(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if writer.write_packet(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(ref e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
        done2.store(true, Ordering::SeqCst);
    });

    t1.join().ok();
    t2.join().ok();
    Ok(())
}

fn relay_vision(
    client: TcpStream,
    target: TcpStream,
    user_sent_id: &[u8],
    testseed: &[u32],
) -> Result<(), Box<dyn std::error::Error>> {
    let c_read = client.try_clone()?;
    let c_write = client;
    let t_read = target.try_clone()?;
    let t_write = target;

    // Client → Target (uplink): read from client with Vision, write to target raw
    let up_state = TrafficState::new(user_sent_id);
    let up_seed = if testseed.len() >= 4 {
        testseed.to_vec()
    } else {
        vec![900, 500, 900, 256]
    };

    let t1 = thread::spawn(move || {
        let mut reader = VisionReader::new(c_read, up_state, true);
        let mut buf = [0u8; 8192];
        let mut tgt = t_write;
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = tgt.write_all(&buf[..n]) {
                        debug!("write uplink: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    debug!("read uplink: {}", e);
                    break;
                }
            }
        }
        let _ = tgt.shutdown(Shutdown::Write);
    });

    // Target → Client (downlink): read from target raw, write to client with Vision
    let down_state = TrafficState::new(user_sent_id);
    let t2 = thread::spawn(move || {
        let mut writer = VisionWriter::new(c_write, down_state, false, up_seed);
        let mut buf = [0u8; 8192];
        let mut tgt = t_read;
        loop {
            match tgt.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = writer.write(&buf[..n]) {
                        debug!("write downlink: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    debug!("read downlink: {}", e);
                    break;
                }
            }
        }
        writer.flush().ok();
        let _ = tgt.shutdown(Shutdown::Write);
    });

    t1.join().ok();
    t2.join().ok();
    Ok(())
}
