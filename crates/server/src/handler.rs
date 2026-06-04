use std::io::{Read, Result as IoResult, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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

use crate::config::{AnyTlsServerConfig, Config, RealityServerConfig, TlsServerConfig};

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

fn parse_anytls_config(ac: &AnyTlsServerConfig) -> Result<wrongsv_anytls::AnyTlsConfig, String> {
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

/// Plain TLS configuration — standard TLS 1.3 + VLESS, no password or REALITY.
#[derive(Clone)]
pub(crate) struct TlsConfig {
    pub tls_config: Arc<rustls::ServerConfig>,
    #[allow(dead_code)]
    pub dest: Option<String>,
}

fn parse_tls_config(tc: &TlsServerConfig) -> Result<TlsConfig, String> {
    let (cert_pem, key_pem) = match (&tc.certificate, &tc.key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => {
            let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                .map_err(|e| format!("tls cert: {e}"))?;
            (cert, key)
        }
    };
    let server_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
        .map_err(|e| format!("tls config: {e}"))?;
    Ok(TlsConfig {
        tls_config: Arc::new(server_config),
        dest: tc.dest.clone(),
    })
}

pub struct InboundServer {
    config: Config,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    reality_config: Option<wrongsv_reality::RealityConfig>,
    anytls_config: Option<wrongsv_anytls::AnyTlsConfig>,
    tls_config: Option<TlsConfig>,
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
        let anytls_config = match &config.anytls {
            Some(ac) => Some(parse_anytls_config(ac)?),
            None => None,
        };
        let tls_config = match &config.tls {
            Some(tc) => Some(parse_tls_config(tc)?),
            None => None,
        };
        if let Some(ref rc) = reality_config {
            let rpk_hex: String = rc
                .cert_material
                .raw_pubkey
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            info!("REALITY raw_pubkey (for client cert verification): {rpk_hex}");
        }
        if anytls_config.is_some() {
            info!("AnyTLS enabled");
        }
        if tls_config.is_some() {
            info!("TLS enabled");
        }
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
            anytls_config,
            tls_config,
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
        }) && !matches!(e, ctrlc::Error::MultipleHandlers)
        {
            return Err(format!("failed to set Ctrl-C handler: {e}").into());
        }

        let validator = Arc::clone(&self.validator);
        let kyber_sk = self.kyber_sk;
        let reality_config = self.reality_config.clone();
        let anytls_config = self.anytls_config.clone();
        let tls_config = self.tls_config.clone();

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
                    let ac = anytls_config.clone();
                    let tc = tls_config.clone();
                    thread::spawn(move || {
                        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                            if let Some(ref rc) = rc {
                                handle_reality_connection(stream, v, kyber_sk, rc)
                            } else if let Some(ref ac) = ac {
                                handle_anytls_connection(stream, v, kyber_sk, ac)
                            } else if let Some(ref tc) = tc {
                                handle_tls_connection(stream, v, kyber_sk, tc)
                            } else {
                                handle_connection(stream, v, kyber_sk)
                            }
                        }));
                        match result {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => warn!("connection error: {}", e),
                            Err(panic) => {
                                let msg = panic
                                    .downcast_ref::<&str>()
                                    .copied()
                                    .or_else(|| panic.downcast_ref::<String>().map(|s| s.as_str()))
                                    .unwrap_or("unknown panic");
                                error!("connection thread panicked: {msg}");
                            }
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

/// Complete a standard TLS 1.3 handshake and return an `AnyTlsStream` for VLESS.
///
/// Unlike AnyTLS, there is no password auth — the TLS layer only provides
/// encryption and DPI resistance. VLESS UUID authentication is still enforced
/// when the subsequent VLESS header is read.
fn accept_tls(
    stream: TcpStream,
    config: &TlsConfig,
) -> Result<wrongsv_anytls::AnyTlsStream, Box<dyn std::error::Error>> {
    let mut conn = rustls::ServerConnection::new(Arc::clone(&config.tls_config))
        .map_err(|e| format!("tls create: {e}"))?;
    let mut stream = stream;
    loop {
        match conn.complete_io(&mut stream) {
            Ok((_, _)) if !conn.is_handshaking() => break,
            Ok(_) => {}
            Err(e) => return Err(format!("tls handshake: {e}").into()),
        }
    }
    Ok(wrongsv_anytls::AnyTlsStream::from_parts(conn, stream))
}

fn handle_tls_connection(
    stream: TcpStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    tls_config: &TlsConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} TLS connection");

    let mut tls_stream = match accept_tls(stream, tls_config) {
        Ok(tls) => tls,
        Err(e) => {
            debug!("{peer} TLS handshake failed: {e}");
            return Err(e);
        }
    };
    info!("{peer} TLS handshake complete");

    // Read VLESS header from TLS stream (same as AnyTLS path)
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
    trace!("{peer} TLS read {n} bytes VLESS header");

    if n < 18 {
        debug!("{peer} connection too short ({n} bytes), dropping");
        return Err("connection too short for VLESS header".into());
    }

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

    if !decoded.addons.kyber_ct.is_empty()
        && let Some(sk) = kyber_sk
    {
        match wrongsv_kyber::decapsulate(&sk, &decoded.addons.kyber_ct) {
            Ok(_) => info!("{peer} Kyber session established"),
            Err(e) => warn!("{peer} Kyber decapsulation failed: {e}"),
        }
    }

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
    while read_conn.wants_write() {
        read_conn.write_tls(write_conn)?;
    }

    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_anytls_udp(tls_stream, request, remaining_body)?;
        debug!("{peer} TLS UDP relay finished");
        return Ok(());
    }

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
        )?;
    } else {
        relay_anytls_raw(tls_stream, target, remaining_body)?;
    }
    debug!("{peer} TLS TCP relay finished");
    Ok(())
}

fn handle_anytls_connection(
    stream: TcpStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    anytls_config: &wrongsv_anytls::AnyTlsConfig,
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

    // Protocol detection: read first post-auth byte
    let (mut conn, mut stream_sock) = tls_stream.into_parts();
    let (proto, first_byte) =
        wrongsv_anytls::detect_post_auth_protocol(&mut conn, &mut stream_sock)?;

    if proto == wrongsv_anytls::PostAuthProtocol::SingAnyTls {
        return handle_sing_anytls_session(conn, stream_sock, peer, validator, kyber_sk);
    }

    // VLESS path: reconstruct AnyTlsStream and read the full header.
    // Pre-allocate buffer, put first_byte at position 0, read the rest.
    let mut tls_stream = wrongsv_anytls::AnyTlsStream::from_parts(conn, stream_sock);

    let mut first = vec![0u8; 8192];
    first[0] = first_byte;
    let extra = tls_stream.read(&mut first[1..])?;
    first.truncate(1 + extra);
    let n = first.len();
    trace!("{peer} AnyTLS read {n} bytes VLESS header");

    if n < 18 {
        debug!("{peer} connection too short ({n} bytes), dropping");
        return Err("connection too short for VLESS header".into());
    }

    let (read_conn, write_conn) = tls_stream.get_mut();

    // Decode VLESS header
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

    // Kyber decapsulation
    if !decoded.addons.kyber_ct.is_empty()
        && let Some(sk) = kyber_sk
    {
        match wrongsv_kyber::decapsulate(&sk, &decoded.addons.kyber_ct) {
            Ok(_) => info!("{peer} Kyber session established"),
            Err(e) => warn!("{peer} Kyber decapsulation failed: {e}"),
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
    while read_conn.wants_write() {
        read_conn.write_tls(write_conn)?;
    }

    // UDP relay (AnyTLS)
    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_anytls_udp(tls_stream, request, remaining_body)?;
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
        )?;
    } else {
        relay_anytls_raw(tls_stream, target, remaining_body)?;
    }
    debug!("{peer} TCP relay finished");
    Ok(())
}

// ── sing-anytls session handler ─────────────────────────────────────────────

fn handle_sing_anytls_session(
    mut conn: rustls::ServerConnection,
    mut stream_sock: TcpStream,
    peer: std::net::SocketAddr,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
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
            handle_sing_stream(stream, w, peer, validator.clone(), kyber_sk);
        },
    )?;

    info!("{peer} sing-anytls session ended");
    Ok(())
}

fn handle_sing_stream(
    mut stream: wrongsv_anytls::stream::SingStream,
    writer: wrongsv_anytls::session::SessionWriter,
    peer: std::net::SocketAddr,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
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
        handle_sing_stream_vless(stream, writer, first_data, peer, validator, kyber_sk)
    } else {
        handle_sing_stream_socks(stream, writer, first_data, peer)
    };

    if let Err(e) = result {
        warn!("{peer} sing stream sid={sid}: {e}");
    }
}

fn handle_sing_stream_socks(
    stream: wrongsv_anytls::stream::SingStream,
    writer: wrongsv_anytls::session::SessionWriter,
    first_data: Vec<u8>,
    peer: std::net::SocketAddr,
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

    relay_sing_raw(stream, writer, target, remaining)?;
    Ok(())
}

fn handle_sing_stream_vless(
    stream: wrongsv_anytls::stream::SingStream,
    writer: wrongsv_anytls::session::SessionWriter,
    first_data: Vec<u8>,
    peer: std::net::SocketAddr,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sid = stream.id;

    // Decode VLESS header from first PSH data
    let (decoded, remaining_body) = {
        let v = validator.clone();
        let mut cursor = std::io::Cursor::new(first_data);
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

    let use_vision = decoded.addons.flow == XRV && account.flow == XRV;

    if !decoded.addons.kyber_ct.is_empty()
        && let Some(sk) = kyber_sk
    {
        match wrongsv_kyber::decapsulate(&sk, &decoded.addons.kyber_ct) {
            Ok(_) => info!("{peer} sing-anytls Kyber session established"),
            Err(e) => warn!("{peer} sing-anytls Kyber decapsulation failed: {e}"),
        }
    }

    if request.command == RequestCommand::Udp && use_vision {
        writer.send_synack_error(sid, "Vision does not support UDP")?;
        return Ok(());
    }

    // Send VLESS response header via PSH
    let response_addons = Addons {
        flow: String::new(),
        ..Default::default()
    };
    let mut resp_buf = bytes::BytesMut::new();
    encoding::encode_response_header(&mut resp_buf, request, &response_addons)?;

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
        )?;
    } else {
        relay_sing_raw(stream, writer, target, remaining_body)?;
    }

    debug!("{peer} sing-anytls stream sid={sid} relay finished");
    Ok(())
}

fn relay_sing_raw(
    mut stream: wrongsv_anytls::stream::SingStream,
    writer: wrongsv_anytls::session::SessionWriter,
    mut target: TcpStream,
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sid = stream.id;
    let mut buf = [0u8; 32768];
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(2)))?;

    if !initial_data.is_empty() {
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

fn relay_sing_vision(
    mut stream: wrongsv_anytls::stream::SingStream,
    writer: wrongsv_anytls::session::SessionWriter,
    mut target: TcpStream,
    user_sent_id: &[u8],
    testseed: &[u32],
    initial_data: Vec<u8>,
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

fn relay_sing_udp(
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
    let addr = target_addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("DNS resolution failed for {target_addr}"))?;
    let target = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    target.set_nodelay(true)?;
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

fn relay_reality(
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
struct TlsReadHandle<R> {
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
struct TlsWriteHandle<W> {
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
fn relay_reality_vision(
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

fn relay_anytls_raw(
    mut tls: wrongsv_anytls::AnyTlsStream,
    mut target: TcpStream,
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 32768];
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(2)))?;

    if !initial_data.is_empty() {
        target.write_all(&initial_data)?;
    }

    let (conn, stream) = tls.get_mut();
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    loop {
        // Drain target first — it's the fast, low-latency side.
        // When downloading a large response we want to pull as much
        // data from the target as we can before checking for new
        // client requests.
        match target.read(&mut buf) {
            Ok(0) => {
                conn.send_close_notify();
                while conn.wants_write() {
                    conn.write_tls(stream)?;
                }
                break;
            }
            Ok(n) => {
                conn.writer().write_all(&buf[..n])?;
                while conn.wants_write() {
                    conn.write_tls(stream)?;
                }
                target.set_read_timeout(Some(Duration::from_millis(10)))?;
                continue;
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                target.set_read_timeout(Some(Duration::from_secs(2)))?;
            }
            Err(e) => return Err(e.into()),
        }

        // Client side
        match conn.read_tls(stream) {
            Ok(0) => {
                let _ = target.shutdown(Shutdown::Write);
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
                            target.set_read_timeout(Some(Duration::from_millis(10)))?;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
    }
    let _ = target.shutdown(Shutdown::Write);
    Ok(())
}

fn relay_anytls_vision(
    mut tls: wrongsv_anytls::AnyTlsStream,
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
    let mut up_state = TrafficState::new(user_sent_id);
    let mut down_state = TrafficState::new(user_sent_id);
    let mut down_user_uuid: Option<[u8; 16]> = Some(down_state.user_uuid);

    if !initial_data.is_empty() {
        use wrongsv_vless::vision::xtls_unpadding;
        let unpadded = xtls_unpadding(&initial_data, &mut up_state, true);
        if !unpadded.is_empty() {
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

fn relay_anytls_udp(
    mut tls: wrongsv_anytls::AnyTlsStream,
    request: &RequestHeader,
    remaining: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
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
            socket.send(&pkt)?;
            did_work = true;
        }

        match socket.recv(&mut udp_buf) {
            Ok(n) if n > 0 => {
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

fn relay_raw(
    mut client: TcpStream,
    mut target: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut c2 = client.try_clone()?;
    let mut t2 = target.try_clone()?;

    let t1 = thread::spawn(move || {
        let mut buf = [0u8; 32768];
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
        let mut buf = [0u8; 32768];
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
        let mut buf = [0u8; 32768];
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
        let mut buf = [0u8; 32768];
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
