use std::collections::HashMap;
use std::io::{ErrorKind, Read, Result as IoResult, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, trace};
use wrongsv_net_types::{Address, Port};
use wrongsv_protocol::{RequestCommand, RequestHeader};
use wrongsv_vless::MemoryValidator;
use wrongsv_vless::vision::{TrafficState, VisionWriter};
use wrongsv_vless_encoding::LengthPacketWriter;

use crate::config::WebSocketServerConfig;
use wrongsv_websocket::{self as ws, WebSocketStream};

use super::*;

#[derive(Clone)]
pub(crate) struct WebSocketConfig {
    pub path: String,
    pub host: Option<String>,
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
    #[allow(dead_code)]
    pub tls_dest: Option<String>,
}

fn is_idle_read(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn drain_ws_udp_packets(
    input: &mut Vec<u8>,
    socket: &UdpSocket,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut pos = 0;
    let mut sent = false;

    while input.len().saturating_sub(pos) >= 2 {
        let len = u16::from_be_bytes([input[pos], input[pos + 1]]) as usize;
        if input.len() - pos < len + 2 {
            break;
        }
        let payload_start = pos + 2;
        let payload_end = payload_start + len;
        socket.send(&input[payload_start..payload_end])?;
        sent = true;
        pos = payload_end;
    }

    if pos > 0 {
        input.drain(..pos);
    }

    Ok(sent)
}

fn flush_ws_udp_responses<S: Read + Write>(
    ws: &mut WebSocketStream<S>,
    socket: &UdpSocket,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    socket.set_read_timeout(Some(timeout))?;
    let mut buf = [0u8; 65535];

    loop {
        match socket.recv(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let mut packet = Vec::with_capacity(n + 2);
                LengthPacketWriter::new(&mut packet).write_packet(&buf[..n])?;
                ws.write_all(&packet)?;
                ws.flush()?;
            }
            Err(ref e) if is_idle_read(e) => break,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

const MUX_OPTION_DATA: u8 = 0x01;
const MUX_STATUS_NEW: u8 = 0x01;
const MUX_STATUS_KEEP: u8 = 0x02;
const MUX_STATUS_END: u8 = 0x03;
const MUX_STATUS_KEEPALIVE: u8 = 0x04;
const MUX_NETWORK_TCP: u8 = 0x01;
const MUX_NETWORK_UDP: u8 = 0x02;
const MUX_ADDR_IPV4: u8 = 0x01;
const MUX_ADDR_DOMAIN: u8 = 0x02;
const MUX_ADDR_IPV6: u8 = 0x03;
const MUX_MAX_META_LEN: usize = 512;

struct MuxFrame {
    session_id: u16,
    status: u8,
    option: u8,
    network: Option<u8>,
    address: Option<Address>,
    port: Option<Port>,
    data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MuxUdpKey {
    session_id: u16,
    address: Address,
    port: Port,
}

struct MuxUdpSession {
    socket: UdpSocket,
    address: Address,
    port: Port,
}

fn take_pending(pending: &mut Vec<u8>, out: &mut [u8], offset: &mut usize) {
    let n = out.len().saturating_sub(*offset).min(pending.len());
    out[*offset..*offset + n].copy_from_slice(&pending[..n]);
    pending.drain(..n);
    *offset += n;
}

fn read_ws_mux_exact<S: Read + Write>(
    ws: &mut WebSocketStream<S>,
    pending: &mut Vec<u8>,
    out: &mut [u8],
) -> IoResult<()> {
    let mut offset = 0;

    if !pending.is_empty() {
        take_pending(pending, out, &mut offset);
    }

    let mut buf = [0u8; 32768];
    while offset < out.len() {
        let n = ws.read(&mut buf)?;
        if n == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "Mux stream closed",
            ));
        }
        pending.extend_from_slice(&buf[..n]);
        take_pending(pending, out, &mut offset);
    }

    Ok(())
}

fn parse_mux_address(meta: &[u8], pos: &mut usize) -> Result<(Address, Port), String> {
    if meta.len().saturating_sub(*pos) < 3 {
        return Err("short Mux address".into());
    }
    let port = Port(u16::from_be_bytes([meta[*pos], meta[*pos + 1]]));
    *pos += 2;
    let atyp = meta[*pos];
    *pos += 1;

    let address = match atyp {
        MUX_ADDR_IPV4 => {
            if meta.len().saturating_sub(*pos) < 4 {
                return Err("short Mux IPv4 address".into());
            }
            let mut raw = [0u8; 4];
            raw.copy_from_slice(&meta[*pos..*pos + 4]);
            *pos += 4;
            Address::IPv4(raw)
        }
        MUX_ADDR_DOMAIN => {
            let len = *meta
                .get(*pos)
                .ok_or_else(|| "short Mux domain length".to_string())?
                as usize;
            *pos += 1;
            if meta.len().saturating_sub(*pos) < len {
                return Err("short Mux domain address".into());
            }
            let domain = std::str::from_utf8(&meta[*pos..*pos + len])
                .map_err(|e| format!("invalid Mux domain: {e}"))?
                .to_string();
            *pos += len;
            Address::Domain(domain)
        }
        MUX_ADDR_IPV6 => {
            if meta.len().saturating_sub(*pos) < 16 {
                return Err("short Mux IPv6 address".into());
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&meta[*pos..*pos + 16]);
            *pos += 16;
            Address::IPv6(raw)
        }
        _ => return Err(format!("unsupported Mux address type: {atyp:#04x}")),
    };

    Ok((address, port))
}

fn parse_mux_metadata(meta: &[u8]) -> Result<MuxFrame, String> {
    if meta.len() < 4 {
        return Err("short Mux metadata".into());
    }

    let session_id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = meta[2];
    let option = meta[3];
    let mut network = None;
    let mut address = None;
    let mut port = None;

    if status == MUX_STATUS_NEW
        || (status == MUX_STATUS_KEEP && meta.len() > 4 && meta[4] == MUX_NETWORK_UDP)
    {
        if meta.len() < 8 {
            return Err("short Mux target metadata".into());
        }
        let mut pos = 4;
        let frame_network = meta[pos];
        pos += 1;
        let (frame_address, frame_port) = parse_mux_address(meta, &mut pos)?;
        network = Some(frame_network);
        address = Some(frame_address);
        port = Some(frame_port);
    }

    Ok(MuxFrame {
        session_id,
        status,
        option,
        network,
        address,
        port,
        data: Vec::new(),
    })
}

fn read_ws_mux_frame<S: Read + Write>(
    ws: &mut WebSocketStream<S>,
    pending: &mut Vec<u8>,
) -> Result<Option<MuxFrame>, Box<dyn std::error::Error>> {
    let mut len_buf = [0u8; 2];
    match read_ws_mux_exact(ws, pending, &mut len_buf) {
        Ok(()) => {}
        Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let meta_len = u16::from_be_bytes(len_buf) as usize;
    if meta_len > MUX_MAX_META_LEN {
        return Err(format!("Mux metadata too large: {meta_len}").into());
    }

    let mut meta = vec![0u8; meta_len];
    read_ws_mux_exact(ws, pending, &mut meta)?;
    let mut frame = parse_mux_metadata(&meta)?;

    if frame.option & MUX_OPTION_DATA != 0 {
        let mut data_len = [0u8; 2];
        read_ws_mux_exact(ws, pending, &mut data_len)?;
        let data_len = u16::from_be_bytes(data_len) as usize;
        frame.data = vec![0u8; data_len];
        read_ws_mux_exact(ws, pending, &mut frame.data)?;
    }

    Ok(Some(frame))
}

fn write_mux_address(out: &mut Vec<u8>, address: &Address, port: Port) -> Result<(), String> {
    out.extend_from_slice(&port.0.to_be_bytes());
    match address {
        Address::IPv4(raw) => {
            out.push(MUX_ADDR_IPV4);
            out.extend_from_slice(raw);
        }
        Address::Domain(domain) => {
            if domain.len() > u8::MAX as usize {
                return Err("Mux domain address too long".into());
            }
            out.push(MUX_ADDR_DOMAIN);
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
        Address::IPv6(raw) => {
            out.push(MUX_ADDR_IPV6);
            out.extend_from_slice(raw);
        }
    }
    Ok(())
}

fn write_ws_mux_udp_response<S: Read + Write>(
    ws: &mut WebSocketStream<S>,
    session_id: u16,
    address: &Address,
    port: Port,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut meta = Vec::new();
    meta.extend_from_slice(&session_id.to_be_bytes());
    meta.push(MUX_STATUS_KEEP);
    meta.push(MUX_OPTION_DATA);
    meta.push(MUX_NETWORK_UDP);
    write_mux_address(&mut meta, address, port)?;

    let mut frame = Vec::with_capacity(2 + meta.len() + 2 + payload.len());
    frame.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    frame.extend_from_slice(&meta);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    ws.write_all(&frame)?;
    ws.flush()?;
    Ok(())
}

fn flush_ws_mux_udp_responses<S: Read + Write>(
    ws: &mut WebSocketStream<S>,
    session_id: u16,
    session: &MuxUdpSession,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    session.socket.set_read_timeout(Some(timeout))?;
    let mut buf = [0u8; 65535];
    loop {
        match session.socket.recv(&mut buf) {
            Ok(0) => break,
            Ok(n) => write_ws_mux_udp_response(
                ws,
                session_id,
                &session.address,
                session.port,
                &buf[..n],
            )?,
            Err(ref e) if is_idle_read(e) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn mux_udp_socket(address: &Address, port: Port) -> IoResult<UdpSocket> {
    let bind_addr = match address {
        Address::IPv6(_) => "[::]:0",
        _ => "0.0.0.0:0",
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(format!("{address}:{port}"))?;
    Ok(socket)
}

pub(crate) fn parse_ws_config(wc: &WebSocketServerConfig) -> Result<WebSocketConfig, String> {
    let path = if wc.path.starts_with('/') {
        wc.path.clone()
    } else {
        format!("/{}", wc.path)
    };
    let (tls_config, tls_dest) = match &wc.tls {
        Some(tls) => {
            let (cert_pem, key_pem) = match (&tls.certificate, &tls.key) {
                (Some(c), Some(k)) => (c.clone(), k.clone()),
                _ => {
                    let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                        .map_err(|e| format!("ws tls cert: {e}"))?;
                    (cert, key)
                }
            };
            let server_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
                .map_err(|e| format!("ws tls config: {e}"))?;
            (Some(Arc::new(server_config)), tls.dest.clone())
        }
        None => (None, None),
    };
    Ok(WebSocketConfig {
        path,
        host: wc.host.clone(),
        tls_config,
        tls_dest,
    })
}
pub(crate) fn handle_ws_connection(
    stream: TcpStream,
    validator: Arc<MemoryValidator>,
    ws_config: &WebSocketConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} WS connection");

    match &ws_config.tls_config {
        Some(tls_config) => {
            // ── TLS + WS ──
            let mut conn = rustls::ServerConnection::new(Arc::clone(tls_config))
                .map_err(|e| format!("ws+tls create: {e}"))?;
            let mut sock = stream;
            loop {
                match conn.complete_io(&mut sock) {
                    Ok((_, _)) if !conn.is_handshaking() => break,
                    Ok(_) => {}
                    Err(e) => return Err(format!("ws+tls handshake: {e}").into()),
                }
            }
            info!("{peer} TLS+WS: TLS handshake done, WS upgrading...");

            let tls_stream = wrongsv_anytls::AnyTlsStream::from_parts(conn, sock);

            // Read HTTP upgrade through TLS
            let (mut tls_conn, mut tls_sock) = tls_stream.into_parts();
            let mut header_buf = vec![0u8; 16384];
            let n = read_tls_plaintext(&mut tls_conn, &mut tls_sock, &mut header_buf)?;
            if n == 0 {
                return Err("TLS+WS: connection closed before upgrade".into());
            }
            header_buf.truncate(n);

            let (ws_req, remaining) =
                ws::parse_upgrade(&header_buf, &ws_config.path, ws_config.host.as_deref())?;
            let accept_key = ws::compute_accept_key(&ws_req.websocket_key);
            let response = ws::build_upgrade_response(&accept_key);

            // Write 101 response through TLS
            tls_conn.writer().write_all(&response)?;
            while tls_conn.wants_write() {
                tls_conn.write_tls(&mut tls_sock)?;
            }

            let tls_stream = wrongsv_anytls::AnyTlsStream::from_parts(tls_conn, tls_sock);
            let mut ws_stream = WebSocketStream::new(tls_stream, remaining);

            info!("{peer} TLS+WS upgraded on path '{}'", ws_config.path);
            handle_vless_over_ws(&mut ws_stream, validator, peer, ws_config, true)?;
            Ok(())
        }
        None => {
            // ── Raw WS (no TLS) ──
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            let mut header_buf = Vec::new();
            let _n = stream_read_upgrade(&stream, &mut header_buf)?;

            let (ws_req, remaining) =
                ws::parse_upgrade(&header_buf, &ws_config.path, ws_config.host.as_deref())?;
            let accept_key = ws::compute_accept_key(&ws_req.websocket_key);
            let response = ws::build_upgrade_response(&accept_key);

            // Write 101 response
            let mut raw_stream = stream;
            raw_stream.write_all(&response)?;
            raw_stream.set_read_timeout(None)?;

            let mut ws_stream = WebSocketStream::new(raw_stream, remaining);

            info!("{peer} WS upgraded on path '{}'", ws_config.path);
            handle_vless_over_ws(&mut ws_stream, validator, peer, ws_config, false)?;
            Ok(())
        }
    }
}

pub(crate) fn handle_vless_over_ws<S: Read + Write>(
    ws_stream: &mut WebSocketStream<S>,
    validator: Arc<MemoryValidator>,
    peer: SocketAddr,
    _ws_config: &WebSocketConfig,
    _tls: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read VLESS header from WebSocket frames
    let mut first = vec![0u8; 8192];
    let n = ws_stream.read(&mut first)?;
    if n == 0 {
        return Err("WebSocket closed before VLESS header".into());
    }
    first.truncate(n);
    trace!("{peer} WS read {n} bytes VLESS header");

    let VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    } = decode_vless_request(first, &validator, peer)?;
    let request = &decoded.header;
    let account = &request.user.account;

    log_vless_request(peer, request);
    validate_vless_command(request, use_vision)?;

    let resp_buf = response_header_buf(request)?;
    ws_stream.write_all(&resp_buf)?;
    ws_stream.flush()?;

    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_ws_udp(ws_stream, request, remaining_body)?;
        debug!("{peer} WS UDP relay finished");
        return Ok(());
    }

    if request.command == RequestCommand::Mux {
        relay_ws_mux_udp(ws_stream, remaining_body, account.udp)?;
        debug!("{peer} WS Mux UDP relay finished");
        return Ok(());
    }

    // Connect to target
    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("{peer} WS connecting to target {target_addr}");
    let target = TcpStream::connect(&target_addr)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(60)))?;

    if use_vision {
        relay_ws_vision(
            ws_stream,
            target,
            remaining_body,
            &decoded.user_sent_id,
            &account.testseed,
        )?;
    } else {
        relay_ws_raw(ws_stream, target, remaining_body)?;
    }
    debug!("{peer} WS relay finished");
    Ok(())
}

pub(crate) fn relay_ws_udp<S: Read + Write>(
    ws: &mut WebSocketStream<S>,
    request: &RequestHeader,
    remaining: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    if is_packetaddr_request(request) {
        debug!(
            "WS packetaddr UDP relay, {} remaining bytes",
            remaining.len()
        );
        return relay_packetaddr_udp_stream(ws, remaining);
    }

    let target_addr = format!("{}:{}", request.address, request.port);
    debug!(
        "WS UDP relay to {target_addr}, {} remaining bytes",
        remaining.len()
    );

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(&target_addr)?;

    let mut input = remaining;
    let mut ws_buf = [0u8; 32768];

    loop {
        if drain_ws_udp_packets(&mut input, &socket)? {
            flush_ws_udp_responses(ws, &socket, Duration::from_millis(500))?;
        }

        match ws.read(&mut ws_buf) {
            Ok(0) => break,
            Ok(n) => {
                input.extend_from_slice(&ws_buf[..n]);
            }
            Err(ref e) if is_idle_read(e) => {
                flush_ws_udp_responses(ws, &socket, Duration::from_millis(10))?;
            }
            Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

pub(crate) fn relay_ws_mux_udp<S: Read + Write>(
    ws: &mut WebSocketStream<S>,
    remaining: Vec<u8>,
    udp_enabled: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut pending = remaining;
    let mut sessions: HashMap<MuxUdpKey, MuxUdpSession> = HashMap::new();

    while let Some(frame) = read_ws_mux_frame(ws, &mut pending)? {
        match frame.status {
            MUX_STATUS_NEW | MUX_STATUS_KEEP => {
                let network = frame.network.unwrap_or(MUX_NETWORK_TCP);
                if network != MUX_NETWORK_UDP {
                    return Err("Mux.Cool TCP relay is not implemented".into());
                }
                if !udp_enabled {
                    return Err("UDP not enabled for this user".into());
                }

                let address = frame.address.ok_or("Mux UDP frame missing address")?;
                let port = frame.port.ok_or("Mux UDP frame missing port")?;
                let key = MuxUdpKey {
                    session_id: frame.session_id,
                    address: address.clone(),
                    port,
                };
                if !sessions.contains_key(&key) {
                    let socket = mux_udp_socket(&address, port)?;
                    sessions.insert(
                        key.clone(),
                        MuxUdpSession {
                            socket,
                            address,
                            port,
                        },
                    );
                }

                if !frame.data.is_empty() {
                    let session = sessions.get(&key).expect("session inserted");
                    session.socket.send(&frame.data)?;
                    flush_ws_mux_udp_responses(
                        ws,
                        frame.session_id,
                        session,
                        Duration::from_millis(500),
                    )?;
                }
            }
            MUX_STATUS_END => {
                sessions.retain(|key, _| key.session_id != frame.session_id);
            }
            MUX_STATUS_KEEPALIVE => {}
            status => return Err(format!("unsupported Mux status: {status:#04x}").into()),
        }

        for (key, session) in &sessions {
            flush_ws_mux_udp_responses(ws, key.session_id, session, Duration::from_millis(10))?;
        }
    }

    Ok(())
}

pub(crate) fn relay_ws_raw<S: Read + Write>(
    ws: &mut WebSocketStream<S>,
    mut target: TcpStream,
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 32768];
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_millis(10)))?;

    if !initial_data.is_empty() {
        target.write_all(&initial_data)?;
        target.set_read_timeout(Some(Duration::from_millis(10)))?;
    }

    loop {
        // ── Target → Client (downlink) ──
        match target.read(&mut buf) {
            Ok(0) => {
                let _ = ws.write_close(1000);
                break;
            }
            Ok(n) => {
                ws.write_all(&buf[..n])?;
                ws.flush()?;
                target.set_read_timeout(Some(Duration::from_millis(10)))?;
                continue;
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Keep 10ms — 50ms backoff kills upload throughput.
                target.set_read_timeout(Some(Duration::from_millis(10)))?;
            }
            Err(e) => return Err(e.into()),
        }

        // ── Client → Target (uplink) ──
        match ws.read(&mut buf) {
            Ok(0) => {
                let _ = target.shutdown(Shutdown::Write);
                break;
            }
            Ok(n) => {
                target.write_all(&buf[..n])?;
                target.set_read_timeout(Some(Duration::from_millis(10)))?;
            }
            Err(ref e) if is_idle_read(e) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let _ = target.shutdown(Shutdown::Write);
    Ok(())
}

/// Vision relay for WebSocket.
pub(crate) fn relay_ws_vision<S: Read + Write>(
    ws: &mut WebSocketStream<S>,
    mut target: TcpStream,
    initial_data: Vec<u8>,
    user_sent_id: &[u8],
    testseed: &[u32],
) -> Result<(), Box<dyn std::error::Error>> {
    let up_seed = if testseed.len() >= 4 {
        testseed.to_vec()
    } else {
        vec![900, 500, 900, 256]
    };
    let mut up_state = TrafficState::new(user_sent_id);
    let mut down_state = TrafficState::new(user_sent_id);
    let mut down_user_uuid: Option<[u8; 16]> = Some(down_state.user_uuid);

    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_millis(10)))?;
    let mut buf = [0u8; 32768];

    if !initial_data.is_empty() {
        let unpadded = wrongsv_vless::vision::xtls_unpadding(&initial_data, &mut up_state, true);
        if !unpadded.is_empty() {
            target.write_all(&unpadded)?;
            target.set_read_timeout(Some(Duration::from_millis(10)))?;
        }
    }

    loop {
        // Downlink: target → Vision encode → WS frame
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
                        ws.write_all(&encoded)?;
                        ws.flush()?;
                    }
                    target.set_read_timeout(Some(Duration::from_millis(10)))?;
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    target.set_read_timeout(Some(Duration::from_millis(10)))?;
                    break false;
                }
                Err(e) => return Err(e.into()),
            }
        };

        // Uplink: WS frame → Vision decode → target
        let uplink_done = loop {
            match ws.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => {
                    let unpadded =
                        wrongsv_vless::vision::xtls_unpadding(&buf[..n], &mut up_state, true);
                    if !unpadded.is_empty() {
                        target.write_all(&unpadded)?;
                        target.set_read_timeout(Some(Duration::from_millis(10)))?;
                    }
                }
                Err(ref e) if is_idle_read(e) => break false,
                Err(e) => return Err(e.into()),
            }
        };

        if uplink_done {
            let _ = target.shutdown(Shutdown::Write);
        }
        if downlink_done {
            let _ = ws.write_close(1000);
            break;
        }
        if uplink_done && downlink_done {
            let _ = ws.write_close(1000);
            break;
        }
    }
    Ok(())
}
