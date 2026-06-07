use std::io::{Read, Result as IoResult, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, trace};
use wrongsv_protocol::RequestCommand;
use wrongsv_vless::vision::{TrafficState, VisionWriter};
use wrongsv_vless::MemoryValidator;

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
    kyber_sk: Option<[u8; 64]>,
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
            handle_vless_over_ws(&mut ws_stream, validator, kyber_sk, peer, ws_config, true)?;
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
            handle_vless_over_ws(&mut ws_stream, validator, kyber_sk, peer, ws_config, false)?;
            Ok(())
        }
    }
}

pub(crate) fn handle_vless_over_ws<S: Read + Write>(
    ws_stream: &mut WebSocketStream<S>,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
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
        remaining_body: _,
        use_vision,
    } = decode_vless_request(first, &validator, peer)?;
    let request = &decoded.header;
    let account = &request.user.account;

    log_vless_request(peer, request);
    handle_kyber_addons(peer, &decoded, kyber_sk);
    validate_vless_command(request, use_vision)?;

    let resp_buf = response_header_buf(request)?;
    ws_stream.write_all(&resp_buf)?;
    ws_stream.flush()?;

    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        // UDP over WebSocket not yet implemented — send close and return
        let _ = ws_stream.write_close(1000);
        debug!("{peer} WS UDP not implemented, closing");
        return Ok(());
    }

    // Connect to target
    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("{peer} WS connecting to target {target_addr}");
    let target = TcpStream::connect(&target_addr)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(60)))?;

    if use_vision {
        relay_ws_vision(ws_stream, target, &decoded.user_sent_id, &account.testseed)?;
    } else {
        relay_ws_raw(ws_stream, target)?;
    }
    debug!("{peer} WS relay finished");
    Ok(())
}

pub(crate) fn relay_ws_raw<S: Read + Write>(
    ws: &mut WebSocketStream<S>,
    mut target: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 32768];
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(2)))?;

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
                target.set_read_timeout(Some(Duration::from_secs(2)))?;
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
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
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
    target.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buf = [0u8; 32768];

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
                    target.set_read_timeout(Some(Duration::from_secs(2)))?;
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
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break false,
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
