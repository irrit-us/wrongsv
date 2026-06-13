use std::io::{self, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use tokio::sync::mpsc as tokio_mpsc;

use http::StatusCode;
use tracing::{debug, trace};
use wrongsv_protocol::{RequestCommand, RequestHeader};
use wrongsv_vless::MemoryValidator;

use crate::config::XhttpServerConfig;

use super::*;

// ── Config ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct XhttpConfig {
    pub path: String,
    pub host: Option<String>,
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
    #[allow(dead_code)]
    pub tls_dest: Option<String>,
}

pub(crate) fn parse_xhttp_config(xc: &XhttpServerConfig) -> Result<XhttpConfig, String> {
    let (tls_config, tls_dest) = match &xc.tls {
        Some(tls) => {
            let (cert_pem, key_pem) = match (&tls.certificate, &tls.key) {
                (Some(c), Some(k)) => (c.clone(), k.clone()),
                _ => {
                    let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                        .map_err(|e| format!("xhttp tls cert: {e}"))?;
                    (cert, key)
                }
            };
            let server_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
                .map_err(|e| format!("xhttp tls config: {e}"))?;
            (Some(Arc::new(server_config)), tls.dest.clone())
        }
        None => (None, None),
    };
    let path = xc.path.clone().unwrap_or_else(|| "/xhttp".into());
    Ok(XhttpConfig {
        path,
        host: xc.host.clone(),
        tls_config,
        tls_dest,
    })
}

// ── XHTTP stream bridge ───────────────────────────────────────────────

pub(crate) struct XhttpStream {
    incoming_rx: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    outgoing_tx: tokio_mpsc::Sender<Vec<u8>>,
    eof: bool,
}

pub(crate) struct XhttpReader {
    incoming_rx: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    eof: bool,
}

#[derive(Clone)]
pub(crate) struct XhttpWriter {
    outgoing_tx: tokio_mpsc::Sender<Vec<u8>>,
}

impl XhttpStream {
    fn from_channels(
        incoming_rx: Receiver<Vec<u8>>,
        outgoing_tx: tokio_mpsc::Sender<Vec<u8>>,
    ) -> Self {
        XhttpStream {
            incoming_rx,
            pending: Vec::new(),
            outgoing_tx,
            eof: false,
        }
    }

    fn split(self) -> (XhttpReader, XhttpWriter) {
        (
            XhttpReader {
                incoming_rx: self.incoming_rx,
                pending: self.pending,
                eof: self.eof,
            },
            XhttpWriter {
                outgoing_tx: self.outgoing_tx,
            },
        )
    }
}

impl Read for XhttpReader {
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

impl Write for XhttpWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outgoing_tx
            .blocking_send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for XhttpStream {
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

impl Write for XhttpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.eof {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP stream closed",
            ));
        }
        self.outgoing_tx
            .blocking_send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ── HTTP/2 driver (async, runs in tokio) ──────────────────────────────

async fn drive_xhttp_connection(
    tcp: TcpStream,
    peer: std::net::SocketAddr,
    path: &str,
    host: Option<&str>,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tcp.set_nonblocking(true)?;
    let tcp = tokio::net::TcpStream::from_std(tcp)?;
    tcp.set_nodelay(true)?;

    let mut conn = h2::server::Builder::new()
        .initial_window_size(1_048_576) // 1 MiB — avoids flow-control stalls
        .handshake(tcp)
        .await
        .map_err(|e| format!("h2 handshake: {e}"))?;
    trace!("{peer} HTTP/2 handshake done");

    let (request_tx, mut request_rx) = tokio_mpsc::channel(32);
    let conn_handle = tokio::spawn(async move {
        loop {
            match conn.accept().await {
                Some(Ok(stream)) => {
                    if request_tx.send(Ok(stream)).await.is_err() {
                        break;
                    }
                }
                Some(Err(e)) => {
                    let _ = request_tx.send(Err(format!("h2 accept: {e}"))).await;
                    break;
                }
                None => break,
            }
        }
    });

    while let Some(item) = request_rx.recv().await {
        let (request, respond) = item.map_err(|e| format!("XHTTP connection error: {e}"))?;
        handle_xhttp_request_stream(
            request,
            respond,
            peer,
            path,
            host,
            Arc::clone(&validator),
            kyber_sk,
        )
        .await?;
    }

    let _ = conn_handle.await;
    Ok(())
}

fn reject_xhttp(mut respond: h2::server::SendResponse<bytes::Bytes>) {
    let resp = http::Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(())
        .unwrap();
    let _ = respond.send_response(resp, true);
}

async fn handle_xhttp_request_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    peer: std::net::SocketAddr,
    path: &str,
    host: Option<&str>,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (parts, body) = request.into_parts();

    if parts.method != http::Method::POST {
        debug!("{peer} XHTTP rejected: method={}", parts.method);
        reject_xhttp(respond);
        return Ok(());
    }

    if !parts.uri.path().starts_with(path) {
        debug!(
            "{peer} XHTTP path mismatch: expected prefix {path}, got {}",
            parts.uri.path()
        );
        reject_xhttp(respond);
        return Ok(());
    }

    if let Some(expected_host) = host {
        let req_host = parts
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if req_host != expected_host {
            debug!("{peer} XHTTP host mismatch: expected {expected_host}, got {req_host}");
            reject_xhttp(respond);
            return Ok(());
        }
    }

    trace!("{peer} XHTTP stream accepted at {path}");

    let resp = http::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .unwrap();
    let mut send = respond
        .send_response(resp, false)
        .map_err(|e| format!("send response: {e}"))?;

    let (incoming_tx, incoming_rx) = mpsc::sync_channel::<Vec<u8>>(64);
    let (outgoing_tx, outgoing_rx) = tokio_mpsc::channel::<Vec<u8>>(256);

    let relay_handle = tokio::task::spawn_blocking(move || {
        let xhttp_stream = XhttpStream::from_channels(incoming_rx, outgoing_tx);
        handle_vless_over_xhttp(xhttp_stream, validator, kyber_sk, peer).map_err(|e| e.to_string())
    });

    let outgoing_handle =
        tokio::spawn(async move { drive_outgoing(&mut send, outgoing_rx, peer).await });
    let incoming_result = drive_incoming(body, &incoming_tx).await;
    drop(incoming_tx);

    let relay_result = relay_handle
        .await
        .map_err(|e| format!("XHTTP relay panic: {e}"))?;
    let outgoing_result = outgoing_handle
        .await
        .map_err(|e| format!("XHTTP outgoing panic: {e}"))?;

    outgoing_result?;
    relay_result.map_err(|e| format!("XHTTP relay: {e}"))?;
    incoming_result
}

async fn drive_incoming(
    mut body: h2::RecvStream,
    incoming_tx: &mpsc::SyncSender<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        match body.data().await {
            Some(Ok(data)) => {
                if incoming_tx.send(data.to_vec()).is_err() {
                    return Ok(()); // relay stopped
                }
            }
            Some(Err(e)) => return Err(format!("h2 stream error: {e}").into()),
            None => return Ok(()),
        }
    }
}

async fn drive_outgoing(
    send: &mut h2::SendStream<bytes::Bytes>,
    mut outgoing_rx: tokio_mpsc::Receiver<Vec<u8>>,
    peer: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        match outgoing_rx.recv().await {
            Some(data) => {
                send.send_data(data.into(), false)
                    .map_err(|e| format!("h2 send data: {e}"))?;
            }
            None => {
                // Channel closed — relay finished
                let _ = send.send_data(bytes::Bytes::new(), true);
                trace!("{peer} XHTTP stream finished OK");
                return Ok(());
            }
        }
    }
}

// ── Connection handler (sync entry point) ─────────────────────────────

pub(crate) fn handle_xhttp_connection(
    stream: TcpStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    xhttp_config: &XhttpConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} XHTTP connection");

    match &xhttp_config.tls_config {
        Some(tls_config) => {
            // TLS+XHTTP: handshake, then relay through local TCP bridge
            // so the existing async h2 handler sees a plaintext stream.
            let plain = tls_relay(stream, tls_config, peer, "xhttp+tls")?;
            handle_xhttp_connection(
                plain,
                validator,
                kyber_sk,
                &XhttpConfig {
                    tls_config: None,
                    ..xhttp_config.clone()
                },
            )
        }
        None => {
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|e| format!("XHTTP runtime: {e}"))?;
            rt.block_on(drive_xhttp_connection(
                stream,
                peer,
                &xhttp_config.path,
                xhttp_config.host.as_deref(),
                validator,
                kyber_sk,
            ))
            .map_err(|e| format!("XHTTP: {e}").into())
        }
    }
}

fn handle_vless_over_xhttp(
    mut stream: XhttpStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    peer: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut first = vec![0u8; 8192];
    let n = stream.read(&mut first)?;
    if n == 0 {
        return Err("XHTTP closed before VLESS header".into());
    }
    first.truncate(n);
    trace!("{peer} XHTTP read {} bytes VLESS header", first.len());

    let VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    } = decode_vless_request(first, &validator, peer)?;

    let request = &decoded.header;
    let account = &request.user.account;

    log_vless_request(peer, request);
    trace!(
        "{peer} XHTTP flow={} use_vision={use_vision}",
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
        relay_xhttp_udp(&mut stream, request, remaining_body)?;
        debug!("{peer} XHTTP UDP relay finished");
        return Ok(());
    }

    let target = connect_tcp_target(&request.address, request.port)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;

    if use_vision {
        relay_xhttp_vision(
            &mut stream,
            target,
            &decoded.user_sent_id,
            &account.testseed,
            remaining_body,
        )?;
    } else {
        relay_xhttp_raw(stream, target, remaining_body)?;
    }
    debug!("{peer} XHTTP relay finished");
    Ok(())
}

// ── XHTTP relay functions ─────────────────────────────────────────────

fn relay_xhttp_raw(
    client: XhttpStream,
    mut target: TcpStream,
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    target.set_nodelay(true)?;
    if !initial_data.is_empty() {
        target.write_all(&initial_data)?;
    }
    let (mut reader, mut writer) = client.split();
    let mut target_write = target.try_clone()?;
    let mut target_read = target;

    let up = std::thread::spawn(move || {
        let mut buf = [0u8; 32768];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = target_write.write_all(&buf[..n]) {
                        debug!("XHTTP uplink write error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("XHTTP uplink read error: {e}");
                    break;
                }
            }
        }
        let _ = target_write.shutdown(std::net::Shutdown::Write);
    });

    let down = std::thread::spawn(move || {
        let mut buf = [0u8; 32768];
        loop {
            match target_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = writer.write_all(&buf[..n]) {
                        debug!("XHTTP downlink write error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("XHTTP downlink read error: {e}");
                    break;
                }
            }
        }
    });

    let _ = up.join();
    let _ = down.join();
    Ok(())
}

fn relay_xhttp_vision(
    client: &mut XhttpStream,
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
        // Downlink: target → Vision encode → XHTTP
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
                    target.set_read_timeout(Some(Duration::from_millis(10)))?;
                    break false;
                }
                Err(e) => return Err(e.into()),
            }
        };

        // Uplink: XHTTP → Vision decode → target
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

fn relay_xhttp_udp(
    client: &mut XhttpStream,
    request: &RequestHeader,
    remaining: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Cursor, ErrorKind};
    use wrongsv_vless_encoding::{LengthPacketReader, LengthPacketWriter, PacketReadError};

    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("XHTTP UDP relay to {target_addr}");

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
        let xhttp_data = {
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

        if let Some(pkts) = xhttp_data {
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
    fn parse_default_path() {
        let cfg = XhttpServerConfig {
            path: None,
            host: None,
            tls: None,
        };
        let xhttp = parse_xhttp_config(&cfg).unwrap();
        assert_eq!(xhttp.path, "/xhttp");
    }

    #[test]
    fn parse_custom_path() {
        let cfg = XhttpServerConfig {
            path: Some("/custom".into()),
            host: None,
            tls: None,
        };
        let xhttp = parse_xhttp_config(&cfg).unwrap();
        assert_eq!(xhttp.path, "/custom");
    }

    #[test]
    fn parse_with_host() {
        let cfg = XhttpServerConfig {
            path: None,
            host: Some("example.com".into()),
            tls: None,
        };
        let xhttp = parse_xhttp_config(&cfg).unwrap();
        assert_eq!(xhttp.host.as_deref(), Some("example.com"));
    }
}
