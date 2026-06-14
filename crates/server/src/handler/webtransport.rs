use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use tokio::sync::mpsc as tokio_mpsc;
use tracing::{debug, info, trace, warn};
use wrongsv_protocol::{RequestCommand, RequestHeader};
use wrongsv_vless::MemoryValidator;

use crate::config::WebTransportServerConfig;

use super::*;

// ── Config ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct WebTransportConfig {
    pub tls_config: Arc<rustls::ServerConfig>,
    pub path: String,
    pub host: Option<String>,
    pub udp_relay: bool,
}

pub(crate) fn parse_webtransport_config(
    wt: &WebTransportServerConfig,
) -> Result<WebTransportConfig, String> {
    let path = if wt.path.starts_with('/') {
        wt.path.clone()
    } else {
        format!("/{}", wt.path)
    };

    let (cert_pem, key_pem) = match &wt.tls {
        Some(tls) => match (&tls.certificate, &tls.key) {
            (Some(c), Some(k)) => (c.clone(), k.clone()),
            _ => {
                let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                    .map_err(|e| format!("webtransport tls cert: {e}"))?;
                (cert, key)
            }
        },
        None => {
            let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                .map_err(|e| format!("webtransport tls cert: {e}"))?;
            (cert, key)
        }
    };

    let mut tls_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
        .map_err(|e| format!("webtransport tls: {e}"))?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    Ok(WebTransportConfig {
        tls_config: Arc::new(tls_config),
        path,
        host: wt.host.clone(),
        udp_relay: wt.udp_relay,
    })
}

// ── WebTransport endpoint runner ──────────────────────────────────────

pub(crate) async fn run_webtransport_endpoint(
    listen: &str,
    config: WebTransportConfig,
    validator: Arc<MemoryValidator>,
    shutdown: super::ShutdownSignal,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = listen.parse()?;
    let endpoint_config = wtransport::ServerConfig::builder()
        .with_bind_address(addr)
        .with_custom_tls((*config.tls_config).clone())
        .build();

    let endpoint = wtransport::Endpoint::server(endpoint_config)?;
    info!(
        "WebTransport endpoint listening on {}",
        endpoint.local_addr()?
    );

    loop {
        if shutdown.is_shutdown_requested() {
            info!("WebTransport server stopped");
            break;
        }

        match tokio::time::timeout(Duration::from_millis(200), endpoint.accept()).await {
            Ok(incoming_session) => {
                let v = Arc::clone(&validator);
                let cfg = config.clone();
                tokio::spawn(async move {
                    let peer = incoming_session.remote_address();
                    if let Err(e) =
                        handle_webtransport_session(incoming_session, v, peer, cfg).await
                    {
                        warn!("{peer} WebTransport session error: {e}");
                    }
                });
            }
            Err(_) => continue,
        }
    }

    Ok(())
}

async fn handle_webtransport_session(
    incoming_session: wtransport::endpoint::IncomingSession,
    validator: Arc<MemoryValidator>,
    peer: SocketAddr,
    config: WebTransportConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let session_request = incoming_session.await?;

    // Validate path and host if configured
    if let Some(ref expected_host) = config.host {
        let authority = session_request.authority();
        if !authority.eq_ignore_ascii_case(expected_host) {
            trace!("{peer} WebTransport host mismatch: expected {expected_host}, got {authority}");
            session_request.forbidden().await;
            return Ok(());
        }
    }

    let request_path = session_request.path();
    if request_path != config.path {
        trace!(
            "{peer} WebTransport path mismatch: expected {}, got {request_path}",
            config.path
        );
        session_request.forbidden().await;
        return Ok(());
    }

    let connection = session_request.accept().await?;
    trace!(
        "{peer} WebTransport session accepted on path '{}'",
        config.path
    );

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let v = Arc::clone(&validator);
                let udp = config.udp_relay;
                std::thread::spawn(move || {
                    let mut stream = WebTransportStream::from_streams(send, recv, peer);
                    if let Err(e) = handle_vless_over_webtransport(&mut stream, v, peer, udp) {
                        warn!("{peer} WebTransport stream error: {e}");
                    }
                });
            }
            Err(wtransport::error::ConnectionError::LocallyClosed) => break,
            Err(e) => {
                trace!("{peer} accept_bi error: {e}");
                break;
            }
        }
    }

    Ok(())
}

// ── WebTransport stream bridge (sync Read + Write) ────────────────────

pub(crate) struct WebTransportStream {
    incoming_rx: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    outgoing_tx: tokio_mpsc::Sender<Vec<u8>>,
    eof: bool,
    _thread: std::thread::JoinHandle<()>,
}

impl WebTransportStream {
    fn from_streams(
        send: wtransport::SendStream,
        recv: wtransport::RecvStream,
        peer: SocketAddr,
    ) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::sync_channel::<Vec<u8>>(64);
        let (outgoing_tx, outgoing_rx) = tokio_mpsc::channel::<Vec<u8>>(256);

        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("webtransport stream runtime");
            rt.block_on(async move {
                let recv_handle = tokio::spawn(drive_wt_recv(recv, incoming_tx));
                let send_handle = tokio::spawn(drive_wt_send(send, outgoing_rx, peer));
                if let Err(e) = send_handle.await {
                    trace!("{peer} send task panic: {e}");
                }
                recv_handle.abort();
            });
        });

        WebTransportStream {
            incoming_rx,
            pending: Vec::new(),
            outgoing_tx,
            eof: false,
            _thread: thread,
        }
    }
}

impl Read for WebTransportStream {
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

impl Write for WebTransportStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.eof {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebTransport stream closed",
            ));
        }
        self.outgoing_tx
            .blocking_send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WebTransport stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn drive_wt_recv(mut recv: wtransport::RecvStream, incoming_tx: mpsc::SyncSender<Vec<u8>>) {
    let mut buf = vec![0u8; 32768];
    loop {
        match recv.read(&mut buf).await {
            Ok(None) | Err(_) => break,
            Ok(Some(n)) => {
                if incoming_tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        }
    }
}

async fn drive_wt_send(
    mut send: wtransport::SendStream,
    mut outgoing_rx: tokio_mpsc::Receiver<Vec<u8>>,
    peer: SocketAddr,
) {
    loop {
        match outgoing_rx.recv().await {
            Some(data) => {
                if let Err(e) = send.write_all(&data).await {
                    trace!("{peer} WebTransport send error: {e}");
                    break;
                }
            }
            None => {
                tokio::spawn(async move {
                    let _ = send.finish().await;
                });
                trace!("{peer} WebTransport stream finished OK");
                break;
            }
        }
    }
}

// ── VLESS over WebTransport ───────────────────────────────────────────

fn handle_vless_over_webtransport(
    stream: &mut WebTransportStream,
    validator: Arc<MemoryValidator>,
    peer: SocketAddr,
    udp_relay: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut first = vec![0u8; 8192];
    let n = stream.read(&mut first)?;
    if n == 0 {
        return Err("WebTransport stream closed before VLESS header".into());
    }
    first.truncate(n);
    trace!(
        "{peer} WebTransport read {} bytes VLESS header",
        first.len()
    );

    let VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    } = decode_vless_request(first, &validator, peer)?;

    let request = &decoded.header;
    let account = &request.user.account;

    log_vless_request(peer, request);
    trace!(
        "{peer} WebTransport flow={} use_vision={use_vision}",
        decoded.addons.flow
    );
    validate_vless_command(request, use_vision)?;

    let resp_buf = response_header_buf(request)?;
    stream.write_all(&resp_buf)?;

    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        if !udp_relay {
            return Err("WebTransport UDP relay disabled".into());
        }
        relay_wt_udp(stream, request, remaining_body)?;
        debug!("{peer} WebTransport UDP relay finished");
        return Ok(());
    }

    let target = connect_tcp_target(&request.address, request.port)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;

    if use_vision {
        relay_wt_vision(
            stream,
            target,
            &decoded.user_sent_id,
            &account.testseed,
            remaining_body,
        )?;
    } else {
        relay_wt_raw(stream, target, remaining_body)?;
    }
    debug!("{peer} WebTransport relay finished");
    Ok(())
}

// ── WebTransport relay functions ──────────────────────────────────────

fn relay_wt_raw(
    client: &mut WebTransportStream,
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
        // Downlink: target → WebTransport
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

        // Uplink: WebTransport → target
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

fn relay_wt_vision(
    client: &mut WebTransportStream,
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
        // Downlink: target → Vision encode → WebTransport
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

        // Uplink: WebTransport → Vision decode → target
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

fn relay_wt_udp(
    client: &mut WebTransportStream,
    request: &RequestHeader,
    remaining: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Cursor, ErrorKind};
    use wrongsv_vless_encoding::{LengthPacketReader, LengthPacketWriter, PacketReadError};

    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("WebTransport UDP relay to {target_addr}");

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
        let wt_data = {
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

        if let Some(pkts) = wt_data {
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
    use crate::config::WebTransportServerConfig;

    #[test]
    fn parse_default_webtransport_config() {
        let cfg = WebTransportServerConfig {
            path: "/wt".to_string(),
            host: None,
            udp_relay: true,
            tls: None,
        };
        let wt = parse_webtransport_config(&cfg).unwrap();
        assert!(wt.udp_relay);
        assert_eq!(wt.path, "/wt");
        assert!(wt.host.is_none());
    }

    #[test]
    fn parse_webtransport_without_udp() {
        let cfg = WebTransportServerConfig {
            path: "/wt".to_string(),
            host: None,
            udp_relay: false,
            tls: None,
        };
        let wt = parse_webtransport_config(&cfg).unwrap();
        assert!(!wt.udp_relay);
    }

    #[test]
    fn parse_webtransport_path_prefixes_slash() {
        let cfg = WebTransportServerConfig {
            path: "mypath".to_string(),
            host: None,
            udp_relay: true,
            tls: None,
        };
        let wt = parse_webtransport_config(&cfg).unwrap();
        assert_eq!(wt.path, "/mypath");
    }

    #[test]
    fn parse_webtransport_with_host() {
        let cfg = WebTransportServerConfig {
            path: "/wt".to_string(),
            host: Some("example.com".to_string()),
            udp_relay: true,
            tls: None,
        };
        let wt = parse_webtransport_config(&cfg).unwrap();
        assert_eq!(wt.host.unwrap(), "example.com");
    }
}
