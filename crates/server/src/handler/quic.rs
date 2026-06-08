use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use tokio::sync::mpsc as tokio_mpsc;
use tracing::{debug, info, trace, warn};
use wrongsv_protocol::{RequestCommand, RequestHeader};
use wrongsv_vless::MemoryValidator;

use crate::config::QuicServerConfig;

use super::*;

// ── Config ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct QuicConfig {
    pub quic_server_config: quinn::ServerConfig,
    pub udp_relay: bool,
}

pub(crate) fn parse_quic_config(qc: &QuicServerConfig) -> Result<QuicConfig, String> {
    let (cert_pem, key_pem) = match &qc.tls {
        Some(tls) => match (&tls.certificate, &tls.key) {
            (Some(c), Some(k)) => (c.clone(), k.clone()),
            _ => {
                let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                    .map_err(|e| format!("quic tls cert: {e}"))?;
                (cert, key)
            }
        },
        None => {
            let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                .map_err(|e| format!("quic tls cert: {e}"))?;
            (cert, key)
        }
    };

    let mut tls_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
        .map_err(|e| format!("quic tls: {e}"))?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls_config))
        .map_err(|e| format!("quic crypto: {e}"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1024u32.into());
    transport.max_concurrent_uni_streams(1024u32.into());
    server_config.transport_config(Arc::new(transport));

    Ok(QuicConfig {
        quic_server_config: server_config,
        udp_relay: qc.udp_relay,
    })
}

// ── QUIC endpoint runner ───────────────────────────────────────────────

pub(crate) async fn run_quic_endpoint(
    listen: &str,
    config: QuicConfig,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    shutdown: super::ShutdownSignal,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = listen.parse()?;
    let endpoint = quinn::Endpoint::server(config.quic_server_config, addr)?;
    info!("QUIC endpoint listening on {}", endpoint.local_addr()?);

    loop {
        if shutdown.is_shutdown_requested() {
            info!("QUIC server stopped");
            break;
        }

        match tokio::time::timeout(Duration::from_millis(200), endpoint.accept()).await {
            Ok(Some(incoming)) => {
                let v = Arc::clone(&validator);
                let ks = kyber_sk;
                let udp = config.udp_relay;
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            let peer = conn.remote_address();
                            trace!("{peer} QUIC connection");
                            if let Err(e) = handle_quic_connection(conn, v, ks, peer, udp).await {
                                warn!("{peer} QUIC connection error: {e}");
                            }
                        }
                        Err(e) => warn!("QUIC incoming error: {e}"),
                    }
                });
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    Ok(())
}

async fn handle_quic_connection(
    conn: quinn::Connection,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    peer: SocketAddr,
    udp_relay: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let v = Arc::clone(&validator);
                let ks = kyber_sk;
                // Spawn a dedicated OS thread for each stream's VLESS processing.
                // The async ↔ sync bridge uses the same pattern as gRPC/XHTTP.
                std::thread::spawn(move || {
                    let mut stream = QuicStream::from_quic_streams(send, recv, peer);
                    if let Err(e) = handle_vless_over_quic(&mut stream, v, ks, peer, udp_relay) {
                        warn!("{peer} QUIC stream error: {e}");
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => break,
            Err(e) => {
                trace!("{peer} accept_bi error: {e}");
                break;
            }
        }
    }
    Ok(())
}

// ── QUIC stream bridge (sync Read + Write) ────────────────────────────

pub(crate) struct QuicStream {
    incoming_rx: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    outgoing_tx: tokio_mpsc::UnboundedSender<Vec<u8>>,
    eof: bool,
    _thread: std::thread::JoinHandle<()>,
}

impl QuicStream {
    fn from_quic_streams(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        peer: SocketAddr,
    ) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::sync_channel::<Vec<u8>>(64);
        let (outgoing_tx, outgoing_rx) = tokio_mpsc::unbounded_channel::<Vec<u8>>();

        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("quic stream runtime");
            rt.block_on(async move {
                let recv_handle = tokio::spawn(drive_quic_recv(recv, incoming_tx));
                let send_handle = tokio::spawn(drive_quic_send(send, outgoing_rx, peer));
                // When the VLESS handler finishes, it drops outgoing_tx,
                // which causes drive_quic_send to drain and finish().
                // Wait for send to complete so all outgoing data is flushed,
                // then abort recv (which may still be running).
                if let Err(e) = send_handle.await {
                    trace!("{peer} send task panic: {e}");
                }
                recv_handle.abort();
            });
        });

        QuicStream {
            incoming_rx,
            pending: Vec::new(),
            outgoing_tx,
            eof: false,
            _thread: thread,
        }
    }
}

impl Read for QuicStream {
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

impl Write for QuicStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.eof {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "QUIC stream closed",
            ));
        }
        self.outgoing_tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "QUIC stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn drive_quic_recv(mut recv: quinn::RecvStream, incoming_tx: mpsc::SyncSender<Vec<u8>>) {
    let mut buf = vec![0u8; 32768];
    loop {
        match recv.read(&mut buf).await {
            Ok(None) | Err(_) => break, // stream finished or error
            Ok(Some(n)) => {
                if incoming_tx.send(buf[..n].to_vec()).is_err() {
                    break; // relay stopped
                }
            }
        }
    }
}

async fn drive_quic_send(
    mut send: quinn::SendStream,
    mut outgoing_rx: tokio_mpsc::UnboundedReceiver<Vec<u8>>,
    peer: SocketAddr,
) {
    loop {
        match outgoing_rx.recv().await {
            Some(data) => {
                if let Err(e) = send.write_all(&data).await {
                    trace!("{peer} QUIC send error: {e}");
                    break;
                }
            }
            None => {
                let _ = send.finish();
                trace!("{peer} QUIC stream finished OK");
                break;
            }
        }
    }
}

// ── VLESS over QUIC ────────────────────────────────────────────────────

fn handle_vless_over_quic(
    stream: &mut QuicStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    peer: SocketAddr,
    udp_relay: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut first = vec![0u8; 8192];
    let n = stream.read(&mut first)?;
    if n == 0 {
        return Err("QUIC closed before VLESS header".into());
    }
    first.truncate(n);
    trace!("{peer} QUIC read {} bytes VLESS header", first.len());

    let VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    } = decode_vless_request(first, &validator, peer)?;

    let request = &decoded.header;
    let account = &request.user.account;

    log_vless_request(peer, request);
    trace!(
        "{peer} QUIC flow={} use_vision={use_vision}",
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
        if !udp_relay {
            return Err("QUIC UDP relay disabled".into());
        }
        relay_quic_udp(stream, request, remaining_body)?;
        debug!("{peer} QUIC UDP relay finished");
        return Ok(());
    }

    let target = connect_tcp_target(&request.address, request.port)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;

    if use_vision {
        relay_quic_vision(
            stream,
            target,
            &decoded.user_sent_id,
            &account.testseed,
            remaining_body,
        )?;
    } else {
        relay_quic_raw(stream, target, remaining_body)?;
    }
    debug!("{peer} QUIC relay finished");
    Ok(())
}

// ── QUIC relay functions ───────────────────────────────────────────────

fn relay_quic_raw(
    client: &mut QuicStream,
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
        // Downlink: target → QUIC
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

        // Uplink: QUIC → target
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

fn relay_quic_vision(
    client: &mut QuicStream,
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
        // Downlink: target → Vision encode → QUIC
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

        // Uplink: QUIC → Vision decode → target
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

fn relay_quic_udp(
    client: &mut QuicStream,
    request: &RequestHeader,
    remaining: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Cursor, ErrorKind};
    use wrongsv_vless_encoding::{LengthPacketReader, LengthPacketWriter, PacketReadError};

    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("QUIC UDP relay to {target_addr}");

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
        let quic_data = {
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

        if let Some(pkts) = quic_data {
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
    use crate::config::QuicServerConfig;

    #[test]
    fn parse_default_quic_config() {
        let cfg = QuicServerConfig {
            tls: None,
            udp_relay: true,
        };
        let quic = parse_quic_config(&cfg).unwrap();
        assert!(quic.udp_relay);
    }

    #[test]
    fn parse_quic_without_udp() {
        let cfg = QuicServerConfig {
            tls: None,
            udp_relay: false,
        };
        let quic = parse_quic_config(&cfg).unwrap();
        assert!(!quic.udp_relay);
    }
}
