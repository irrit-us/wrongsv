use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use quinn::{Connection as QuinnConnection, Endpoint};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::sync::{Mutex, Notify};
use tracing::{info, trace, warn};

use crate::config::TuicServerConfig;
use crate::config::is_strict_uuid_text;

use super::*;

type TuicError = Box<dyn std::error::Error + Send + Sync>;

const TUIC_VERSION: u8 = 0x05;
const TUIC_CMD_AUTHENTICATE: u8 = 0x00;
const TUIC_CMD_CONNECT: u8 = 0x01;
const TUIC_CMD_PACKET: u8 = 0x02;
const TUIC_CMD_DISSOCIATE: u8 = 0x03;
const TUIC_CMD_HEARTBEAT: u8 = 0x04;
const TUIC_ADDR_NONE: u8 = 0xff;
const TUIC_MAX_DATAGRAM_PAYLOAD: usize = 1200;

#[derive(Clone)]
pub(crate) struct TuicConfig {
    users: Vec<TuicUser>,
    quic_config: quinn::ServerConfig,
    auth_timeout: Duration,
}

#[derive(Clone)]
struct TuicUser {
    uuid: wrongsv_uuid::Uuid,
    password: String,
    name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TuicPacketRelayMode {
    Datagram,
    Stream,
}

struct TuicUdpSession {
    assoc_id: u16,
    conn: QuinnConnection,
    mode: Mutex<Option<TuicPacketRelayMode>>,
    next_packet_id: AtomicU16,
    closed: AtomicBool,
    close_notify: Notify,
    ipv4: Arc<UdpSocket>,
    ipv6: Option<Arc<UdpSocket>>,
}

impl TuicUdpSession {
    async fn new(conn: QuinnConnection, assoc_id: u16) -> Result<Self, TuicError> {
        let ipv4 = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let ipv6 = match UdpSocket::bind("[::]:0").await {
            Ok(socket) => Some(Arc::new(socket)),
            Err(_) => None,
        };
        Ok(Self {
            assoc_id,
            conn,
            mode: Mutex::new(None),
            next_packet_id: AtomicU16::new(0),
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
            ipv4,
            ipv6,
        })
    }

    async fn set_mode(&self, mode: TuicPacketRelayMode) {
        let mut guard = self.mode.lock().await;
        if guard.is_none() {
            *guard = Some(mode);
        }
    }

    async fn mode(&self) -> Option<TuicPacketRelayMode> {
        *self.mode.lock().await
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.close_notify.notify_waiters();
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    async fn send_payload_to_target(
        self: &Arc<Self>,
        mode: TuicPacketRelayMode,
        address: &str,
        payload: Vec<u8>,
    ) -> Result<(), TuicError> {
        self.set_mode(mode).await;
        let target = resolve_tuic_target(address).await?;
        let socket = if target.is_ipv4() {
            &self.ipv4
        } else {
            self.ipv6.as_ref().ok_or("IPv6 UDP socket unavailable")?
        };
        socket.send_to(&payload, target).await?;
        Ok(())
    }

    async fn send_packet_to_client(
        self: &Arc<Self>,
        address: &str,
        payload: &[u8],
    ) -> Result<(), TuicError> {
        if self.is_closed() {
            return Ok(());
        }
        let Some(mode) = self.mode().await else {
            return Ok(());
        };
        match mode {
            TuicPacketRelayMode::Datagram => {
                let packet_id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
                let fragments = fragment_tuic_payload(self.assoc_id, address, payload, packet_id)?;
                for fragment in fragments {
                    if self.conn.send_datagram(Bytes::from(fragment)).is_err() {
                        break;
                    }
                }
            }
            TuicPacketRelayMode::Stream => {
                let packet_id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
                let (mut send, _recv) = self.conn.open_bi().await?;
                let packet = encode_tuic_packet(self.assoc_id, packet_id, 0, 1, address, payload)?;
                send.write_all(&packet).await?;
                send.finish()?;
            }
        }
        Ok(())
    }

    async fn recv_loop(self: Arc<Self>) {
        let mut buf = [0u8; 65535];
        loop {
            tokio::select! {
                _ = self.close_notify.notified() => break,
                result = self.ipv4.recv_from(&mut buf) => {
                    let Ok((n, source)) = result else { break };
                    let (address, port) = socket_addr_to_tuic_address(source);
                    let addr = format!("{address}:{port}");
                    if self.send_packet_to_client(&addr, &buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    async fn recv_loop_v6(self: Arc<Self>) {
        let Some(socket) = self.ipv6.as_ref().map(Arc::clone) else {
            return;
        };
        let mut buf = [0u8; 65535];
        loop {
            tokio::select! {
                _ = self.close_notify.notified() => break,
                result = socket.recv_from(&mut buf) => {
                    let Ok((n, source)) = result else { break };
                    let (address, port) = socket_addr_to_tuic_address(source);
                    let addr = format!("{address}:{port}");
                    if self.send_packet_to_client(&addr, &buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
}

pub(crate) fn parse_tuic_config(cfg: &TuicServerConfig) -> Result<TuicConfig, String> {
    let (cert_pem, key_pem) = match &cfg.tls {
        Some(tls) => match (&tls.certificate, &tls.key) {
            (Some(cert), Some(key)) => (cert.clone(), key.clone()),
            _ => {
                let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                    .map_err(|e| format!("tuic tls cert: {e}"))?;
                (cert, key)
            }
        },
        None => {
            let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                .map_err(|e| format!("tuic tls cert: {e}"))?;
            (cert, key)
        }
    };
    let tls_config = build_tuic_tls_config(&cert_pem, &key_pem)?;
    let quic_config =
        build_tuic_quic_config(tls_config, cfg.congestion_control.as_str(), cfg.heartbeat)?;
    let users = cfg
        .users
        .iter()
        .map(|user| {
            if !is_strict_uuid_text(&user.uuid) {
                return Err(format!("tuic uuid: invalid UUID text: {}", user.uuid));
            }
            let uuid = wrongsv_uuid::Uuid::parse_string(&user.uuid)
                .map_err(|e| format!("tuic uuid: {e}"))?;
            Ok(TuicUser {
                uuid,
                password: user.password.clone(),
                name: user.name.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(TuicConfig {
        users,
        quic_config,
        auth_timeout: Duration::from_secs(cfg.auth_timeout.max(1)),
    })
}

fn build_tuic_tls_config(cert_pem: &str, key_pem: &str) -> Result<rustls::ServerConfig, String> {
    let mut config = wrongsv_anytls::build_tls_config(cert_pem, key_pem)
        .map_err(|e| format!("tuic tls config: {e}"))?;
    config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(config)
}

fn build_tuic_quic_config(
    tls_config: rustls::ServerConfig,
    congestion_control: &str,
    heartbeat: u64,
) -> Result<quinn::ServerConfig, String> {
    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls_config))
        .map_err(|e| format!("tuic quic tls: {e}"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| "tuic transport config unexpectedly shared".to_string())?;
    transport_config.datagram_receive_buffer_size(Some(64 * 1024));
    transport_config.datagram_send_buffer_size(64 * 1024);
    transport_config.keep_alive_interval(Some(Duration::from_secs(heartbeat.max(1))));
    match congestion_control {
        "cubic" => transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
        "new_reno" => transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default())),
        "bbr" => transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default())),
        _ => {
            return Err(format!(
                "unsupported congestion control: {congestion_control}"
            ));
        }
    };
    Ok(server_config)
}

pub(crate) async fn run_tuic_endpoint(
    listen: &str,
    config: TuicConfig,
    shutdown: ShutdownSignal,
) -> Result<(), TuicError> {
    let endpoint = create_tuic_endpoint(listen, &config)?;
    info!("TUIC endpoint listening on {}", endpoint.local_addr()?);

    loop {
        if shutdown.is_shutdown_requested() {
            info!("server stopped");
            break;
        }
        match tokio::time::timeout(Duration::from_millis(200), endpoint.accept()).await {
            Ok(Some(incoming)) => {
                let cfg = config.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            if let Err(e) = handle_tuic_connection(conn, cfg).await {
                                warn!("TUIC connection error: {e}");
                            }
                        }
                        Err(e) => warn!("TUIC incoming connection failed: {e}"),
                    }
                });
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    Ok(())
}

fn create_tuic_endpoint(listen: &str, config: &TuicConfig) -> Result<Endpoint, TuicError> {
    Ok(Endpoint::server(
        config.quic_config.clone(),
        listen.parse::<SocketAddr>()?,
    )?)
}

async fn handle_tuic_connection(
    conn: QuinnConnection,
    config: TuicConfig,
) -> Result<(), TuicError> {
    let peer = conn.remote_address();
    trace!("{peer} TUIC connection");
    let user = authenticate_tuic_connection(&conn, &config).await?;
    if let Some(ref name) = user.name {
        info!("{peer} TUIC auth accepted [{name}]");
    } else {
        info!("{peer} TUIC auth accepted");
    }

    let udp_sessions: Arc<Mutex<HashMap<u16, Arc<TuicUdpSession>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let packet_assemblies: Arc<Mutex<HashMap<(u16, u16), TuicPacketAssembly>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let tcp_conn = conn.clone();
    let uni_conn = conn.clone();
    let udp_conn = conn.clone();
    let cleanup_sessions = Arc::clone(&udp_sessions);
    let udp_sessions_for_uni = Arc::clone(&udp_sessions);
    let udp_sessions_for_udp = Arc::clone(&udp_sessions);
    let packet_assemblies_for_uni = Arc::clone(&packet_assemblies);
    let packet_assemblies_for_udp = Arc::clone(&packet_assemblies);

    let tcp_task = tokio::spawn(async move { drive_tuic_tcp(tcp_conn).await });
    let uni_task = tokio::spawn(async move {
        drive_tuic_uni(uni_conn, udp_sessions_for_uni, packet_assemblies_for_uni).await
    });
    let udp_task = tokio::spawn(async move {
        drive_tuic_datagrams(udp_conn, udp_sessions_for_udp, packet_assemblies_for_udp).await
    });

    let (tcp_result, uni_result, udp_result) = tokio::join!(tcp_task, uni_task, udp_task);
    {
        let mut guard = cleanup_sessions.lock().await;
        for session in guard.values() {
            session.close();
        }
        guard.clear();
    }
    match tcp_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(format!("tuic tcp task panic: {e}").into()),
    }
    match uni_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(format!("tuic uni task panic: {e}").into()),
    }
    match udp_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(format!("tuic datagram task panic: {e}").into()),
    }
    Ok(())
}

struct TuicAuthenticatedUser {
    name: Option<String>,
}

async fn authenticate_tuic_connection(
    conn: &QuinnConnection,
    config: &TuicConfig,
) -> Result<TuicAuthenticatedUser, TuicError> {
    let mut recv = tokio::time::timeout(config.auth_timeout, conn.accept_uni()).await??;
    let mut auth = [0u8; 50];
    recv.read_exact(&mut auth).await?;
    if auth[0] != TUIC_VERSION || auth[1] != TUIC_CMD_AUTHENTICATE {
        return Err("TUIC expected Authenticate command first".into());
    }
    let uuid = wrongsv_uuid::Uuid::from({
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&auth[2..18]);
        uuid
    });
    let mut token = [0u8; 32];
    token.copy_from_slice(&auth[18..50]);
    let user = config
        .users
        .iter()
        .find(|user| user.uuid == uuid)
        .ok_or("TUIC auth failed: unknown user")?;
    let expected = derive_tuic_token(conn, &uuid, &user.password)?;
    if expected != token {
        return Err("TUIC auth failed: invalid token".into());
    }
    Ok(TuicAuthenticatedUser {
        name: user.name.clone(),
    })
}

fn derive_tuic_token(
    conn: &QuinnConnection,
    uuid: &wrongsv_uuid::Uuid,
    password: &str,
) -> Result<[u8; 32], TuicError> {
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, uuid.as_bytes(), password.as_bytes())
        .map_err(|e| format!("tuic token derivation failed: {e:?}"))?;
    Ok(token)
}

async fn drive_tuic_tcp(conn: QuinnConnection) -> Result<(), TuicError> {
    while let Ok((send, recv)) = conn.accept_bi().await {
        tokio::spawn(async move {
            if let Err(e) = handle_tuic_connect_stream(send, recv).await {
                warn!("TUIC TCP stream error: {e}");
            }
        });
    }
    Ok(())
}

async fn handle_tuic_connect_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), TuicError> {
    let (address, initial_body) = read_tuic_connect_request(&mut recv).await?;
    let target = match TcpStream::connect(&address).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("TUIC connect failed for {address}: {e}");
            return Ok(());
        }
    };
    target.set_nodelay(true)?;
    let (mut target_read, mut target_write) = target.into_split();
    if !initial_body.is_empty() {
        target_write.write_all(&initial_body).await?;
    }
    let client_to_target = async {
        tokio::io::copy(&mut recv, &mut target_write).await?;
        target_write.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };
    let target_to_client = async {
        tokio::io::copy(&mut target_read, &mut send).await?;
        send.finish()?;
        Ok::<(), std::io::Error>(())
    };
    tokio::try_join!(client_to_target, target_to_client)?;
    Ok(())
}

async fn read_tuic_connect_request(
    recv: &mut quinn::RecvStream,
) -> Result<(String, Vec<u8>), TuicError> {
    let mut buf = BytesMut::new();
    let mut tmp = [0u8; 4096];
    loop {
        match try_parse_tuic_connect_request(&buf)? {
            Some((address, consumed)) => {
                let remaining = buf.split_off(consumed);
                return Ok((address, remaining.to_vec()));
            }
            None => {
                let n = recv.read(&mut tmp).await?;
                let Some(n) = n else {
                    return Err("TUIC closed before TCP request header".into());
                };
                if n == 0 {
                    return Err("TUIC closed before TCP request header".into());
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 64 * 1024 {
                    return Err("TUIC TCP request too large".into());
                }
            }
        }
    }
}

fn try_parse_tuic_connect_request(buf: &[u8]) -> Result<Option<(String, usize)>, TuicError> {
    let mut pos = 0usize;
    let Some(version) = buf.get(pos).copied() else {
        return Ok(None);
    };
    pos += 1;
    if version != TUIC_VERSION {
        return Err(format!("unexpected TUIC version: {version:#x}").into());
    }
    let Some(cmd) = buf.get(pos).copied() else {
        return Ok(None);
    };
    pos += 1;
    if cmd != TUIC_CMD_CONNECT {
        return Err(format!("unexpected TUIC command for TCP stream: {cmd:#x}").into());
    }
    let Some(address) = parse_tuic_address(buf, &mut pos)? else {
        return Ok(None);
    };
    Ok(Some((address, pos)))
}

async fn drive_tuic_uni(
    conn: QuinnConnection,
    sessions: Arc<Mutex<HashMap<u16, Arc<TuicUdpSession>>>>,
    packet_assemblies: Arc<Mutex<HashMap<(u16, u16), TuicPacketAssembly>>>,
) -> Result<(), TuicError> {
    while let Ok(mut recv) = conn.accept_uni().await {
        let sessions = Arc::clone(&sessions);
        let packet_assemblies = Arc::clone(&packet_assemblies);
        let conn = conn.clone();
        if let Err(e) = handle_tuic_uni_stream(conn, sessions, packet_assemblies, &mut recv).await {
            warn!("TUIC unidirectional stream error: {e}");
        }
    }
    Ok(())
}

async fn handle_tuic_uni_stream(
    conn: QuinnConnection,
    sessions: Arc<Mutex<HashMap<u16, Arc<TuicUdpSession>>>>,
    packet_assemblies: Arc<Mutex<HashMap<(u16, u16), TuicPacketAssembly>>>,
    recv: &mut quinn::RecvStream,
) -> Result<(), TuicError> {
    let cmd = read_tuic_command_header(recv).await?;
    match cmd {
        TuicCommand::Packet(packet) => {
            handle_tuic_packet(
                conn,
                sessions,
                packet_assemblies,
                packet,
                TuicPacketRelayMode::Stream,
            )
            .await?;
        }
        TuicCommand::Dissociate(assoc_id) => {
            let session = {
                let mut guard = sessions.lock().await;
                guard.remove(&assoc_id)
            };
            if let Some(session) = session {
                session.close();
            }
        }
        TuicCommand::Authenticate(_) | TuicCommand::Connect(_) | TuicCommand::Heartbeat => {}
    }
    Ok(())
}

async fn drive_tuic_datagrams(
    conn: QuinnConnection,
    sessions: Arc<Mutex<HashMap<u16, Arc<TuicUdpSession>>>>,
    packet_assemblies: Arc<Mutex<HashMap<(u16, u16), TuicPacketAssembly>>>,
) -> Result<(), TuicError> {
    loop {
        let datagram = conn.read_datagram().await?;
        match parse_tuic_datagram_command(datagram.as_ref())? {
            TuicCommand::Packet(packet) => {
                handle_tuic_packet(
                    conn.clone(),
                    Arc::clone(&sessions),
                    Arc::clone(&packet_assemblies),
                    packet,
                    TuicPacketRelayMode::Datagram,
                )
                .await?;
            }
            TuicCommand::Dissociate(assoc_id) => {
                let session = {
                    let mut guard = sessions.lock().await;
                    guard.remove(&assoc_id)
                };
                if let Some(session) = session {
                    session.close();
                }
            }
            TuicCommand::Connect(_) | TuicCommand::Authenticate(_) => {
                trace!("TUIC datagram command ignored");
            }
            TuicCommand::Heartbeat => {}
        }
    }
}

async fn handle_tuic_packet(
    conn: QuinnConnection,
    sessions: Arc<Mutex<HashMap<u16, Arc<TuicUdpSession>>>>,
    packet_assemblies: Arc<Mutex<HashMap<(u16, u16), TuicPacketAssembly>>>,
    packet: TuicPacket,
    source_mode: TuicPacketRelayMode,
) -> Result<(), TuicError> {
    let session = {
        let mut guard = sessions.lock().await;
        if let Some(session) = guard.get(&packet.assoc_id) {
            Arc::clone(session)
        } else {
            let session = Arc::new(TuicUdpSession::new(conn.clone(), packet.assoc_id).await?);
            guard.insert(packet.assoc_id, Arc::clone(&session));
            let v4_session = Arc::clone(&session);
            tokio::spawn(async move { v4_session.recv_loop().await });
            if session.ipv6.is_some() {
                let v6_session = Arc::clone(&session);
                tokio::spawn(async move { v6_session.recv_loop_v6().await });
            }
            session
        }
    };
    session.set_mode(source_mode).await;

    if packet.frag_total == 0 {
        return Err("TUIC invalid fragment count".into());
    }

    if packet.frag_total == 1 {
        let address = packet
            .address
            .as_deref()
            .ok_or("TUIC first packet fragment requires an address")?;
        session
            .send_payload_to_target(source_mode, address, packet.payload)
            .await?;
        return Ok(());
    }

    let key = (packet.assoc_id, packet.packet_id);
    let payload = {
        let mut guard = packet_assemblies.lock().await;
        let assembly = guard
            .entry(key)
            .or_insert_with(|| TuicPacketAssembly::new(packet.frag_total));
        assembly.insert(
            packet.fragment_index,
            packet.address.clone(),
            packet.payload,
        )?;
        if !assembly.is_complete() {
            None
        } else {
            let data = assembly.take_payload()?;
            guard.remove(&key);
            Some(data)
        }
    };
    if let Some((address, payload)) = payload {
        let address = address.ok_or("TUIC fragmented packet missing initial address")?;
        session
            .send_payload_to_target(source_mode, &address, payload)
            .await?;
    }
    Ok(())
}

async fn read_tuic_command_header(recv: &mut quinn::RecvStream) -> Result<TuicCommand, TuicError> {
    let mut buf = BytesMut::new();
    let mut tmp = [0u8; 4096];
    loop {
        match try_parse_tuic_command(&buf)? {
            Some((cmd, _consumed)) => return Ok(cmd),
            None => {
                let n = recv.read(&mut tmp).await?;
                let Some(n) = n else {
                    return Err("TUIC stream closed before command header".into());
                };
                if n == 0 {
                    return Err("TUIC stream closed before command header".into());
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 64 * 1024 {
                    return Err("TUIC command too large".into());
                }
            }
        }
    }
}

fn parse_tuic_datagram_command(packet: &[u8]) -> Result<TuicCommand, TuicError> {
    let (cmd, consumed) =
        try_parse_tuic_command(packet)?.ok_or("TUIC datagram too short to contain a command")?;
    if consumed != packet.len() {
        trace!(
            "TUIC datagram contains {} trailing bytes",
            packet.len() - consumed
        );
    }
    Ok(cmd)
}

fn try_parse_tuic_command(buf: &[u8]) -> Result<Option<(TuicCommand, usize)>, TuicError> {
    let mut pos = 0usize;
    let Some(version) = buf.get(pos).copied() else {
        return Ok(None);
    };
    pos += 1;
    if version != TUIC_VERSION {
        return Err(format!("unexpected TUIC version: {version:#x}").into());
    }
    let Some(cmd) = buf.get(pos).copied() else {
        return Ok(None);
    };
    pos += 1;
    match cmd {
        TUIC_CMD_AUTHENTICATE => {
            if buf.len() < pos + 48 {
                return Ok(None);
            }
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&buf[pos..pos + 16]);
            pos += 16;
            let mut token = [0u8; 32];
            token.copy_from_slice(&buf[pos..pos + 32]);
            pos += 32;
            Ok(Some((
                TuicCommand::Authenticate(TuicAuthenticate { uuid, token }),
                pos,
            )))
        }
        TUIC_CMD_CONNECT => {
            let Some(address) = parse_tuic_address(buf, &mut pos)? else {
                return Ok(None);
            };
            let body = buf[pos..].to_vec();
            Ok(Some((
                TuicCommand::Connect(TuicConnect {
                    address,
                    initial_body: body,
                }),
                buf.len(),
            )))
        }
        TUIC_CMD_PACKET => {
            if buf.len() < pos + 8 {
                return Ok(None);
            }
            let assoc_id = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            let packet_id = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            let frag_total = buf[pos];
            pos += 1;
            let fragment_index = buf[pos];
            pos += 1;
            let size = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            pos += 2;
            let address = parse_tuic_address(buf, &mut pos)?;
            if buf.len() < pos + size {
                return Ok(None);
            }
            let payload = buf[pos..pos + size].to_vec();
            pos += size;
            Ok(Some((
                TuicCommand::Packet(TuicPacket {
                    assoc_id,
                    packet_id,
                    frag_total,
                    fragment_index,
                    address,
                    payload,
                }),
                pos,
            )))
        }
        TUIC_CMD_DISSOCIATE => {
            if buf.len() < pos + 2 {
                return Ok(None);
            }
            let assoc_id = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            Ok(Some((TuicCommand::Dissociate(assoc_id), pos)))
        }
        TUIC_CMD_HEARTBEAT => Ok(Some((TuicCommand::Heartbeat, pos))),
        other => Err(format!("unexpected TUIC command: {other:#x}").into()),
    }
}

#[allow(dead_code)]
enum TuicCommand {
    Authenticate(TuicAuthenticate),
    Connect(TuicConnect),
    Packet(TuicPacket),
    Dissociate(u16),
    Heartbeat,
}

#[allow(dead_code)]
struct TuicAuthenticate {
    uuid: [u8; 16],
    token: [u8; 32],
}

#[allow(dead_code)]
struct TuicConnect {
    address: String,
    initial_body: Vec<u8>,
}

struct TuicPacket {
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    fragment_index: u8,
    address: Option<String>,
    payload: Vec<u8>,
}

struct TuicPacketAssembly {
    fragments: Vec<Option<Vec<u8>>>,
    address: Option<String>,
}

impl TuicPacketAssembly {
    fn new(fragment_total: u8) -> Self {
        Self {
            fragments: vec![None; fragment_total as usize],
            address: None,
        }
    }

    fn insert(
        &mut self,
        fragment_index: u8,
        address: Option<String>,
        payload: Vec<u8>,
    ) -> Result<(), TuicError> {
        let idx = fragment_index as usize;
        if idx >= self.fragments.len() {
            return Err("invalid TUIC fragment index".into());
        }
        if self.address.is_none() && address.is_some() {
            self.address = address;
        }
        self.fragments[idx] = Some(payload);
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.fragments.iter().all(Option::is_some)
    }

    fn take_payload(&mut self) -> Result<(Option<String>, Vec<u8>), TuicError> {
        let mut out = Vec::new();
        for fragment in self.fragments.iter_mut() {
            out.extend_from_slice(fragment.take().as_deref().ok_or("missing TUIC fragment")?);
        }
        Ok((self.address.take(), out))
    }
}

fn parse_tuic_address(buf: &[u8], pos: &mut usize) -> Result<Option<String>, TuicError> {
    let Some(addr_type) = buf.get(*pos).copied() else {
        return Ok(None);
    };
    *pos += 1;
    match addr_type {
        TUIC_ADDR_NONE => Ok(None),
        0x00 => {
            let Some(len) = buf.get(*pos).copied() else {
                return Ok(None);
            };
            *pos += 1;
            let len = len as usize;
            if buf.len() < *pos + len + 2 {
                return Ok(None);
            }
            let host = std::str::from_utf8(&buf[*pos..*pos + len])?.to_string();
            *pos += len;
            let port = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
            *pos += 2;
            Ok(Some(format!("{host}:{port}")))
        }
        0x01 => {
            if buf.len() < *pos + 4 + 2 {
                return Ok(None);
            }
            let raw = [buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]];
            *pos += 4;
            let port = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
            *pos += 2;
            Ok(Some(format!("{}:{port}", Ipv4Addr::from(raw))))
        }
        0x02 => {
            if buf.len() < *pos + 16 + 2 {
                return Ok(None);
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&buf[*pos..*pos + 16]);
            *pos += 16;
            let port = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
            *pos += 2;
            Ok(Some(format!("[{}]:{port}", Ipv6Addr::from(raw))))
        }
        other => Err(format!("unexpected TUIC address type: {other:#x}").into()),
    }
}

fn socket_addr_to_tuic_address(source: SocketAddr) -> (String, u16) {
    match source {
        SocketAddr::V4(addr) => (addr.ip().to_string(), addr.port()),
        SocketAddr::V6(addr) => (format!("[{}]", addr.ip()), addr.port()),
    }
}

async fn resolve_tuic_target(address: &str) -> Result<SocketAddr, TuicError> {
    if let Ok(addr) = address.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = split_tuic_host_port(address)?;
    let mut targets = lookup_host((host, port)).await?;
    targets
        .next()
        .ok_or_else(|| format!("DNS resolution failed for {address}").into())
}

fn split_tuic_host_port(s: &str) -> Result<(&str, u16), TuicError> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find("]:").ok_or("invalid IPv6 host:port")?;
        let host = &rest[..end];
        let port = rest[end + 2..].parse::<u16>()?;
        return Ok((host, port));
    }
    let (host, port) = s.rsplit_once(':').ok_or("missing port")?;
    Ok((host, port.parse::<u16>()?))
}

fn fragment_tuic_payload(
    assoc_id: u16,
    address: &str,
    payload: &[u8],
    packet_id: u16,
) -> Result<Vec<Vec<u8>>, TuicError> {
    if payload.len() <= TUIC_MAX_DATAGRAM_PAYLOAD {
        return Ok(vec![encode_tuic_packet(
            assoc_id, packet_id, 0, 1, address, payload,
        )?]);
    }
    let mut fragments = Vec::new();
    let chunk_count = payload
        .len()
        .div_ceil(TUIC_MAX_DATAGRAM_PAYLOAD)
        .min(u8::MAX as usize);
    let total = chunk_count as u8;
    for (idx, chunk) in payload.chunks(TUIC_MAX_DATAGRAM_PAYLOAD).enumerate() {
        let addr = if idx == 0 { address } else { "" };
        fragments.push(encode_tuic_packet(
            assoc_id, packet_id, idx as u8, total, addr, chunk,
        )?);
    }
    Ok(fragments)
}

fn encode_tuic_packet(
    assoc_id: u16,
    packet_id: u16,
    fragment_index: u8,
    fragment_total: u8,
    address: &str,
    payload: &[u8],
) -> Result<Vec<u8>, TuicError> {
    let mut out = Vec::with_capacity(16 + address.len() + payload.len());
    out.push(TUIC_VERSION);
    out.push(TUIC_CMD_PACKET);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(fragment_total);
    out.push(fragment_index);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    if fragment_index == 0 {
        let (host, port) = split_tuic_host_port(address)?;
        if let Ok(ip) = host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    out.push(0x01);
                    out.extend_from_slice(&v4.octets());
                    out.extend_from_slice(&port.to_be_bytes());
                }
                IpAddr::V6(v6) => {
                    out.push(0x02);
                    out.extend_from_slice(&v6.octets());
                    out.extend_from_slice(&port.to_be_bytes());
                }
            }
        } else {
            out.push(0x00);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    } else {
        out.push(TUIC_ADDR_NONE);
    }
    out.extend_from_slice(payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static RUSTLS_PROVIDER: Once = Once::new();

    fn ensure_rustls_provider() {
        RUSTLS_PROVIDER.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    fn test_config() -> TuicConfig {
        ensure_rustls_provider();
        let (cert, key) = wrongsv_anytls::generate_self_signed_cert().unwrap();
        let tls = build_tuic_tls_config(&cert, &key).unwrap();
        TuicConfig {
            users: vec![TuicUser {
                uuid: wrongsv_uuid::Uuid::parse_string("12345678-1234-1234-1234-123456789abc")
                    .unwrap(),
                password: "secret".into(),
                name: Some("alice".into()),
            }],
            quic_config: build_tuic_quic_config(tls, "cubic", 10).unwrap(),
            auth_timeout: Duration::from_secs(3),
        }
    }

    #[test]
    fn tuic_test_config_smoke() {
        let config = test_config();
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.auth_timeout, Duration::from_secs(3));
    }

    #[test]
    fn tuic_address_parser_roundtrips() {
        let mut pos = 0;
        let buf = [
            0x00, 0x04, b't', b'e', b's', b't', 0x01, 0xbb, 0x01, 0x02, 0x03, 0x04, 0x01, 0xbb,
            0x02, 0x10, 0xdb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb,
        ];
        let first = parse_tuic_address(&buf, &mut pos).unwrap().unwrap();
        assert_eq!(first, "test:443");
    }

    #[test]
    fn tuic_command_parser_connect() {
        let mut buf = Vec::new();
        buf.push(TUIC_VERSION);
        buf.push(TUIC_CMD_CONNECT);
        buf.push(0x01);
        buf.extend_from_slice(&[127, 0, 0, 1]);
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.extend_from_slice(b"hello");
        let parsed = try_parse_tuic_command(&buf).unwrap().unwrap();
        match parsed.0 {
            TuicCommand::Connect(connect) => {
                assert_eq!(connect.address, "127.0.0.1:443");
                assert_eq!(connect.initial_body, b"hello");
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn tuic_command_parser_packet() {
        let mut buf = Vec::new();
        buf.push(TUIC_VERSION);
        buf.push(TUIC_CMD_PACKET);
        buf.extend_from_slice(&7u16.to_be_bytes());
        buf.extend_from_slice(&9u16.to_be_bytes());
        buf.push(1);
        buf.push(0);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.push(0x01);
        buf.extend_from_slice(&[127, 0, 0, 1]);
        buf.extend_from_slice(&53u16.to_be_bytes());
        buf.extend_from_slice(b"ping");
        let parsed = try_parse_tuic_command(&buf).unwrap().unwrap();
        match parsed.0 {
            TuicCommand::Packet(packet) => {
                assert_eq!(packet.assoc_id, 7);
                assert_eq!(packet.packet_id, 9);
                assert_eq!(packet.frag_total, 1);
                assert_eq!(packet.fragment_index, 0);
                assert_eq!(packet.address.as_deref(), Some("127.0.0.1:53"));
                assert_eq!(packet.payload, b"ping");
            }
            _ => panic!("unexpected command"),
        }
    }
}
