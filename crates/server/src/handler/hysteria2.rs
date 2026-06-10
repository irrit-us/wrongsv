use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use h3::server;
use h3_quinn::Connection as H3QuinnConnection;
use http::StatusCode;
use quinn::{Connection as QuinnConnection, Endpoint};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tracing::{info, trace, warn};

use crate::config::Hysteria2ServerConfig;

use super::*;

type H2Error = Box<dyn std::error::Error + Send + Sync>;
type H2UdpMessage = (u32, u16, u8, u8, String, Vec<u8>);

#[derive(Clone)]
pub(crate) struct Hysteria2Config {
    pub password_auths: Vec<String>,
    pub quic_config: quinn::ServerConfig,
    pub disable_udp: bool,
    pub down_mbps: Option<u64>,
    pub ignore_client_bandwidth: bool,
}

pub(crate) fn parse_hysteria2_config(
    cfg: &Hysteria2ServerConfig,
) -> Result<Hysteria2Config, String> {
    let (cert_pem, key_pem) = match &cfg.tls {
        Some(tls) => match (&tls.certificate, &tls.key) {
            (Some(cert), Some(key)) => (cert.clone(), key.clone()),
            _ => {
                let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                    .map_err(|e| format!("hysteria2 tls cert: {e}"))?;
                (cert, key)
            }
        },
        None => {
            let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                .map_err(|e| format!("hysteria2 tls cert: {e}"))?;
            (cert, key)
        }
    };
    let tls_config = build_hysteria2_tls_config(&cert_pem, &key_pem)?;
    let quic_config = build_hysteria2_quic_config(tls_config)?;
    let mut password_auths = Vec::new();
    if let Some(password) = cfg.password.as_ref() {
        password_auths.push(password.clone());
    }
    for user in &cfg.users {
        password_auths.push(format!("{}:{}", user.name, user.password));
    }
    Ok(Hysteria2Config {
        password_auths,
        quic_config,
        disable_udp: cfg.disable_udp,
        down_mbps: cfg.down_mbps,
        ignore_client_bandwidth: cfg.ignore_client_bandwidth,
    })
}

fn build_hysteria2_tls_config(
    cert_pem: &str,
    key_pem: &str,
) -> Result<rustls::ServerConfig, String> {
    let mut config = wrongsv_anytls::build_tls_config(cert_pem, key_pem)
        .map_err(|e| format!("tls config: {e}"))?;
    config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(config)
}

fn build_hysteria2_quic_config(
    tls_config: rustls::ServerConfig,
) -> Result<quinn::ServerConfig, String> {
    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls_config))
        .map_err(|e| format!("quic tls: {e}"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| "quic transport config unexpectedly shared".to_string())?;
    transport_config.datagram_receive_buffer_size(Some(64 * 1024));
    transport_config.datagram_send_buffer_size(64 * 1024);
    transport_config.keep_alive_interval(Some(Duration::from_secs(10)));
    Ok(server_config)
}

pub(crate) async fn run_hysteria2_endpoint(
    listen: &str,
    config: Hysteria2Config,
    shutdown: ShutdownSignal,
) -> Result<(), H2Error> {
    let endpoint = create_hysteria2_endpoint(listen, &config)?;
    info!("Hysteria2 endpoint listening on {}", endpoint.local_addr()?);

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
                            if let Err(e) = handle_hysteria2_connection(conn, cfg).await {
                                warn!("Hysteria2 connection error: {e}");
                            }
                        }
                        Err(e) => warn!("Hysteria2 incoming connection failed: {e}"),
                    }
                });
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    Ok(())
}

fn create_hysteria2_endpoint(listen: &str, config: &Hysteria2Config) -> Result<Endpoint, H2Error> {
    Ok(Endpoint::server(
        config.quic_config.clone(),
        listen.parse::<SocketAddr>()?,
    )?)
}

async fn handle_hysteria2_connection(
    conn: QuinnConnection,
    config: Hysteria2Config,
) -> Result<(), H2Error> {
    let peer = conn.remote_address();
    trace!("{peer} Hysteria2 connection");

    let raw_conn = conn.clone();
    let h3_conn = H3QuinnConnection::new(conn);
    let mut h3_conn = server::builder().build::<_, Bytes>(h3_conn).await?;
    let Some(resolver) = h3_conn.accept().await? else {
        return Err("Hysteria2 closed before auth request".into());
    };
    let (request, mut stream) = resolver.resolve_request().await?;
    if !matches_hysteria2_auth(&request, &config)? {
        let resp = http::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .unwrap();
        stream.send_response(resp).await?;
        stream.finish().await?;
        return Ok(());
    }

    let resp = http::Response::builder()
        .status(233)
        .header("Hysteria-UDP", (!config.disable_udp).to_string())
        .header("Hysteria-CC-RX", hysteria2_cc_rx(&config))
        .body(())
        .unwrap();
    stream.send_response(resp).await?;

    info!("{peer} Hysteria2 auth accepted");
    handle_hysteria2_raw_connection(raw_conn, config).await?;
    Ok(())
}

fn matches_hysteria2_auth(
    request: &http::Request<()>,
    config: &Hysteria2Config,
) -> Result<bool, H2Error> {
    if request.method() != http::Method::POST || request.uri().path() != "/auth" {
        return Ok(false);
    }
    let auth = match request.headers().get("Hysteria-Auth") {
        Some(value) => value.to_str()?.to_string(),
        None => return Ok(false),
    };
    Ok(config
        .password_auths
        .iter()
        .any(|expected| expected == &auth))
}

fn hysteria2_cc_rx(config: &Hysteria2Config) -> String {
    if config.ignore_client_bandwidth {
        return "auto".to_string();
    }
    match config.down_mbps {
        Some(mbps) => (mbps.saturating_mul(125_000)).to_string(),
        None => "auto".to_string(),
    }
}

async fn handle_hysteria2_raw_connection(
    conn: QuinnConnection,
    config: Hysteria2Config,
) -> Result<(), H2Error> {
    let udp_sessions: Arc<tokio::sync::Mutex<HashMap<u32, Arc<Hysteria2UdpSession>>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let tcp_conn = conn.clone();
    let udp_conn = conn.clone();
    let udp_sessions_for_loop = Arc::clone(&udp_sessions);
    let udp_config = config.clone();

    let tcp_task = tokio::spawn(async move { drive_hysteria2_tcp(tcp_conn).await });
    let udp_task = tokio::spawn(async move {
        if udp_config.disable_udp {
            discard_hysteria2_datagrams(udp_conn).await
        } else {
            drive_hysteria2_udp(udp_conn, udp_sessions_for_loop, udp_config).await
        }
    });

    let (tcp_result, udp_result) = tokio::join!(tcp_task, udp_task);
    match tcp_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(format!("hysteria2 tcp task panic: {e}").into()),
    }
    match udp_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(format!("hysteria2 udp task panic: {e}").into()),
    }
    Ok(())
}

async fn drive_hysteria2_tcp(conn: QuinnConnection) -> Result<(), H2Error> {
    while let Ok((send, recv)) = conn.accept_bi().await {
        tokio::spawn(async move {
            if let Err(e) = handle_hysteria2_tcp_stream(send, recv).await {
                warn!("Hysteria2 TCP stream error: {e}");
            }
        });
    }
    Ok(())
}

async fn handle_hysteria2_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), H2Error> {
    let (address, initial_body) = read_hysteria2_tcp_request(&mut recv).await?;
    let target = match TcpStream::connect(&address).await {
        Ok(stream) => stream,
        Err(e) => {
            let msg = e.to_string();
            write_hysteria2_tcp_response(&mut send, 1, &msg).await?;
            return Ok(());
        }
    };
    target.set_nodelay(true)?;
    write_hysteria2_tcp_response(&mut send, 0, "OK").await?;

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

async fn write_hysteria2_tcp_response(
    send: &mut quinn::SendStream,
    status: u8,
    message: &str,
) -> Result<(), H2Error> {
    let mut resp = Vec::with_capacity(message.len() + 16);
    resp.push(status);
    resp.extend_from_slice(&encode_quic_varint(message.len() as u64)?);
    resp.extend_from_slice(message.as_bytes());
    resp.extend_from_slice(&encode_quic_varint(0)?);
    send.write_all(&resp).await?;
    Ok(())
}

async fn read_hysteria2_tcp_request(
    recv: &mut quinn::RecvStream,
) -> Result<(String, Vec<u8>), H2Error> {
    let mut buf = BytesMut::new();
    let mut tmp = [0u8; 4096];
    loop {
        match try_parse_hysteria2_tcp_request(&buf)? {
            Some((address, consumed)) => {
                let remaining = buf.split_off(consumed);
                return Ok((address, remaining.to_vec()));
            }
            None => {
                let n = recv.read(&mut tmp).await?;
                let Some(n) = n else {
                    return Err("Hysteria2 closed before TCP request header".into());
                };
                if n == 0 {
                    return Err("Hysteria2 closed before TCP request header".into());
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 64 * 1024 {
                    return Err("Hysteria2 TCP request too large".into());
                }
            }
        }
    }
}

fn try_parse_hysteria2_tcp_request(buf: &[u8]) -> Result<Option<(String, usize)>, H2Error> {
    let mut pos = 0usize;
    let Some(cmd) = read_quic_varint(buf, &mut pos)? else {
        return Ok(None);
    };
    if cmd != 0x401 {
        return Err(format!("unexpected Hysteria2 TCP request id: {cmd:#x}").into());
    }
    let Some(addr_len) = read_quic_varint(buf, &mut pos)? else {
        return Ok(None);
    };
    let addr_len = addr_len as usize;
    if buf.len() < pos + addr_len {
        return Ok(None);
    }
    let address = std::str::from_utf8(&buf[pos..pos + addr_len])?.to_string();
    pos += addr_len;
    let Some(padding_len) = read_quic_varint(buf, &mut pos)? else {
        return Ok(None);
    };
    let padding_len = padding_len as usize;
    if buf.len() < pos + padding_len {
        return Ok(None);
    }
    pos += padding_len;
    Ok(Some((address, pos)))
}

async fn drive_hysteria2_udp(
    conn: QuinnConnection,
    sessions: Arc<tokio::sync::Mutex<HashMap<u32, Arc<Hysteria2UdpSession>>>>,
    config: Hysteria2Config,
) -> Result<(), H2Error> {
    let mut assemblies: HashMap<(u32, u16), Hysteria2UdpAssembly> = HashMap::new();
    loop {
        let datagram = conn.read_datagram().await?;
        let (session_id, packet_id, fragment_id, fragment_count, address, payload) =
            parse_hysteria2_udp_message(datagram.as_ref())?;
        let payload = if fragment_count <= 1 {
            payload
        } else {
            let assembly = assemblies
                .entry((session_id, packet_id))
                .or_insert_with(|| Hysteria2UdpAssembly::new(fragment_count));
            assembly.insert(fragment_id, payload)?;
            match assembly.is_complete() {
                true => assembly.take_payload()?,
                false => continue,
            }
        };
        let session = {
            let mut guard = sessions.lock().await;
            if let Some(session) = guard.get(&session_id) {
                Arc::clone(session)
            } else {
                let session = Arc::new(Hysteria2UdpSession::new(conn.clone(), session_id).await?);
                guard.insert(session_id, Arc::clone(&session));
                session
            }
        };
        session.send_payload(&address, payload).await?;
        if config.disable_udp {
            continue;
        }
    }
}

async fn discard_hysteria2_datagrams(conn: QuinnConnection) -> Result<(), H2Error> {
    loop {
        let _ = conn.read_datagram().await?;
    }
}

struct Hysteria2UdpSession {
    ipv4: Arc<UdpSocket>,
    ipv6: Option<Arc<UdpSocket>>,
}

impl Hysteria2UdpSession {
    async fn new(conn: QuinnConnection, session_id: u32) -> Result<Self, H2Error> {
        let ipv4 = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let ipv6 = match UdpSocket::bind("[::]:0").await {
            Ok(socket) => Some(Arc::new(socket)),
            Err(_) => None,
        };
        spawn_hysteria2_udp_response_loop(conn.clone(), session_id, Arc::clone(&ipv4));
        if let Some(ref ipv6_socket) = ipv6 {
            spawn_hysteria2_udp_response_loop(conn.clone(), session_id, Arc::clone(ipv6_socket));
        }
        Ok(Self { ipv4, ipv6 })
    }

    async fn send_payload(&self, address: &str, payload: Vec<u8>) -> Result<(), H2Error> {
        let (host, port) = split_host_port(address)?;
        let mut targets = lookup_host((host, port)).await?;
        let target = targets
            .next()
            .ok_or_else(|| format!("DNS resolution failed for {address}"))?;
        let socket = if target.is_ipv4() {
            &self.ipv4
        } else {
            self.ipv6.as_ref().ok_or("IPv6 UDP socket unavailable")?
        };
        socket.send_to(&payload, target).await?;
        Ok(())
    }
}

fn spawn_hysteria2_udp_response_loop(
    conn: QuinnConnection,
    session_id: u32,
    socket: Arc<UdpSocket>,
) {
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let (n, source) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let (address, port) = super::socket_addr_to_destination(source);
            let address = format!("{address}:{port}");
            let packet =
                match encode_hysteria2_udp_message(session_id, 0, 0, 1, &address, &buf[..n]) {
                    Ok(packet) => packet,
                    Err(_) => break,
                };
            if conn.send_datagram(Bytes::from(packet)).is_err() {
                break;
            }
        }
    });
}

struct Hysteria2UdpAssembly {
    fragments: Vec<Option<Vec<u8>>>,
}

impl Hysteria2UdpAssembly {
    fn new(fragment_count: u8) -> Self {
        Self {
            fragments: vec![None; fragment_count as usize],
        }
    }

    fn insert(&mut self, fragment_id: u8, payload: Vec<u8>) -> Result<(), H2Error> {
        let idx = fragment_id as usize;
        if idx >= self.fragments.len() {
            return Err("invalid Hysteria2 fragment id".into());
        }
        self.fragments[idx] = Some(payload);
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.fragments.iter().all(Option::is_some)
    }

    fn take_payload(&mut self) -> Result<Vec<u8>, H2Error> {
        let mut out = Vec::new();
        for fragment in self.fragments.iter_mut() {
            out.extend_from_slice(
                fragment
                    .take()
                    .as_deref()
                    .ok_or("missing Hysteria2 fragment")?,
            );
        }
        Ok(out)
    }
}

fn parse_hysteria2_udp_message(packet: &[u8]) -> Result<H2UdpMessage, H2Error> {
    if packet.len() < 8 {
        return Err("Hysteria2 UDP packet too short".into());
    }
    let session_id = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
    let packet_id = u16::from_be_bytes([packet[4], packet[5]]);
    let fragment_id = packet[6];
    let fragment_count = packet[7];
    let mut pos = 8usize;
    let Some(addr_len) = read_quic_varint(packet, &mut pos)? else {
        return Err("Hysteria2 UDP packet missing address length".into());
    };
    let addr_len = addr_len as usize;
    if packet.len() < pos + addr_len {
        return Err("Hysteria2 UDP packet truncated address".into());
    }
    let address = std::str::from_utf8(&packet[pos..pos + addr_len])?.to_string();
    pos += addr_len;
    Ok((
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        address,
        packet[pos..].to_vec(),
    ))
}

fn encode_hysteria2_udp_message(
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    address: &str,
    payload: &[u8],
) -> Result<Vec<u8>, H2Error> {
    let mut out = Vec::with_capacity(8 + address.len() + payload.len() + 16);
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(fragment_id);
    out.push(fragment_count);
    out.extend_from_slice(&encode_quic_varint(address.len() as u64)?);
    out.extend_from_slice(address.as_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn split_host_port(s: &str) -> Result<(&str, u16), H2Error> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find("]:").ok_or("invalid IPv6 host:port")?;
        let host = &rest[..end];
        let port = rest[end + 2..].parse::<u16>()?;
        return Ok((host, port));
    }
    let (host, port) = s.rsplit_once(':').ok_or("missing port")?;
    Ok((host, port.parse::<u16>()?))
}

fn read_quic_varint(buf: &[u8], pos: &mut usize) -> Result<Option<u64>, H2Error> {
    if *pos >= buf.len() {
        return Ok(None);
    }
    let first = buf[*pos];
    let len = 1usize << (first >> 6);
    if buf.len() < *pos + len {
        return Ok(None);
    }
    let value = match len {
        1 => (first & 0x3f) as u64,
        2 => u16::from_be_bytes([buf[*pos], buf[*pos + 1]]) as u64 & 0x3fff,
        4 => {
            u32::from_be_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]) as u64
                & 0x3fff_ffff
        }
        8 => {
            u64::from_be_bytes([
                buf[*pos],
                buf[*pos + 1],
                buf[*pos + 2],
                buf[*pos + 3],
                buf[*pos + 4],
                buf[*pos + 5],
                buf[*pos + 6],
                buf[*pos + 7],
            ]) & 0x3fff_ffff_ffff_ffff
        }
        _ => unreachable!(),
    };
    *pos += len;
    Ok(Some(value))
}

fn encode_quic_varint(value: u64) -> Result<Vec<u8>, H2Error> {
    let out = if value < (1 << 6) {
        vec![value as u8]
    } else if value < (1 << 14) {
        let val = 0x4000 | value as u16;
        val.to_be_bytes().to_vec()
    } else if value < (1 << 30) {
        let val = 0x8000_0000 | value as u32;
        val.to_be_bytes().to_vec()
    } else if value < (1 << 62) {
        let val = 0xC000_0000_0000_0000 | value;
        val.to_be_bytes().to_vec()
    } else {
        return Err("quic varint too large".into());
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static RUSTLS_PROVIDER: Once = Once::new();

    fn ensure_rustls_provider() {
        RUSTLS_PROVIDER.call_once(|| {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .expect("install rustls crypto provider");
        });
    }

    fn test_config() -> Hysteria2Config {
        ensure_rustls_provider();
        let (cert, key) = wrongsv_anytls::generate_self_signed_cert().unwrap();
        let tls = build_hysteria2_tls_config(&cert, &key).unwrap();
        Hysteria2Config {
            password_auths: vec!["secret".into(), "alice:password".into()],
            quic_config: build_hysteria2_quic_config(tls).unwrap(),
            disable_udp: false,
            down_mbps: Some(100),
            ignore_client_bandwidth: false,
        }
    }

    #[test]
    fn hysteria2_varint_roundtrip() {
        for value in [0, 63, 64, 16_383, 16_384, 1 << 20, 1 << 30] {
            let encoded = encode_quic_varint(value).unwrap();
            let mut pos = 0;
            let decoded = read_quic_varint(&encoded, &mut pos).unwrap().unwrap();
            assert_eq!(decoded, value);
            assert_eq!(pos, encoded.len());
        }
    }

    #[test]
    fn hysteria2_tcp_request_parser() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_quic_varint(0x401).unwrap());
        buf.extend_from_slice(&encode_quic_varint(12).unwrap());
        buf.extend_from_slice(b"127.0.0.1:53");
        buf.extend_from_slice(&encode_quic_varint(0).unwrap());
        buf.extend_from_slice(b"payload");
        let parsed = try_parse_hysteria2_tcp_request(&buf).unwrap().unwrap();
        assert_eq!(parsed.0, "127.0.0.1:53");
        assert_eq!(parsed.1, buf.len() - 7);
    }

    #[test]
    fn hysteria2_udp_message_roundtrips() {
        let packet = encode_hysteria2_udp_message(7, 9, 0, 1, "127.0.0.1:53", b"hello").unwrap();
        let parsed = parse_hysteria2_udp_message(&packet).unwrap();
        assert_eq!(parsed.0, 7);
        assert_eq!(parsed.1, 9);
        assert_eq!(parsed.4, "127.0.0.1:53");
        assert_eq!(parsed.5, b"hello");
    }

    #[test]
    fn hysteria2_auth_matches_exact_passwords() {
        let config = test_config();
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("/auth")
            .header("Hysteria-Auth", "alice:password")
            .body(())
            .unwrap();
        assert!(matches_hysteria2_auth(&request, &config).unwrap());
    }

    fn build_root_store(cert_pem: &str) -> rustls::RootCertStore {
        ensure_rustls_provider();
        let mut reader = std::io::Cursor::new(cert_pem.as_bytes());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        let _ = roots.add_parsable_certificates(certs);
        roots
    }

    async fn build_hysteria2_test_client(
        cert_pem: &str,
        server_addr: SocketAddr,
    ) -> Result<(quinn::Endpoint, QuinnConnection), H2Error> {
        let roots = build_root_store(cert_pem);
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];
        let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| std::io::Error::other(format!("client crypto: {e}")))?;
        let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
        let mut endpoint = quinn::Endpoint::client("[::]:0".parse()?)?;
        endpoint.set_default_client_config(client_config);
        let conn = endpoint.connect(server_addr, "foo.cloudfront.net")?.await?;
        Ok((endpoint, conn))
    }

    async fn authenticate_hysteria2(
        cert_pem: &str,
        server_addr: SocketAddr,
        auth: &str,
    ) -> Result<(quinn::Endpoint, QuinnConnection), H2Error> {
        let (endpoint, conn) = build_hysteria2_test_client(cert_pem, server_addr).await?;
        let h3_conn = H3QuinnConnection::new(conn.clone());
        let mut builder = h3::client::builder();
        builder.enable_datagram(true);
        let (_h3_conn, mut send_request) = builder.build::<_, _, Bytes>(h3_conn).await?;
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://foo.cloudfront.net/auth")
            .header("Hysteria-Auth", auth)
            .header("Hysteria-CC-RX", "1000")
            .body(())
            .unwrap();
        let mut req_stream = send_request.send_request(request).await?;
        req_stream.finish().await?;
        let response = req_stream.recv_response().await?;
        assert_eq!(response.status(), 233);
        assert_eq!(
            response
                .headers()
                .get("Hysteria-UDP")
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            response
                .headers()
                .get("Hysteria-CC-RX")
                .and_then(|v| v.to_str().ok()),
            Some("12500000")
        );
        Ok((endpoint, conn))
    }

    async fn read_quic_varint_from_stream(recv: &mut quinn::RecvStream) -> Result<u64, H2Error> {
        let mut first = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(recv, &mut first).await?;
        let len = 1usize << (first[0] >> 6);
        let mut buf = vec![0u8; len];
        buf[0] = first[0];
        if len > 1 {
            tokio::io::AsyncReadExt::read_exact(recv, &mut buf[1..]).await?;
        }
        let mut pos = 0usize;
        read_quic_varint(&buf, &mut pos)?.ok_or_else(|| "missing varint".into())
    }

    async fn read_hysteria2_tcp_response(
        recv: &mut quinn::RecvStream,
    ) -> Result<(bool, String), H2Error> {
        let mut status = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(recv, &mut status).await?;
        let msg_len = read_quic_varint_from_stream(recv).await? as usize;
        let mut msg = vec![0u8; msg_len];
        if msg_len > 0 {
            tokio::io::AsyncReadExt::read_exact(recv, &mut msg).await?;
        }
        let pad_len = read_quic_varint_from_stream(recv).await? as usize;
        if pad_len > 0 {
            let mut padding = vec![0u8; pad_len];
            tokio::io::AsyncReadExt::read_exact(recv, &mut padding).await?;
        }
        Ok((status[0] == 0, String::from_utf8(msg)?))
    }

    async fn spawn_hysteria2_test_server(
        config: Hysteria2Config,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), H2Error> {
        let endpoint = create_hysteria2_endpoint("127.0.0.1:0", &config)?;
        let addr = endpoint.local_addr()?;
        let handle = tokio::spawn(async move {
            let endpoint = endpoint;
            while let Some(incoming) = endpoint.accept().await {
                let cfg = config.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        let _ = handle_hysteria2_connection(conn, cfg).await;
                    }
                });
            }
        });
        Ok((addr, handle))
    }

    async fn spawn_tcp_echo_server() -> Result<(SocketAddr, tokio::task::JoinHandle<()>), H2Error> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = match tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if tokio::io::AsyncWriteExt::write_all(&mut socket, &buf[..n])
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
        Ok((addr, handle))
    }

    async fn spawn_udp_echo_server() -> Result<(SocketAddr, tokio::task::JoinHandle<()>), H2Error> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if socket.send_to(&buf[..n], peer).await.is_err() {
                    break;
                }
            }
        });
        Ok((addr, handle))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hysteria2_tcp_relay_roundtrip() -> Result<(), H2Error> {
        ensure_rustls_provider();
        let (cert, key) = wrongsv_anytls::generate_self_signed_cert().unwrap();
        let tls = build_hysteria2_tls_config(&cert, &key).unwrap();
        let config = Hysteria2Config {
            password_auths: vec!["secret".into()],
            quic_config: build_hysteria2_quic_config(tls).unwrap(),
            disable_udp: false,
            down_mbps: Some(100),
            ignore_client_bandwidth: false,
        };
        let (echo_addr, echo_handle) = spawn_tcp_echo_server().await?;
        let (server_addr, server_handle) = spawn_hysteria2_test_server(config).await?;
        let (_endpoint, conn) = authenticate_hysteria2(&cert, server_addr, "secret").await?;

        let (mut send, mut recv) = conn.open_bi().await?;
        let mut req = Vec::new();
        req.extend_from_slice(&encode_quic_varint(0x401)?);
        let target = format!("{echo_addr}");
        req.extend_from_slice(&encode_quic_varint(target.len() as u64)?);
        req.extend_from_slice(target.as_bytes());
        req.extend_from_slice(&encode_quic_varint(0)?);
        send.write_all(&req).await?;
        send.flush().await?;

        let (ok, message) = read_hysteria2_tcp_response(&mut recv).await?;
        assert!(ok, "{message}");

        send.write_all(b"ping").await?;
        send.flush().await?;
        let mut echoed = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut recv, &mut echoed).await?;
        assert_eq!(&echoed, b"ping");

        server_handle.abort();
        echo_handle.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hysteria2_udp_relay_roundtrip() -> Result<(), H2Error> {
        ensure_rustls_provider();
        let (cert, key) = wrongsv_anytls::generate_self_signed_cert().unwrap();
        let tls = build_hysteria2_tls_config(&cert, &key).unwrap();
        let config = Hysteria2Config {
            password_auths: vec!["secret".into()],
            quic_config: build_hysteria2_quic_config(tls).unwrap(),
            disable_udp: false,
            down_mbps: Some(100),
            ignore_client_bandwidth: false,
        };
        let (echo_addr, echo_handle) = spawn_udp_echo_server().await?;
        let (server_addr, server_handle) = spawn_hysteria2_test_server(config).await?;
        let (_endpoint, conn) = authenticate_hysteria2(&cert, server_addr, "secret").await?;

        let session_id = 42u32;
        let packet =
            encode_hysteria2_udp_message(session_id, 1, 0, 1, &format!("{echo_addr}"), b"pong")?;
        conn.send_datagram(Bytes::from(packet))?;
        let datagram = tokio::time::timeout(Duration::from_secs(2), conn.read_datagram())
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "udp timeout"))??;
        let parsed = parse_hysteria2_udp_message(datagram.as_ref())?;
        assert_eq!(parsed.0, session_id);
        assert_eq!(parsed.5, b"pong");

        server_handle.abort();
        echo_handle.abort();
        Ok(())
    }
}
