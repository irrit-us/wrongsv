use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;
use tracing::{debug, info, trace, warn};

use super::*;

pub(crate) fn parse_shadowsocks_config(
    sc: &crate::config::ShadowsocksServerConfig,
) -> Result<wrongsv_shadowsocks::ServerConfig, String> {
    wrongsv_shadowsocks::ServerConfig::new_with_prefixes(
        &sc.method,
        sc.password.clone(),
        sc.tcp_prefix
            .as_deref()
            .map(str::as_bytes)
            .unwrap_or_default()
            .to_vec(),
        sc.udp_prefix
            .as_deref()
            .map(str::as_bytes)
            .unwrap_or_default()
            .to_vec(),
    )
    .map_err(|e| format!("shadowsocks: {e}"))
}
pub(crate) fn drain_shadowsocks_udp(
    socket: &UdpSocket,
    config: &wrongsv_shadowsocks::ServerConfig,
) {
    loop {
        let mut packet = vec![0u8; 65535];
        match socket.recv_from(&mut packet) {
            Ok((n, client_addr)) => {
                packet.truncate(n);
                let response_socket = match socket.try_clone() {
                    Ok(socket) => socket,
                    Err(e) => {
                        warn!("Shadowsocks UDP socket clone failed: {e}");
                        continue;
                    }
                };
                let config = config.clone();
                thread::spawn(move || {
                    if let Err(e) =
                        handle_shadowsocks_udp_packet(response_socket, client_addr, packet, config)
                    {
                        warn!("Shadowsocks UDP packet error: {e}");
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => {
                warn!("Shadowsocks UDP recv error: {e}");
                break;
            }
        }
    }
}

pub(crate) fn handle_shadowsocks_udp_packet(
    socket: UdpSocket,
    client_addr: SocketAddr,
    packet: Vec<u8>,
    config: wrongsv_shadowsocks::ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.method.is_aead_2022() {
        return handle_shadowsocks_aead_2022_udp_packet(socket, client_addr, packet, config);
    }

    let plaintext = wrongsv_shadowsocks::decrypt_udp_packet(&packet, &config)?;
    let (address, port, consumed) = wrongsv_shadowsocks::parse_request_header(&plaintext)?;
    let payload = plaintext
        .get(consumed..)
        .ok_or_else(|| std::io::Error::other("invalid Shadowsocks UDP payload offset"))?;
    if payload.is_empty() {
        return Ok(());
    }

    let target_addr = format!("{address}:{port}");
    debug!(
        "{client_addr} Shadowsocks UDP -> {target_addr} ({}B)",
        payload.len()
    );
    let (response_addr, response_payload) = send_udp_datagram_to_target(&address, port, payload)?;
    let (response_address, response_port) = socket_addr_to_destination(response_addr);

    let mut response_plaintext = Vec::with_capacity(32 + response_payload.len());
    wrongsv_shadowsocks::write_request_header(
        &mut response_plaintext,
        &response_address,
        response_port,
    );
    response_plaintext.extend_from_slice(&response_payload);
    let response_packet = wrongsv_shadowsocks::encrypt_udp_packet(&response_plaintext, &config)?;
    socket.send_to(&response_packet, client_addr)?;
    Ok(())
}

pub(crate) fn handle_shadowsocks_aead_2022_udp_packet(
    socket: UdpSocket,
    client_addr: SocketAddr,
    packet: Vec<u8>,
    config: wrongsv_shadowsocks::ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = wrongsv_shadowsocks::decrypt_aead_2022_udp_request(&packet, &config)?;
    let response_context =
        config.accept_aead_2022_udp_packet(request.client_session_id, request.packet_id)?;
    if request.payload.is_empty() {
        return Ok(());
    }

    let target_addr = format!("{}:{}", request.address, request.port);
    debug!(
        "{client_addr} Shadowsocks AEAD-2022 UDP -> {target_addr} ({}B)",
        request.payload.len()
    );
    let (response_addr, response_payload) =
        send_udp_datagram_to_target(&request.address, request.port, &request.payload)?;
    let (response_address, response_port) = socket_addr_to_destination(response_addr);
    let response_packet = wrongsv_shadowsocks::encrypt_aead_2022_udp_response(
        &config,
        response_context.server_session_id,
        response_context.packet_id,
        request.client_session_id,
        &response_address,
        response_port,
        &response_payload,
    )?;
    socket.send_to(&response_packet, client_addr)?;
    Ok(())
}
pub(crate) fn handle_shadowsocks_connection(
    stream: TcpStream,
    config: &wrongsv_shadowsocks::ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} Shadowsocks connection");

    // Bound the salt + request-header read so a slowloris peer can't
    // park a thread forever by connecting and sending nothing.
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let read_stream = stream.try_clone()?;
    let mut reader = wrongsv_shadowsocks::ShadowsocksReader::new(read_stream, config)?;
    let request_salt = reader.request_salt().map(Vec::from);
    let first = reader.read_chunk()?;
    let (address, port, consumed) = wrongsv_shadowsocks::parse_request_header(&first)?;
    let remaining = if consumed < first.len() {
        first[consumed..].to_vec()
    } else {
        Vec::new()
    };

    let target_addr = format!("{address}:{port}");
    info!("{peer} Shadowsocks TCP -> {target_addr}");
    let target = TcpStream::connect(&target_addr)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(2)))?;
    // Relay phase manages its own per-side deadlines; clear the handshake bound.
    stream.set_read_timeout(None)?;

    relay_shadowsocks(
        reader,
        stream,
        target,
        config.clone(),
        request_salt,
        remaining,
    )?;
    debug!("{peer} Shadowsocks relay finished");
    Ok(())
}

pub(crate) fn relay_shadowsocks(
    mut reader: wrongsv_shadowsocks::ShadowsocksReader<TcpStream>,
    client_writer: TcpStream,
    target: TcpStream,
    config: wrongsv_shadowsocks::ServerConfig,
    request_salt: Option<Vec<u8>>,
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut target_writer = target.try_clone()?;
    let mut target_reader = target;
    let mut writer = wrongsv_shadowsocks::ShadowsocksWriter::new_response(
        client_writer,
        &config,
        request_salt.as_deref(),
    )?;

    if !initial_data.is_empty() {
        target_writer.write_all(&initial_data)?;
    }

    let t1 = thread::spawn(move || {
        loop {
            match reader.read_chunk() {
                Ok(data) if data.is_empty() => continue,
                Ok(data) => {
                    if target_writer.write_all(&data).is_err() {
                        break;
                    }
                }
                Err(wrongsv_shadowsocks::ShadowsocksError::Io(e))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    break;
                }
                Err(e) => {
                    debug!("Shadowsocks client read: {e}");
                    break;
                }
            }
        }
        let _ = target_writer.shutdown(Shutdown::Write);
    });

    let t2 = thread::spawn(move || {
        let mut buf = [0u8; 32768];
        loop {
            match target_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if writer.write_chunk(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = target_reader.set_read_timeout(Some(Duration::from_millis(10)));
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    let _ = target_reader.set_read_timeout(Some(Duration::from_secs(2)));
                }
                Err(e) => {
                    debug!("Shadowsocks target read: {e}");
                    break;
                }
            }
        }
    });

    t1.join().ok();
    t2.join().ok();
    Ok(())
}
