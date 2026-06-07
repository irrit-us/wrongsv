use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{debug, info, trace};

use crate::config::TrojanServerConfig;
use crate::trojan::{self, TrojanCommand};

use super::*;

pub(crate) fn parse_trojan_config(tc: &TrojanServerConfig) -> Result<trojan::TrojanConfig, String> {
    let (cert_pem, key_pem) = match (&tc.certificate, &tc.key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => {
            let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                .map_err(|e| format!("trojan cert: {e}"))?;
            (cert, key)
        }
    };
    let tls_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
        .map_err(|e| format!("trojan tls: {e}"))?;

    let mut password_hashes = Vec::new();
    if let Some(password) = &tc.password {
        password_hashes.push(trojan::password_hash_hex(password));
    }
    for user in &tc.users {
        password_hashes.push(trojan::password_hash_hex(&user.password));
    }

    Ok(trojan::TrojanConfig {
        password_hashes,
        tls_config: Arc::new(tls_config),
        dest: tc.dest.clone(),
    })
}
pub(crate) fn handle_trojan_connection(
    stream: TcpStream,
    config: &trojan::TrojanConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} Trojan connection");

    let mut tls_stream = trojan::accept_tls(stream, config)?;
    tls_stream
        .get_mut()
        .1
        .set_read_timeout(Some(Duration::from_secs(30)))?;
    info!("{peer} Trojan TLS handshake complete");

    let request = match trojan::read_request(&mut tls_stream, config) {
        Ok(request) => request,
        Err(accept_err) => {
            debug!("{peer} Trojan request rejected: {}", accept_err.error);
            if let Some(dest) = &config.dest {
                let target = TcpStream::connect(dest)?;
                target.set_nodelay(true)?;
                relay_anytls_raw(tls_stream, target, accept_err.buffered_data)?;
                return Ok(());
            }
            return Err(Box::new(accept_err.error));
        }
    };

    if request.command == TrojanCommand::UdpAssociate {
        info!("{peer} Trojan UDP associate");
        relay_trojan_udp(tls_stream, request.initial_data)?;
        debug!("{peer} Trojan UDP relay finished");
        return Ok(());
    }

    let target_addr = format!("{}:{}", request.address, request.port);
    info!("{peer} Trojan TCP -> {target_addr}");
    let target = connect_tcp_target(&request.address, request.port)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(60)))?;

    relay_anytls_raw(tls_stream, target, request.initial_data)?;
    debug!("{peer} Trojan TCP relay finished");
    Ok(())
}

pub(crate) fn relay_trojan_udp(
    mut tls: wrongsv_anytls::AnyTlsStream,
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;

    let mut tls_buf = initial_data;
    let mut udp_buf = [0u8; 65535];
    let mut client_closed = false;
    let (conn, stream) = tls.get_mut();
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;

    loop {
        let mut did_work = false;

        while let Some(packet) = trojan::parse_udp_packet(&tls_buf)? {
            send_trojan_udp_packet_to_target(
                &socket,
                &packet.address,
                packet.port,
                &packet.payload,
            )?;
            tls_buf.drain(..packet.consumed);
            did_work = true;
        }

        match socket.recv_from(&mut udp_buf) {
            Ok((n, source)) if n > 0 => {
                let (address, port) = socket_addr_to_destination(source);
                let mut response = Vec::with_capacity(32 + n);
                trojan::write_udp_packet(&mut response, &address, port, &udp_buf[..n])?;
                conn.writer().write_all(&response)?;
                while conn.wants_write() {
                    conn.write_tls(stream)?;
                }
                did_work = true;
            }
            Ok(_) => {}
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e.into()),
        }

        if !client_closed {
            let mut tmp = [0u8; 8192];
            match conn.reader().read(&mut tmp) {
                Ok(n) if n > 0 => {
                    tls_buf.extend_from_slice(&tmp[..n]);
                    did_work = true;
                }
                Ok(_) => match conn.read_tls(stream) {
                    Ok(0) => {
                        client_closed = true;
                        did_work = true;
                    }
                    Ok(_) => {
                        conn.process_new_packets()
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        did_work = true;
                    }
                    Err(ref e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(e) => return Err(e.into()),
                },
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    match conn.read_tls(stream) {
                        Ok(0) => {
                            client_closed = true;
                            did_work = true;
                        }
                        Ok(_) => {
                            conn.process_new_packets().map_err(|e| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                            })?;
                            did_work = true;
                        }
                        Err(ref e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }

        if client_closed && !did_work {
            break;
        }
        if !did_work {
            thread::sleep(Duration::from_millis(20));
        }
    }

    Ok(())
}

pub(crate) fn send_trojan_udp_packet_to_target(
    socket: &UdpSocket,
    address: &wrongsv_net_types::Address,
    port: wrongsv_net_types::Port,
    payload: &[u8],
) -> std::io::Result<()> {
    let target_addr = format!("{address}:{port}");
    let mut last_error = None;
    for addr in target_addr.to_socket_addrs()? {
        match socket.send_to(payload, addr) {
            Ok(_) => return Ok(()),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::other(format!("DNS resolution failed for {target_addr}"))
    }))
}
