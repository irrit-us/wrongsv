use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tracing::debug;
use wrongsv_protocol::RequestHeader;
use wrongsv_vless::vision::{TrafficState, VisionReader, VisionWriter};
use wrongsv_vless_encoding::{LengthPacketReader, LengthPacketWriter, PacketReadError};

use crate::mixed_proxy::MixedProtocol;

pub(crate) fn send_udp_datagram_to_target(
    address: &wrongsv_net_types::Address,
    port: wrongsv_net_types::Port,
    payload: &[u8],
) -> std::io::Result<(SocketAddr, Vec<u8>)> {
    let target_addr = format!("{address}:{port}");
    let mut last_error = None;
    for addr in target_addr.to_socket_addrs()? {
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = match UdpSocket::bind(bind_addr) {
            Ok(socket) => socket,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        if let Err(e) = socket.connect(addr) {
            last_error = Some(e);
            continue;
        }
        match socket.send(payload) {
            Ok(_) => {
                let mut buf = vec![0u8; 65535];
                match socket.recv(&mut buf) {
                    Ok(n) => {
                        buf.truncate(n);
                        return Ok((addr, buf));
                    }
                    Err(e) => last_error = Some(e),
                }
            }
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::other(format!("DNS resolution failed for {target_addr}"))
    }))
}

pub(crate) fn socket_addr_to_destination(
    addr: SocketAddr,
) -> (wrongsv_net_types::Address, wrongsv_net_types::Port) {
    let address = match addr.ip() {
        std::net::IpAddr::V4(ip) => wrongsv_net_types::Address::IPv4(ip.octets()),
        std::net::IpAddr::V6(ip) => wrongsv_net_types::Address::IPv6(ip.octets()),
    };
    (address, wrongsv_net_types::Port(addr.port()))
}
pub(crate) fn connect_tcp_target(
    address: &wrongsv_net_types::Address,
    port: wrongsv_net_types::Port,
) -> std::io::Result<TcpStream> {
    let target_addr = format!("{address}:{port}");
    let mut last_error = None;
    for addr in target_addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::other(format!("DNS resolution failed for {target_addr}"))
    }))
}

pub(crate) fn mixed_protocol_name(protocol: MixedProtocol) -> &'static str {
    match protocol {
        MixedProtocol::Socks4 => "SOCKS4/4A CONNECT",
        MixedProtocol::Socks5 => "SOCKS5 CONNECT",
        MixedProtocol::HttpConnect => "HTTP CONNECT",
        MixedProtocol::HttpForward => "HTTP FORWARD",
    }
}
pub(crate) fn relay_raw(
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

pub(crate) fn relay_raw_with_initial(
    client: TcpStream,
    mut target: TcpStream,
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !initial_data.is_empty() {
        target.write_all(&initial_data)?;
    }
    relay_raw(client, target)
}

pub(crate) fn relay_udp(
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

pub(crate) fn relay_vision(
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

#[cfg(test)]
use super::*;
#[cfg(test)]
use std::net::TcpListener;
#[cfg(test)]
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand};
#[cfg(test)]
use wrongsv_uuid::Uuid;
#[cfg(test)]
use wrongsv_vless::{MemoryValidator, XRV};
#[cfg(test)]
use wrongsv_vless_encoding::{self as encoding, Addons};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, UserConfig};
    use wrongsv_net_types::{Address, Port};

    const TEST_UUID: &str = "12345678-1234-1234-1234-123456789abc";

    fn test_config(listen: String) -> Config {
        Config {
            listen,
            users: vec![UserConfig {
                id: TEST_UUID.into(),
                email: "test@example.com".into(),
                flow: String::new(),
                encryption: String::new(),
                udp: true,
            }],
            decryption: None,
            flow: None,
            kyber_secret_key: None,
            reality: None,
            anytls: None,
            tls: None,
            shadowsocks: None,
            mixed: None,
            trojan: None,
            websocket: None,
        }
    }

    fn test_user(flow: &str) -> MemoryUser {
        let uuid = Uuid::parse_string(TEST_UUID).unwrap();
        MemoryUser {
            account: MemoryAccount {
                id: ID::new(uuid),
                flow: flow.into(),
                encryption: String::new(),
                udp: true,
                xor_mode: 0,
                seconds: 0,
                padding: String::new(),
                testpre: 0,
                testseed: vec![],
            },
            email: "test@example.com".into(),
            level: 0,
        }
    }

    fn test_validator(user: MemoryUser) -> Arc<MemoryValidator> {
        let validator = Arc::new(MemoryValidator::new());
        validator.add(user).unwrap();
        validator
    }

    fn test_request(user: MemoryUser, command: RequestCommand) -> RequestHeader {
        RequestHeader {
            version: 0,
            command,
            address: Address::parse("127.0.0.1"),
            port: Port(8080),
            user,
        }
    }

    #[test]
    fn decode_vless_request_preserves_body_and_detects_vision() {
        let user = test_user(XRV);
        let validator = test_validator(user.clone());
        let request = test_request(user, RequestCommand::Tcp);
        let addons = Addons {
            flow: XRV.into(),
            ..Default::default()
        };
        let body = b"pipelined-request-body";
        let peer = "127.0.0.1:10000".parse().unwrap();

        let mut first = bytes::BytesMut::new();
        encoding::encode_request_header(&mut first, &request, &addons).unwrap();
        first.extend_from_slice(body);

        let decoded = decode_vless_request(first.to_vec(), &validator, peer).unwrap();

        assert!(decoded.use_vision);
        assert_eq!(decoded.remaining_body, body);
        assert_eq!(decoded.decoded.header.command, RequestCommand::Tcp);
        assert_eq!(decoded.decoded.header.user.email, request.user.email);
    }

    #[test]
    fn decode_vless_request_rejects_short_headers() {
        let validator = test_validator(test_user(""));
        let peer = "127.0.0.1:10001".parse().unwrap();

        let err = match decode_vless_request(vec![0; 17], &validator, peer) {
            Ok(_) => panic!("short VLESS header decoded successfully"),
            Err(err) => err,
        };

        assert_eq!(err.to_string(), "connection too short for VLESS header");
    }

    #[test]
    fn validate_vless_command_rejects_udp_vision() {
        let request = test_request(test_user(XRV), RequestCommand::Udp);

        let err = validate_vless_command(&request, true).unwrap_err();

        assert_eq!(err.to_string(), "XTLS Vision does not support UDP");
    }

    #[test]
    fn response_header_buf_is_decode_compatible() {
        let request = test_request(test_user(""), RequestCommand::Tcp);
        let response = response_header_buf(&request).unwrap();
        let mut cursor = std::io::Cursor::new(response.as_ref());

        let addons = encoding::decode_response_header(&mut cursor, &request).unwrap();

        assert!(addons.flow.is_empty());
    }

    #[test]
    fn run_until_shutdown_releases_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap().to_string();
        let server = InboundServer::new(test_config(listen.clone())).unwrap();
        let shutdown = ShutdownSignal::new();
        let run_shutdown = shutdown.clone();

        let handle = thread::spawn(move || {
            server
                .run_with_listener(listener, run_shutdown)
                .map_err(|e| e.to_string())
        });
        thread::sleep(Duration::from_millis(50));
        shutdown.shutdown();

        handle.join().unwrap().unwrap();
        TcpListener::bind(&listen).unwrap();
    }

    #[test]
    fn server_handle_drop_releases_listener() {
        let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = reserve.local_addr().unwrap().to_string();
        drop(reserve);

        let server = InboundServer::new(test_config(listen.clone())).unwrap();
        let handle = server.spawn();
        thread::sleep(Duration::from_millis(250));
        drop(handle);

        TcpListener::bind(&listen).unwrap();
    }
}
