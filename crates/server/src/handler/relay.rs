use std::io::{Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tracing::debug;
use wrongsv_protocol::RequestHeader;
use wrongsv_vless::vision::{TrafficState, VisionReader, VisionWriter};
use wrongsv_vless_encoding::{LengthPacketReader, LengthPacketWriter, PacketReadError};

use crate::mixed_proxy::MixedProtocol;

pub(crate) const PACKETADDR_MAGIC_DOMAIN: &str = "sp.packet-addr.v2fly.arpa";

pub(crate) fn is_packetaddr_request(request: &RequestHeader) -> bool {
    matches!(
        &request.address,
        wrongsv_net_types::Address::Domain(domain) if domain == PACKETADDR_MAGIC_DOMAIN
    )
}

pub(crate) fn encode_packetaddr_payload(
    address: &wrongsv_net_types::Address,
    port: wrongsv_net_types::Port,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut packet = Vec::with_capacity(1 + 16 + 2 + payload.len());
    match address {
        wrongsv_net_types::Address::IPv4(raw) => {
            packet.push(0x01);
            packet.extend_from_slice(raw);
        }
        wrongsv_net_types::Address::IPv6(raw) => {
            packet.push(0x02);
            packet.extend_from_slice(raw);
        }
        wrongsv_net_types::Address::Domain(_) => {
            return Err("packetaddr does not support domain addresses".into());
        }
    }
    packet.extend_from_slice(&port.0.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub(crate) fn decode_packetaddr_payload(
    packet: &[u8],
) -> Result<
    (wrongsv_net_types::Address, wrongsv_net_types::Port, Vec<u8>),
    Box<dyn std::error::Error>,
> {
    if packet.is_empty() {
        return Err("empty packetaddr packet".into());
    }

    let mut pos = 1;
    let address = match packet[0] {
        0x01 => {
            if packet.len() < pos + 4 + 2 {
                return Err("short packetaddr IPv4 packet".into());
            }
            let mut raw = [0u8; 4];
            raw.copy_from_slice(&packet[pos..pos + 4]);
            pos += 4;
            wrongsv_net_types::Address::IPv4(raw)
        }
        0x02 => {
            if packet.len() < pos + 16 + 2 {
                return Err("short packetaddr IPv6 packet".into());
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&packet[pos..pos + 16]);
            pos += 16;
            wrongsv_net_types::Address::IPv6(raw)
        }
        other => return Err(format!("unsupported packetaddr address type: {other:#04x}").into()),
    };

    let port = wrongsv_net_types::Port(u16::from_be_bytes([packet[pos], packet[pos + 1]]));
    pos += 2;
    Ok((address, port, packet[pos..].to_vec()))
}

pub(crate) fn bind_packetaddr_sockets() -> std::io::Result<(UdpSocket, Option<UdpSocket>)> {
    let ipv4 = UdpSocket::bind("0.0.0.0:0")?;
    let ipv6 = UdpSocket::bind("[::]:0").ok();
    Ok((ipv4, ipv6))
}

pub(crate) fn send_packetaddr_datagram(
    ipv4: &UdpSocket,
    ipv6: Option<&UdpSocket>,
    address: &wrongsv_net_types::Address,
    port: wrongsv_net_types::Port,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    match address {
        wrongsv_net_types::Address::IPv4(raw) => {
            let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*raw)), port.0);
            ipv4.send_to(payload, target)?;
        }
        wrongsv_net_types::Address::IPv6(raw) => {
            let socket = ipv6.ok_or("IPv6 packetaddr socket is unavailable")?;
            let target = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*raw)), port.0);
            socket.send_to(payload, target)?;
        }
        wrongsv_net_types::Address::Domain(_) => {
            return Err("packetaddr does not support domain addresses".into());
        }
    }
    Ok(())
}

pub(crate) fn drain_packetaddr_packets(
    input: &mut Vec<u8>,
    ipv4: &UdpSocket,
    ipv6: Option<&UdpSocket>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut pos = 0;
    let mut sent = false;

    while input.len().saturating_sub(pos) >= 2 {
        let len = u16::from_be_bytes([input[pos], input[pos + 1]]) as usize;
        if input.len() - pos < len + 2 {
            break;
        }

        let packet_start = pos + 2;
        let packet_end = packet_start + len;
        let (address, port, payload) = decode_packetaddr_payload(&input[packet_start..packet_end])?;
        send_packetaddr_datagram(ipv4, ipv6, &address, port, &payload)?;
        sent = true;
        pos = packet_end;
    }

    if pos > 0 {
        input.drain(..pos);
    }

    Ok(sent)
}

pub(crate) fn flush_packetaddr_responses<W: Write>(
    writer: &mut W,
    socket: &UdpSocket,
    timeout: Duration,
) -> Result<bool, Box<dyn std::error::Error>> {
    socket.set_read_timeout(Some(timeout))?;
    let mut buf = [0u8; 65535];
    let mut wrote = false;

    loop {
        match socket.recv_from(&mut buf) {
            Ok((0, _)) => break,
            Ok((n, source)) => {
                let (address, port) = match source {
                    SocketAddr::V4(addr) => (
                        wrongsv_net_types::Address::IPv4(addr.ip().octets()),
                        wrongsv_net_types::Port(addr.port()),
                    ),
                    SocketAddr::V6(addr) => (
                        wrongsv_net_types::Address::IPv6(addr.ip().octets()),
                        wrongsv_net_types::Port(addr.port()),
                    ),
                };
                let packet = encode_packetaddr_payload(&address, port, &buf[..n])?;
                let mut framed = Vec::with_capacity(packet.len() + 2);
                LengthPacketWriter::new(&mut framed).write_packet(&packet)?;
                writer.write_all(&framed)?;
                writer.flush()?;
                wrote = true;
            }
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(wrote)
}

pub(crate) fn flush_packetaddr_socket_pair<W: Write>(
    writer: &mut W,
    ipv4: &UdpSocket,
    ipv6: Option<&UdpSocket>,
    timeout: Duration,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut wrote = flush_packetaddr_responses(writer, ipv4, timeout)?;
    if let Some(ipv6) = ipv6 {
        wrote |= flush_packetaddr_responses(writer, ipv6, Duration::from_millis(10))?;
    }
    Ok(wrote)
}

pub(crate) fn relay_packetaddr_udp_stream<S: Read + Write>(
    stream: &mut S,
    remaining: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (ipv4, ipv6) = bind_packetaddr_sockets()?;
    let mut input = remaining;
    let mut read_buf = [0u8; 32768];

    loop {
        let mut did_work = false;

        if drain_packetaddr_packets(&mut input, &ipv4, ipv6.as_ref())? {
            did_work = true;
            if flush_packetaddr_socket_pair(
                stream,
                &ipv4,
                ipv6.as_ref(),
                Duration::from_millis(500),
            )? {
                did_work = true;
            }
        }

        if flush_packetaddr_socket_pair(stream, &ipv4, ipv6.as_ref(), Duration::from_millis(10))? {
            did_work = true;
        }

        match stream.read(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => {
                input.extend_from_slice(&read_buf[..n]);
                did_work = true;
            }
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        if !did_work {
            thread::sleep(Duration::from_millis(20));
        }
    }

    Ok(())
}

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
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut c2 = client.try_clone()?;
    let mut t2 = target.try_clone()?;
    let metrics_up = metrics.clone();
    let metrics_down = metrics;

    let t1 = thread::spawn(move || {
        let mut buf = [0u8; 32768];
        loop {
            match c2.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    metrics_up.record_in(n as u64);
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
                    metrics_down.record_out(n as u64);
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
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    if !initial_data.is_empty() {
        metrics.record_in(initial_data.len() as u64);
        target.write_all(&initial_data)?;
    }
    relay_raw(client, target, metrics)
}

pub(crate) fn relay_udp(
    mut client: TcpStream,
    request: &RequestHeader,
    remaining: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    if is_packetaddr_request(request) {
        debug!("packetaddr UDP relay, {} remaining bytes", remaining.len());
        client.set_read_timeout(Some(Duration::from_millis(200)))?;
        return relay_packetaddr_udp_stream(&mut client, remaining);
    }

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

    let metrics_up = metrics.clone();
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
                    metrics_up.record_in(pkt.len() as u64);
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

    let metrics_down = metrics;
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
                    metrics_down.record_out(n as u64);
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
    metrics: wrongsv_metrics::MetricsTap,
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
    let metrics_up = metrics.clone();

    let t1 = thread::spawn(move || {
        let mut reader = VisionReader::new(c_read, up_state, true);
        let mut buf = [0u8; 32768];
        let mut tgt = t_write;
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    metrics_up.record_in(n as u64);
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
    let metrics_down = metrics;
    let t2 = thread::spawn(move || {
        let mut writer = VisionWriter::new(c_write, down_state, false, up_seed);
        let mut buf = [0u8; 32768];
        let mut tgt = t_read;
        loop {
            match tgt.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    metrics_down.record_out(n as u64);
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
            reality: None,
            anytls: None,
            tls: None,
            shadowsocks: None,
            mixed: None,
            trojan: None,
            websocket: None,
            httpupgrade: None,
            grpc: None,
            xhttp: None,
            meek: None,
            gdocsviewer: None,
            wireguard: None,
            hysteria2: None,
            tuic: None,
            quic: None,
            kcp: None,
            webtransport: None,
            shadowtls: None,
            vmess: None,
            naive: None,
            snell: None,
            lua: None,
            masque: None,
            trusttunnel: None,
            brook: None,
            vlite: None,
            tor: None,
            ssh: None,
            juicity: None,
            mieru: None,
            sudoku: None,
            vless_encryption: None,
            shadowquic: None,
            anytls_reality: None,
            metrics: None,
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
        let addons = Addons { flow: XRV.into() };
        let body = b"pipelined-request-body";
        let peer: std::net::SocketAddr = "127.0.0.1:10000".parse().unwrap();

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
        let peer: std::net::SocketAddr = "127.0.0.1:10001".parse().unwrap();

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
    fn packetaddr_ipv4_payload_roundtrips() {
        let payload = b"packetaddr-ipv4";
        let encoded =
            encode_packetaddr_payload(&Address::IPv4([127, 0, 0, 1]), Port(5353), payload).unwrap();

        assert_eq!(&encoded[..7], &[0x01, 127, 0, 0, 1, 0x14, 0xe9]);

        let (address, port, decoded_payload) = decode_packetaddr_payload(&encoded).unwrap();
        assert_eq!(address, Address::IPv4([127, 0, 0, 1]));
        assert_eq!(port, Port(5353));
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn packetaddr_ipv6_payload_roundtrips() {
        let address = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let payload = b"packetaddr-ipv6";
        let encoded = encode_packetaddr_payload(&address, Port(443), payload).unwrap();

        assert_eq!(encoded[0], 0x02);
        assert_eq!(&encoded[17..19], &[0x01, 0xbb]);

        let (decoded_address, port, decoded_payload) = decode_packetaddr_payload(&encoded).unwrap();
        assert_eq!(decoded_address, address);
        assert_eq!(port, Port(443));
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn packetaddr_rejects_domain_payloads() {
        let err =
            encode_packetaddr_payload(&Address::Domain("example.com".into()), Port(53), b"dns")
                .unwrap_err();

        assert_eq!(
            err.to_string(),
            "packetaddr does not support domain addresses"
        );
    }

    #[test]
    fn packetaddr_magic_request_is_detected() {
        let mut request = test_request(test_user(""), RequestCommand::Udp);
        request.address = Address::Domain(PACKETADDR_MAGIC_DOMAIN.into());
        request.port = Port(0);

        assert!(is_packetaddr_request(&request));

        request.port = Port(53);
        assert!(is_packetaddr_request(&request));

        request.address = Address::Domain("example.com".into());
        assert!(!is_packetaddr_request(&request));
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
