use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, trace, warn};
use wrongsv_protocol::{RequestCommand, RequestHeader};
use wrongsv_vless::{MemoryValidator, Validator, XRV};
use wrongsv_vless_encoding::{
    self as encoding, Addons,
    encoding::EncodeError,
};


use super::*;

pub(crate) struct VlessRequest {
    pub(crate) decoded: encoding::DecodedRequest,
    pub(crate) remaining_body: Vec<u8>,
    pub(crate) use_vision: bool,
}

pub(crate) fn decode_vless_request(
    first: Vec<u8>,
    validator: &Arc<MemoryValidator>,
    peer: std::net::SocketAddr,
) -> Result<VlessRequest, Box<dyn std::error::Error>> {
    let n = first.len();
    if n < 18 {
        debug!("{peer} connection too short ({n} bytes), dropping");
        return Err("connection too short for VLESS header".into());
    }

    let v = Arc::clone(validator);
    let mut cursor = std::io::Cursor::new(first);
    let decoded = encoding::decode_request_header(&mut cursor, move |id| v.get(id))?;
    let pos = cursor.position() as usize;
    let inner = cursor.into_inner();
    let remaining_body = if pos < inner.len() {
        inner[pos..].to_vec()
    } else {
        Vec::new()
    };
    let use_vision = decoded.addons.flow == XRV && decoded.header.user.account.flow == XRV;

    Ok(VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    })
}

pub(crate) fn log_vless_request(peer: std::net::SocketAddr, request: &RequestHeader) {
    info!(
        "{} {} {} -> {}:{}",
        peer,
        if request.command == RequestCommand::Tcp {
            "TCP"
        } else {
            "UDP"
        },
        request.user.email,
        request.address,
        request.port,
    );
}

pub(crate) fn handle_kyber_addons(
    peer: std::net::SocketAddr,
    decoded: &encoding::DecodedRequest,
    kyber_sk: Option<[u8; 64]>,
) {
    if decoded.addons.kyber_ct.is_empty() {
        return;
    }

    if let Some(sk) = kyber_sk {
        match wrongsv_kyber::decapsulate(&sk, &decoded.addons.kyber_ct) {
            Ok(_) => info!(
                "{peer} Kyber session established (ML-KEM-512, ss={} bytes)",
                wrongsv_kyber::SS_SIZE
            ),
            Err(e) => warn!("{peer} Kyber decapsulation failed: {e}"),
        }
    } else {
        debug!("{peer} client sent kyber_ct but server has no kyber_secret_key configured");
    }
}

pub(crate) fn validate_vless_command(
    request: &RequestHeader,
    use_vision: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if request.command == RequestCommand::Udp && use_vision {
        return Err("XTLS Vision does not support UDP".into());
    }
    Ok(())
}

pub(crate) fn response_header_buf(request: &RequestHeader) -> Result<bytes::BytesMut, EncodeError> {
    let response_addons = Addons {
        flow: String::new(),
        ..Default::default()
    };
    let mut resp_buf = bytes::BytesMut::new();
    encoding::encode_response_header(&mut resp_buf, request, &response_addons)?;
    Ok(resp_buf)
}

pub(crate) fn handle_connection(
    mut stream: TcpStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} new connection");
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    // Read first chunk from connection
    let mut first = vec![0u8; 8192];
    let n = stream.read(&mut first)?;
    first.truncate(n);
    trace!("{peer} read {n} bytes");

    let VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    } = decode_vless_request(first, &validator, peer)?;

    let request = &decoded.header;
    let account = &request.user.account;

    log_vless_request(peer, request);
    trace!(
        "{peer} flow={} use_vision={use_vision}",
        decoded.addons.flow
    );
    handle_kyber_addons(peer, &decoded, kyber_sk);
    validate_vless_command(request, use_vision)?;

    let resp_buf = response_header_buf(request)?;
    stream.write_all(&resp_buf)?;

    // UDP relay
    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_udp(stream, request, remaining_body)?;
        debug!("{peer} UDP relay finished");
        return Ok(());
    }

    // Connect to target
    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("{peer} connecting to target {target_addr}");
    let addr = target_addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("DNS resolution failed for {target_addr}"))?;
    let target = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;
    trace!("{peer} connected to target");

    // Clear read timeout for the rest of the connection
    stream.set_read_timeout(None)?;

    if use_vision {
        trace!("{peer} starting vision relay");
        relay_vision(stream, target, &decoded.user_sent_id, &account.testseed)?;
    } else {
        trace!("{peer} starting raw relay");
        relay_raw(stream, target)?;
    }
    debug!("{peer} relay finished");

    Ok(())
}
