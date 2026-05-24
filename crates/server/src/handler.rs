use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use wrongsv_protocol::{MemoryAccount, MemoryUser, RequestCommand, ID};
use wrongsv_uuid::Uuid;
use wrongsv_vless::{MemoryValidator, Validator, XRV};
use wrongsv_vless::vision::{TrafficState, VisionReader, VisionWriter};
use wrongsv_vless_encoding::{self as encoding, Addons};

use crate::config::Config;

/// Decode a hex string into a fixed-size byte array.
fn decode_hex<const N: usize>(hex: &str) -> Result<[u8; N], String> {
    let hex = hex.trim();
    if hex.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, hex.len()));
    }
    let mut bytes = [0u8; N];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(chunk[0]).ok_or_else(|| format!("invalid hex at position {}", i * 2))?;
        let lo = hex_val(chunk[1]).ok_or_else(|| format!("invalid hex at position {}", i * 2 + 1))?;
        bytes[i] = hi << 4 | lo;
    }
    Ok(bytes)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub struct InboundServer {
    config: Config,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
}

impl InboundServer {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        config.validate()?;
        let kyber_sk = match &config.kyber_secret_key {
            Some(hex) => Some(decode_hex::<64>(hex).map_err(|e| format!("kyber_secret_key: {e}"))?),
            None => None,
        };
        let validator = Arc::new(MemoryValidator::new());
        for user in &config.users {
            let uuid = Uuid::parse_string(&user.id)?;
            let flow = if user.flow.is_empty() {
                config.flow.clone().unwrap_or_default()
            } else {
                user.flow.clone()
            };
            let mu = MemoryUser {
                account: MemoryAccount {
                    id: ID::new(uuid),
                    flow,
                    encryption: user.encryption.clone(),
                    xor_mode: 0,
                    seconds: 0,
                    padding: String::new(),
                    testpre: 0,
                    testseed: vec![],
                },
                email: user.email.clone(),
                level: 0,
            };
            validator.add(mu)?;
        }
        Ok(InboundServer {
            config,
            validator,
            kyber_sk,
        })
    }

    /// Run the server loop. Blocks until error.
    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.config.listen)?;
        info!("VLESS server listening on {}", self.config.listen);

        let validator = Arc::clone(&self.validator);
        let kyber_sk = self.kyber_sk;

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let v = Arc::clone(&validator);
                    thread::spawn(move || {
                        if let Err(e) = handle_connection(stream, v, kyber_sk) {
                            warn!("connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("accept error: {}", e);
                }
            }
        }
        Ok(())
    }
}

fn handle_connection(
    mut stream: TcpStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    // Read first chunk from connection
    let mut first = vec![0u8; 8192];
    let n = stream.read(&mut first)?;
    first.truncate(n);

    if n < 18 {
        return Err("connection too short for VLESS header".into());
    }

    // Decode the VLESS request header
    let decoded = {
        let v = validator.clone();
        let mut cursor = std::io::Cursor::new(first);
        encoding::decode_request_header(&mut cursor, move |id| v.get(id))?
    };

    let request = &decoded.header;
    let account = &request.user.account;

    info!(
        "{} {} {} -> {}:{}",
        peer,
        if request.command == RequestCommand::Tcp { "TCP" } else { "UDP" },
        request.user.email,
        request.address,
        request.port,
    );

    // Check flow
    let use_vision = decoded.addons.flow == XRV && account.flow == XRV;

    // Kyber session-key decapsulation
    if !decoded.addons.kyber_ct.is_empty() {
        if let Some(sk) = kyber_sk {
            match wrongsv_kyber::decapsulate(&sk, &decoded.addons.kyber_ct) {
                Ok(_shared_secret) => {
                    info!(
                        "{} Kyber session established (ML-KEM-512, ss={} bytes)",
                        peer,
                        wrongsv_kyber::SS_SIZE,
                    );
                    // TODO: derive AeadKey from shared_secret, wrap streams in CommonConn
                }
                Err(e) => {
                    warn!("{} Kyber decapsulation failed: {}", peer, e);
                }
            }
        } else {
            debug!("{} client sent kyber_ct but server has no kyber_secret_key configured", peer);
        }
    }

    // Send response header
    let response_addons = Addons {
        flow: String::new(),
        ..Default::default()
    };
    let mut resp_buf = bytes::BytesMut::new();
    encoding::encode_response_header(&mut resp_buf, request, &response_addons)?;
    stream.write_all(&resp_buf)?;

    // Connect to target
    let target_addr = format!("{}:{}", request.address, request.port);
    let target = TcpStream::connect_timeout(
        &target_addr.parse()?,
        Duration::from_secs(10),
    )?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;

    // Clear read timeout for the rest of the connection
    stream.set_read_timeout(None)?;

    if use_vision {
        relay_vision(stream, target, &decoded.user_sent_id, &account.testseed)?;
    } else {
        relay_raw(stream, target)?;
    }

    Ok(())
}

fn relay_raw(mut client: TcpStream, mut target: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut c2 = client.try_clone()?;
    let mut t2 = target.try_clone()?;

    let t1 = thread::spawn(move || {
        let mut buf = [0u8; 8192];
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
    });

    let t2 = thread::spawn(move || {
        let mut buf = [0u8; 8192];
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
    });

    t1.join().ok();
    t2.join().ok();
    Ok(())
}

fn relay_vision(
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
        let mut buf = [0u8; 8192];
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
    });

    // Target → Client (downlink): read from target raw, write to client with Vision
    let down_state = TrafficState::new(user_sent_id);
    let t2 = thread::spawn(move || {
        let mut writer = VisionWriter::new(c_write, down_state, false, up_seed);
        let mut buf = [0u8; 8192];
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
    });

    t1.join().ok();
    t2.join().ok();
    Ok(())
}
