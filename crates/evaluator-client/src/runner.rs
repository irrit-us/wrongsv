//! Evaluation runner: connects to evaluator-server, follows the control
//! protocol, and runs latency/bandwidth/packet-loss tests through each
//! protocol's proxy endpoint.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::export::{BandwidthStats, LatencyStats, ProtocolResult};

// ── wire protocol (mirrors evaluator-server types) ──────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum ServerMessage {
    #[serde(rename = "auth_ok")]
    AuthOk,
    #[serde(rename = "auth_err")]
    AuthErr { reason: String },
    #[serde(rename = "test")]
    TestConfig {
        protocol: String,
        proxy_port: u16,
        target_port: u16,
        uuid: String,
    },
    #[serde(rename = "start")]
    Start {
        protocol: String,
        duration_secs: u64,
    },
    #[serde(rename = "next")]
    Next,
    #[serde(rename = "done")]
    Done,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum ClientMessage<'a> {
    #[serde(rename = "auth")]
    Auth { token: &'a str },
    #[serde(rename = "ready")]
    Ready { protocol: &'a str },
    #[serde(rename = "result")]
    Result {
        protocol: &'a str,
        metrics: ClientMetrics,
    },
}

#[derive(Debug, Serialize)]
struct ClientMetrics {
    latency_ms: ClientLatencyStats,
    bandwidth_mbps: ClientBandwidthStats,
    packet_loss_pct: f64,
}

#[derive(Debug, Serialize)]
struct ClientLatencyStats {
    min: f64,
    max: f64,
    avg: f64,
    p50: f64,
    p95: f64,
    p99: f64,
}

#[derive(Debug, Serialize)]
struct ClientBandwidthStats {
    upload: f64,
    download: f64,
}

// ── test helpers ────────────────────────────────────────────────────────

/// Open a raw TCP connection through the proxy to the target (echo).
/// VLESS header is sent inline; for simplicity we use a raw TCP stream
/// for "raw" protocol and skip the VLESS header for others.
/// In production, the client would use the actual protocol libraries.
fn connect_via_proxy(
    proxy_port: u16,
    target_port: u16,
    uuid: &str,
    flow: &str,
) -> Result<TcpStream, std::io::Error> {
    let addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Send a minimal VLESS request header
    let header = build_vless_header(uuid, "127.0.0.1", target_port, flow);
    stream.write_all(&header)?;
    stream.flush()?;

    // Read the 2-byte VLESS response (version + option byte)
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp)?;
    if resp[0] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("VLESS version mismatch: {}", resp[0]),
        ));
    }
    Ok(stream)
}

fn build_vless_header(uuid: &str, target_addr: &str, target_port: u16, flow: &str) -> Vec<u8> {
    use wrongsv_net_types::{Address, Port};
    use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
    use wrongsv_uuid::Uuid;
    use wrongsv_vless_encoding::Addons;

    let uid = Uuid::parse_string(uuid)
        .unwrap_or_else(|_| Uuid::parse_string("00000000-0000-4000-8000-000000000000").unwrap());
    let user = MemoryUser {
        account: MemoryAccount {
            id: ID::new(uid),
            flow: flow.into(),
            encryption: String::new(),
            udp: true,
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            testpre: 0,
            testseed: vec![],
        },
        email: "eval@eval.test".into(),
        level: 0,
    };
    let request = RequestHeader {
        version: 0,
        command: RequestCommand::Tcp,
        address: Address::parse(target_addr),
        port: Port(target_port),
        user,
    };
    let mut buf = bytes::BytesMut::new();
    wrongsv_vless_encoding::encode_request_header(
        &mut buf,
        &request,
        &Addons {
            flow: flow.into(),
            ..Default::default()
        },
    )
    .unwrap_or_default();
    buf.to_vec()
}

/// Run a latency test: send N timestamped pings through the proxy and
/// measure round-trip time.
fn run_latency_test(
    proxy_port: u16,
    target_port: u16,
    uuid: &str,
    flow: &str,
    _duration: Duration,
) -> LatencyStats {
    const PING_COUNT: usize = 20;
    const PING_SIZE: usize = 64;
    let mut rtts = Vec::with_capacity(PING_COUNT);

    for _ in 0..PING_COUNT {
        if let Ok(mut stream) = connect_via_proxy(proxy_port, target_port, uuid, flow) {
            let payload = [0x00u8; PING_SIZE];
            let start = Instant::now();
            if stream.write_all(&payload).is_ok() {
                let mut buf = [0u8; PING_SIZE];
                if stream.read_exact(&mut buf).is_ok() {
                    rtts.push(start.elapsed().as_secs_f64() * 1000.0);
                }
            }
        }
    }

    if rtts.is_empty() {
        return LatencyStats {
            min: 0.0,
            max: 0.0,
            avg: 0.0,
            p50: 0.0,
            p95: 0.0,
            p99: 0.0,
        };
    }

    rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let min = rtts[0];
    let max = rtts[rtts.len() - 1];
    let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
    let p50 = percentile(&rtts, 0.50);
    let p95 = percentile(&rtts, 0.95);
    let p99 = percentile(&rtts, 0.99);

    LatencyStats {
        min,
        max,
        avg,
        p50,
        p95,
        p99,
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Run a bandwidth test: transfer data through the proxy and measure Mbps.
fn run_bandwidth_test(
    proxy_port: u16,
    target_port: u16,
    uuid: &str,
    flow: &str,
    duration: Duration,
) -> BandwidthStats {
    let mut upload_mbps = 0.0;
    let mut download_mbps = 0.0;

    // Upload test: send data for the duration
    if let Ok(mut stream) = connect_via_proxy(proxy_port, target_port, uuid, flow) {
        let payload = vec![0xBBu8; 65536];
        let start = Instant::now();
        let mut total_sent: u64 = 0;
        while start.elapsed() < duration {
            match stream.write(&payload) {
                Ok(n) => total_sent += n as u64,
                Err(_) => break,
            }
        }
        let elapsed = start.elapsed().as_secs_f64().max(0.001);
        upload_mbps = (total_sent as f64 * 8.0) / (elapsed * 1_000_000.0);
    }

    // Download test: receive data for the duration
    if let Ok(mut stream) = connect_via_proxy(proxy_port, target_port, uuid, flow) {
        // Trigger the bandwidth target to send data by writing a small request
        let _ = stream.write_all(b"BW_DOWNLOAD");
        let start = Instant::now();
        let mut total_recv: u64 = 0;
        let mut buf = [0u8; 65536];
        while start.elapsed() < duration {
            match stream.read(&mut buf) {
                Ok(n) if n > 0 => total_recv += n as u64,
                Ok(_) | Err(_) => break,
            }
        }
        let elapsed = start.elapsed().as_secs_f64().max(0.001);
        download_mbps = (total_recv as f64 * 8.0) / (elapsed * 1_000_000.0);
    }

    BandwidthStats {
        upload: upload_mbps,
        download: download_mbps,
    }
}

/// Run a packet loss test: send UDP packets through the proxy.
fn run_packet_loss_test(
    proxy_port: u16,
    _target_port: u16,
    _uuid: &str,
    _flow: &str,
    _duration: Duration,
) -> f64 {
    const PACKET_COUNT: usize = 100;
    let socket = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(_) => return 100.0,
    };
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();

    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();
    let mut sent = 0usize;
    let mut received = 0usize;

    // For non-raw protocols through UDP proxy, we would need protocol-specific
    // UDP relay. This is a simplified test: send directly to proxy port.
    for seq in 0..PACKET_COUNT {
        let packet = seq.to_be_bytes();
        if socket.send_to(&packet, proxy_addr).is_ok() {
            sent += 1;
        }
        // Try to receive acks
        let mut buf = [0u8; 8];
        if let Ok((_, _)) = socket.recv_from(&mut buf) {
            received += 1;
        }
    }

    // Drain remaining acks
    while let Ok((_, _)) = socket.recv_from(&mut [0u8; 8]) {
        received += 1;
    }

    if sent == 0 {
        100.0
    } else {
        ((sent - received) as f64 / sent as f64) * 100.0
    }
}

// ── main evaluation loop ────────────────────────────────────────────────

/// Connect to the evaluator server, authenticate, run through all protocols,
/// and return results.
pub fn run_evaluation(
    server_addr: &str,
    token: &str,
    duration_secs: u64,
) -> Result<Vec<ProtocolResult>, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect_timeout(&server_addr.parse()?, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;

    // --- auth ---
    send_msg(&mut stream, &ClientMessage::Auth { token })?;
    match recv_msg::<ServerMessage>(&mut stream)? {
        ServerMessage::AuthOk => {
            println!("authenticated");
        }
        ServerMessage::AuthErr { reason } => {
            return Err(format!("auth failed: {reason}").into());
        }
        _ => return Err("unexpected auth response".into()),
    }

    let mut results: Vec<ProtocolResult> = Vec::new();
    let duration = Duration::from_secs(duration_secs);

    loop {
        match recv_msg::<ServerMessage>(&mut stream)? {
            ServerMessage::TestConfig {
                protocol,
                proxy_port,
                target_port,
                uuid,
            } => {
                println!("testing protocol: {protocol} (proxy={proxy_port}, target={target_port})");

                // Send ready
                send_msg(
                    &mut stream,
                    &ClientMessage::Ready {
                        protocol: &protocol,
                    },
                )?;

                // Wait for start
                match recv_msg::<ServerMessage>(&mut stream)? {
                    ServerMessage::Start { .. } => {}
                    _ => return Err("expected start".into()),
                }

                // Determine flow based on protocol
                let flow = if protocol.contains("reality") {
                    "xtls-rprx-vision"
                } else {
                    ""
                };

                // Run tests
                let lat = run_latency_test(proxy_port, target_port, &uuid, flow, duration);
                let bw = run_bandwidth_test(proxy_port, target_port, &uuid, flow, duration);
                let pl = run_packet_loss_test(proxy_port, target_port, &uuid, flow, duration);

                let pl_val = pl;

                let metrics = ClientMetrics {
                    latency_ms: ClientLatencyStats {
                        min: lat.min,
                        max: lat.max,
                        avg: lat.avg,
                        p50: lat.p50,
                        p95: lat.p95,
                        p99: lat.p99,
                    },
                    bandwidth_mbps: ClientBandwidthStats {
                        upload: bw.upload,
                        download: bw.download,
                    },
                    packet_loss_pct: pl_val,
                };

                // Send result
                send_msg(
                    &mut stream,
                    &ClientMessage::Result {
                        protocol: &protocol,
                        metrics,
                    },
                )?;

                println!(
                    "  lat={:.2}ms avg, bw={:.2}/{:.2} Mbps up/dn, loss={:.2}%",
                    lat.avg, bw.upload, bw.download, pl_val
                );

                results.push(ProtocolResult {
                    protocol: protocol.clone(),
                    latency_ms: lat,
                    bandwidth_mbps: bw,
                    packet_loss_pct: pl,
                });
            }
            ServerMessage::Next => {
                continue;
            }
            ServerMessage::Done => {
                println!("evaluation complete");
                break;
            }
            other => {
                return Err(format!("unexpected server message: {other:?}").into());
            }
        }
    }

    Ok(results)
}

fn send_msg(stream: &mut TcpStream, msg: &impl Serialize) -> Result<(), std::io::Error> {
    let mut json = serde_json::to_string(msg).expect("message should serialize");
    json.push('\n');
    stream.write_all(json.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn recv_msg<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> Result<T, std::io::Error> {
    let mut buf = [0u8; 4096];
    let mut line = String::new();
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }
        line.push_str(&String::from_utf8_lossy(&buf[..n]));
        if line.contains('\n') {
            // Take up to the first newline
            let split: Vec<&str> = line.splitn(2, '\n').collect();
            return serde_json::from_str(split[0])
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()));
        }
    }
}
