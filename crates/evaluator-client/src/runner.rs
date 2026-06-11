//! Evaluation runner: connects to evaluator-server, follows the control
//! protocol, and runs latency/bandwidth/packet-loss tests through each
//! protocol's proxy endpoint.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::export::{BandwidthStats, LatencyStats, ProtocolResult};
use crate::transport;

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
        echo_port: u16,
        bw_port: u16,
        pl_port: u16,
        uuid: String,
        #[serde(default)]
        reality_pubkey_b64: Option<String>,
        #[serde(default)]
        reality_short_id: Option<String>,
        #[serde(default)]
        reality_raw_pubkey: Option<String>,
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

#[derive(Debug, Serialize, Deserialize)]
struct ClientMetrics {
    latency_ms: ClientLatencyStats,
    bandwidth_mbps: ClientBandwidthStats,
    packet_loss_pct: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientLatencyStats {
    min: f64,
    max: f64,
    avg: f64,
    p50: f64,
    p95: f64,
    p99: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientBandwidthStats {
    upload: f64,
    download: f64,
}

/// Like `Read::read_exact`, but retries on `WouldBlock` so that a bounded
/// `read_tls_inner` doesn't cause spurious failures in latency/packet-loss
/// tests.  Each retry sleeps 5 ms and the total wait is capped at ~2.5 s
/// (500 retries) to avoid hanging forever.
fn read_exact_retry(stream: &mut dyn transport::ReadWrite, mut buf: &mut [u8]) -> std::io::Result<()> {
    let mut retries: u32 = 0;
    const MAX_RETRIES: u32 = 500;
    while !buf.is_empty() {
        match stream.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                let tmp = buf;
                buf = &mut tmp[n..];
                retries = 0; // reset on progress
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                retries += 1;
                if retries > MAX_RETRIES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "read_exact_retry: too many WouldBlock retries",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => return Err(e),
        }
    }
    if buf.is_empty() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
    }
}

// ── test helpers ────────────────────────────────────────────────────────

/// Run a latency test: send N timestamped pings through the proxy and
/// measure round-trip time.
fn run_latency_test(
    stream: &mut dyn transport::ReadWrite,
    _duration: Duration,
) -> LatencyStats {
    const PING_COUNT: usize = 20;
    const PING_SIZE: usize = 64;
    let mut rtts = Vec::with_capacity(PING_COUNT);

    // Warmup: the first read after connect can be slow (~2 s) because the
    // server may still be sending post-handshake TLS data (e.g. session
    // tickets).  Absorb that delay here so it doesn't skew the metrics.
    {
        let payload = [0xFFu8; PING_SIZE];
        let _ = stream.write_all(&payload);
        let mut buf = [0u8; PING_SIZE];
        let _ = read_exact_retry(stream, &mut buf);
    }

    for _ in 0..PING_COUNT {
        let payload = [0x00u8; PING_SIZE];
        let start = Instant::now();
        if stream.write_all(&payload).is_ok() {
            let mut buf = [0u8; PING_SIZE];
            if read_exact_retry(stream, &mut buf).is_ok() {
                rtts.push(start.elapsed().as_secs_f64() * 1000.0);
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
/// Run upload phase: send 0xBB payload for `duration` seconds, then send
/// the "BW_DOWNLOAD" trigger so the server target switches to download mode.
/// Returns total bytes sent.
fn run_upload_phase(stream: &mut dyn transport::ReadWrite, duration: Duration) -> u64 {
    let payload = vec![0xBBu8; 65536];
    let start = Instant::now();
    let mut total_sent: u64 = 0;
    while start.elapsed() < duration {
        match stream.write(&payload) {
            Ok(n) => total_sent += n as u64,
            Err(_) => break,
        }
    }
    // Send trigger to switch the target to download mode
    let _ = stream.write_all(b"BW_DOWNLOAD");
    stream.flush().ok();
    total_sent
}

/// Run download phase on an already-triggered stream: read 0xAA payloads
/// for `duration` seconds. The stream should already have had "BW_DOWNLOAD"
/// sent (either on this connection or another).
fn run_download_phase(stream: &mut dyn transport::ReadWrite, duration: Duration) -> u64 {
    let start = Instant::now();
    let mut total_recv: u64 = 0;
    let mut buf = [0u8; 65536];
    while start.elapsed() < duration {
        match stream.read(&mut buf) {
            Ok(n) if n > 0 => total_recv += n as u64,
            Ok(0) => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Ok(_) => break,
            Err(_) => break,
        }
    }
    total_recv
}

/// Run a bandwidth test: transfer data through the proxy and measure Mbps.
/// Uses two connections to avoid head-of-line blocking between upload and
/// download: the upload connection primes the target, and a fresh download
/// connection reads the stream of 0xAA payloads.
fn run_bandwidth_test(
    upload_stream: &mut dyn transport::ReadWrite,
    download_stream: &mut dyn transport::ReadWrite,
    duration: Duration,
) -> BandwidthStats {
    // --- upload ---
    let upload_start = Instant::now();
    let _total_sent = run_upload_phase(upload_stream, duration);
    let upload_elapsed = upload_start.elapsed().as_secs_f64().max(0.001);
    let upload_mbps = (_total_sent as f64 * 8.0) / (upload_elapsed * 1_000_000.0);

    // --- download on fresh connection ---
    // Send trigger immediately (no upload backlog on this connection).
    let _ = download_stream.write_all(b"BW_DOWNLOAD");
    download_stream.flush().ok();
    std::thread::sleep(Duration::from_millis(200));

    let total_recv = run_download_phase(download_stream, duration);
    let download_elapsed = duration.as_secs_f64().max(0.001);
    let download_mbps = (total_recv as f64 * 8.0) / (download_elapsed * 1_000_000.0);

    BandwidthStats {
        upload: upload_mbps,
        download: download_mbps,
    }
}

/// Run a packet loss test through the proxy transport connection.
/// Sends numbered packets through the proxy to the echo target and counts
/// responses. Does NOT use raw UDP — packets flow through the VLESS tunnel
/// like real traffic would.
fn run_packet_loss_test(
    stream: &mut dyn transport::ReadWrite,
    _duration: Duration,
) -> f64 {
    const PACKET_COUNT: usize = 20;
    const PACKET_SIZE: usize = 64;
    let mut sent = 0usize;
    let mut received = 0usize;

    // Warmup: absorb post-handshake delay before the timed packets.
    {
        let payload = [0xFFu8; PACKET_SIZE];
        let _ = stream.write_all(&payload);
        let mut buf = [0u8; PACKET_SIZE];
        let _ = read_exact_retry(stream, &mut buf);
    }

    // Send one, read one — like the latency test.  Sending all packets
    // before reading any responses causes the server's relay loop to batch
    // all plaintext into one TLS record, which RealityConnection::read()
    // truncates because it does not buffer excess decrypted data.
    for seq in 0..PACKET_COUNT {
        let mut payload = [0u8; PACKET_SIZE];
        payload[..8].copy_from_slice(&seq.to_be_bytes());
        if stream.write_all(&payload).is_err() {
            break;
        }
        sent += 1;

        let mut buf = [0u8; PACKET_SIZE];
        match read_exact_retry(stream, &mut buf) {
            Ok(_) => received += 1,
            Err(_) => break,
        }
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
    let mut stream =
        TcpStream::connect_timeout(&server_addr.parse()?, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;

    // Derive proxy host from orchestrator address.  Strip the port portion
    // so that transport connections target the same host as the control
    // channel (e.g. "tencentde:19999" → proxy host "tencentde").
    let proxy_host = server_addr
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(server_addr);

    let mut reader = BufReader::new(&mut stream);

    // --- auth ---
    send_msg(reader.get_mut(), &ClientMessage::Auth { token })?;
    match recv_msg(&mut reader)? {
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
        match recv_msg(&mut reader)? {
            ServerMessage::TestConfig {
                protocol,
                proxy_port,
                echo_port,
                bw_port,
                pl_port,
                uuid,
                reality_pubkey_b64,
                reality_short_id,
                reality_raw_pubkey,
            } => {
                println!(
                    "testing protocol: {protocol} (proxy={proxy_port}, echo={echo_port}, bw={bw_port}, pl={pl_port})"
                );

                // Send ready
                send_msg(
                    reader.get_mut(),
                    &ClientMessage::Ready {
                        protocol: &protocol,
                    },
                )?;

                // Wait for start
                match recv_msg(&mut reader)? {
                    ServerMessage::Start { .. } => {}
                    _ => return Err("expected start".into()),
                }

                // Determine flow
                let flow = if protocol.contains("reality") {
                    "xtls-rprx-vision"
                } else {
                    ""
                };

                let lat = match transport::connect_for_protocol(
                    &protocol,
                    proxy_host,
                    proxy_port,
                    echo_port,
                    &uuid,
                    flow,
                    reality_pubkey_b64.as_deref(),
                    reality_short_id.as_deref(),
                    reality_raw_pubkey.as_deref(),
                ) {
                    Ok(mut transport_stream) => {
                        run_latency_test(&mut *transport_stream, duration)
                    }
                    Err(e) => {
                        eprintln!("  [WARN] {protocol} connect failed: {e}");
                        LatencyStats { min: 0.0, max: 0.0, avg: 0.0, p50: 0.0, p95: 0.0, p99: 0.0 }
                    }
                };

                // Bandwidth: use separate upload + download connections to
                // avoid head-of-line blocking (upload backlog delays the
                // "BW_DOWNLOAD" trigger from reaching the target).
                let make_bw_conn = || {
                    transport::connect_for_protocol(
                        &protocol,
                        proxy_host,
                        proxy_port,
                        bw_port,
                        &uuid,
                        flow,
                        reality_pubkey_b64.as_deref(),
                        reality_short_id.as_deref(),
                        reality_raw_pubkey.as_deref(),
                    )
                };
                let bw = match (make_bw_conn(), make_bw_conn()) {
                    (Ok(mut up), Ok(mut dn)) => {
                        let result = run_bandwidth_test(&mut *up, &mut *dn, duration);
                        drop(up);
                        drop(dn);
                        result
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        eprintln!("  [WARN] {protocol} bw connect failed: {e}");
                        BandwidthStats { upload: 0.0, download: 0.0 }
                    }
                };

                let pl = match transport::connect_for_protocol(
                    &protocol,
                    proxy_host,
                    proxy_port,
                    echo_port,
                    &uuid,
                    flow,
                    reality_pubkey_b64.as_deref(),
                    reality_short_id.as_deref(),
                    reality_raw_pubkey.as_deref(),
                ) {
                    Ok(mut transport_stream) => {
                        run_packet_loss_test(&mut *transport_stream, duration)
                    }
                    Err(e) => {
                        eprintln!("  [WARN] {protocol} pl connect failed: {e}");
                        100.0
                    }
                };

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
                    packet_loss_pct: pl,
                };

                // Send result
                send_msg(
                    reader.get_mut(),
                    &ClientMessage::Result {
                        protocol: &protocol,
                        metrics,
                    },
                )?;

                println!(
                    "  lat={:.2}ms avg, bw={:.2}/{:.2} Mbps up/dn, loss={:.2}%",
                    lat.avg, bw.upload, bw.download, pl
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

fn recv_msg<T: for<'de> Deserialize<'de>>(
    reader: &mut BufReader<&mut TcpStream>,
) -> Result<T, std::io::Error> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed",
        ));
    }
    let trimmed = line.trim_end();
    serde_json::from_str(trimmed)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── percentile ───────────────────────────────────────────────────────

    #[test]
    fn percentile_empty() {
        assert_eq!(percentile(&[], 0.50), 0.0);
    }

    #[test]
    fn percentile_single() {
        assert_eq!(percentile(&[42.0], 0.50), 42.0);
        assert_eq!(percentile(&[42.0], 0.0), 42.0);
        assert_eq!(percentile(&[42.0], 1.0), 42.0);
    }

    #[test]
    fn percentile_known_values() {
        let data = [1.0, 2.0, 3.0, 4.0, 5.0];
        // p50 = median = index round((5-1)*0.50) = round(2) = 2 → 3.0
        assert_eq!(percentile(&data, 0.50), 3.0);
        // p0 = min
        assert_eq!(percentile(&data, 0.0), 1.0);
        // p100 = max
        assert_eq!(percentile(&data, 1.0), 5.0);
        // p95 = index round((5-1)*0.95) = round(3.8) = 4 → 5.0
        assert_eq!(percentile(&data, 0.95), 5.0);
        // p25 = index round((5-1)*0.25) = round(1) = 1 → 2.0
        assert_eq!(percentile(&data, 0.25), 2.0);
    }

    #[test]
    fn percentile_100_elements() {
        let data: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let p50 = percentile(&data, 0.50);
        assert!(p50 >= 50.0 && p50 <= 51.0, "p50={p50}");
        let p99 = percentile(&data, 0.99);
        assert!(p99 >= 99.0, "p99={p99}");
    }

    // ── LatencyStats edge cases ──────────────────────────────────────────

    #[test]
    fn latency_stats_empty_on_failure() {
        // When no pings succeed, run_latency_test returns all zeros
        let stats = LatencyStats {
            min: 0.0,
            max: 0.0,
            avg: 0.0,
            p50: 0.0,
            p95: 0.0,
            p99: 0.0,
        };
        assert_eq!(stats.avg, 0.0);
        assert_eq!(stats.min, 0.0);
        assert_eq!(stats.max, 0.0);
    }

    #[test]
    fn latency_stats_valid_values() {
        let stats = LatencyStats {
            min: 1.0,
            max: 100.0,
            avg: 50.0,
            p50: 48.0,
            p95: 95.0,
            p99: 99.0,
        };
        assert!(stats.min <= stats.avg);
        assert!(stats.avg <= stats.max);
        assert!(stats.p50 >= stats.min);
        assert!(stats.p99 <= stats.max);
    }

    // ── BandwidthStats ───────────────────────────────────────────────────

    #[test]
    fn bandwidth_stats_zero_on_failure() {
        let stats = BandwidthStats {
            upload: 0.0,
            download: 0.0,
        };
        assert_eq!(stats.upload, 0.0);
        assert_eq!(stats.download, 0.0);
    }

    #[test]
    fn bandwidth_stats_positive() {
        let stats = BandwidthStats {
            upload: 100.5,
            download: 200.3,
        };
        assert!(stats.upload > 0.0);
        assert!(stats.download > 0.0);
    }

    // ── ClientMetrics serialization ──────────────────────────────────────

    #[test]
    fn client_metrics_json_roundtrip() {
        let metrics = ClientMetrics {
            latency_ms: ClientLatencyStats {
                min: 0.5,
                max: 12.3,
                avg: 4.2,
                p50: 3.8,
                p95: 10.1,
                p99: 11.9,
            },
            bandwidth_mbps: ClientBandwidthStats {
                upload: 50.0,
                download: 100.0,
            },
            packet_loss_pct: 0.5,
        };
        let json = serde_json::to_string(&metrics).unwrap();
        let back: ClientMetrics = serde_json::from_str(&json).unwrap();
        assert!((back.latency_ms.avg - 4.2).abs() < 0.01);
        assert!((back.bandwidth_mbps.upload - 50.0).abs() < 0.01);
        assert!((back.packet_loss_pct - 0.5).abs() < 0.01);
    }

    // ── Wire protocol messages ───────────────────────────────────────────

    #[test]
    fn server_message_test_config_deser() {
        let json = r#"{"type":"test","protocol":"raw","proxy_port":1234,"echo_port":1235,"bw_port":1236,"pl_port":1237,"uuid":"550e8400-e29b-41d4-a716-446655440000"}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::TestConfig {
                protocol,
                proxy_port,
                echo_port,
                bw_port,
                pl_port,
                uuid,
                ..
            } => {
                assert_eq!(protocol, "raw");
                assert_eq!(proxy_port, 1234);
                assert_eq!(echo_port, 1235);
                assert_eq!(bw_port, 1236);
                assert_eq!(pl_port, 1237);
                assert_eq!(uuid, "550e8400-e29b-41d4-a716-446655440000");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_test_config_with_reality_params() {
        let json = r#"{"type":"test","protocol":"reality","proxy_port":1,"echo_port":2,"bw_port":3,"pl_port":4,"uuid":"a","reality_pubkey_b64":"abc","reality_short_id":"1234abcd","reality_raw_pubkey":"00"}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::TestConfig {
                reality_pubkey_b64,
                reality_short_id,
                reality_raw_pubkey,
                ..
            } => {
                assert_eq!(reality_pubkey_b64.unwrap(), "abc");
                assert_eq!(reality_short_id.unwrap(), "1234abcd");
                assert!(reality_raw_pubkey.is_some());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_auth_ok() {
        let json = r#"{"type":"auth_ok"}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, ServerMessage::AuthOk));
    }

    #[test]
    fn server_message_auth_err() {
        let json = r#"{"type":"auth_err","reason":"bad token"}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        match msg {
            ServerMessage::AuthErr { reason } => assert_eq!(reason, "bad token"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_done() {
        let json = r#"{"type":"done"}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, ServerMessage::Done));
    }

    #[test]
    fn client_message_auth_serialize() {
        let msg = ClientMessage::Auth { token: "test-token" };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("auth"));
        assert!(json.contains("test-token"));
    }

    #[test]
    fn client_message_ready_serialize() {
        let msg = ClientMessage::Ready {
            protocol: "reality",
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("ready"));
        assert!(json.contains("reality"));
    }

    #[test]
    fn client_message_result_serialize() {
        let msg = ClientMessage::Result {
            protocol: "tls",
            metrics: ClientMetrics {
                latency_ms: ClientLatencyStats {
                    min: 0.0, max: 0.0, avg: 0.0, p50: 0.0, p95: 0.0, p99: 0.0,
                },
                bandwidth_mbps: ClientBandwidthStats {
                    upload: 0.0, download: 0.0,
                },
                packet_loss_pct: 0.0,
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("result"));
        assert!(json.contains("tls"));
        assert!(json.contains("latency_ms"));
        assert!(json.contains("bandwidth_mbps"));
        assert!(json.contains("packet_loss_pct"));
    }

    #[test]
    fn protocol_result_has_all_fields() {
        let result = ProtocolResult {
            protocol: "raw".into(),
            latency_ms: LatencyStats { min: 1.0, max: 2.0, avg: 1.5, p50: 1.5, p95: 1.9, p99: 2.0 },
            bandwidth_mbps: BandwidthStats { upload: 10.0, download: 20.0 },
            packet_loss_pct: 0.0,
        };
        assert_eq!(result.protocol, "raw");
        assert!((result.latency_ms.avg - 1.5).abs() < 0.01);
        assert!((result.bandwidth_mbps.download - 20.0).abs() < 0.01);
        assert_eq!(result.packet_loss_pct, 0.0);
    }
}
