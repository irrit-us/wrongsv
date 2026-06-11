//! Lightweight target servers for latency, bandwidth, and packet-loss tests.
//! These run alongside the evaluator orchestrator and serve as the "destination"
//! that the client reaches through the wrongsv proxy chain.

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::info;

/// Spawn an echo server. Returns the bound address.
/// The echo server reads up to 64 KiB, writes it back unchanged.
pub async fn spawn_echo_target() -> Result<SocketAddr, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, peer)) = listener.accept().await {
            info!("echo target: connection from {peer}");
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

/// Spawn a bandwidth (sink/source) server. Returns the bound address.
/// Waits for a "BW_DOWNLOAD" trigger from the client, then sends
/// continuous 64 KiB payload chunks for download measurements.
/// Upload data before the trigger is discarded.
pub async fn spawn_bandwidth_target() -> Result<SocketAddr, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, peer)) = listener.accept().await {
            info!("bandwidth target: connection from {peer}");
            tokio::spawn(async move {
                let (mut read_half, mut write_half) = stream.into_split();
                // Scan incoming stream for "BW_DOWNLOAD" trigger — discard
                // upload data (0xBB…) until we find the exact 11-byte marker.
                // Without this, the target would start sending download data
                // while the client is still uploading, causing a TCP deadlock.
                let mut buf = vec![0u8; 65536];
                let mut window: Vec<u8> = Vec::new();
                loop {
                    match read_half.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(n) => {
                            window.extend_from_slice(&buf[..n]);
                            if window.windows(11).any(|w| w == b"BW_DOWNLOAD") {
                                break;
                            }
                            // Keep only the last 10 bytes — a partial
                            // trigger might straddle a read boundary.
                            let keep = window.len().min(10);
                            if window.len() > keep {
                                let drain_end = window.len() - keep;
                                window.drain(..drain_end);
                            }
                        }
                        Err(_) => return,
                    }
                }
                // Continuously send data for download measurement
                let payload = vec![0xAAu8; 65536];
                loop {
                    if write_half.write_all(&payload).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(addr)
}

/// Spawn a packet-loss counter server. Returns the bound address.
/// Listens on UDP and echoes back every received packet so the client
/// can count acks vs sent packets.
pub async fn spawn_packet_loss_target() -> Result<SocketAddr, std::io::Error> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], src).await;
        }
    });
    Ok(addr)
}
