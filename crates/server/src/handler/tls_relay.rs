//! TLS-to-plaintext relay for async h2 handlers (gRPC, xHTTP).
//!
//! After a synchronous TLS handshake, bridges the TLS stream to a fresh
//! local TCP connection so the existing tokio-based h2 handler sees a
//! plaintext `TcpStream`. The relay thread does a non-blocking polling
//! loop — suitable for local and low-latency paths.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tracing::{info, trace, warn};

/// Perform TLS handshake on `stream`, then spawn a relay thread that
/// bridges between the TLS connection and a local TCP socket pair.
///
/// Returns the plaintext `TcpStream` — pass it to the existing async
/// h2 handler as if it were a raw TCP connection.
pub(crate) fn tls_relay(
    stream: TcpStream,
    tls_config: &Arc<rustls::ServerConfig>,
    peer: std::net::SocketAddr,
    label: &str,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    // ── TLS handshake ────────────────────────────────────────────────
    let mut conn = rustls::ServerConnection::new(Arc::clone(tls_config))
        .map_err(|e| format!("{label} TLS create: {e}"))?;
    let mut sock = stream;
    // Bound the TLS handshake to drop slowloris peers.
    let _ = sock.set_read_timeout(Some(Duration::from_secs(30)));
    loop {
        match conn.complete_io(&mut sock) {
            Ok((_, _)) if !conn.is_handshaking() => break,
            Ok(_) => {}
            Err(e) => return Err(format!("{label} TLS handshake: {e}").into()),
        }
    }
    info!("{peer} {label}: TLS handshake done");
    sock.set_nonblocking(true)?;

    let mut tls = wrongsv_anytls::AnyTlsStream::from_parts(conn, sock);

    // ── Local TCP bridge ─────────────────────────────────────────────
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let local_addr = listener.local_addr()?;

    let label_owned = label.to_string();
    thread::spawn(move || {
        let (mut local, _local_peer) = match listener.accept() {
            Ok(v) => v,
            Err(e) => {
                warn!("{peer} {label_owned} relay accept failed: {e}");
                return;
            }
        };
        let _ = local.set_read_timeout(Some(Duration::from_millis(10)));
        let mut tls_buf = vec![0u8; 65536];
        let mut local_buf = vec![0u8; 65536];
        loop {
            // TLS → local
            match tls.read(&mut tls_buf) {
                Ok(0) => break,
                Ok(n) => {
                    if local.write_all(&tls_buf[..n]).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
            // Local → TLS
            match local.read(&mut local_buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tls.write_all(&local_buf[..n]).is_err() {
                        break;
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
        trace!("{peer} {label_owned} relay finished");
        let _ = local.shutdown(std::net::Shutdown::Both);
    });

    let plain = TcpStream::connect(local_addr)?;
    Ok(plain)
}
