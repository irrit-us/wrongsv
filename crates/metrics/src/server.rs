//! Minimal HTTP listener that serves `GET /metrics` from a [`Registry`].
//!
//! Intentionally tiny — no async runtime, just one thread per connection. The
//! handler reads a single request line, ignores headers, and emits either a
//! Prometheus dump for `/metrics` or a 404 for anything else.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::Registry;

const ACCEPT_LOOP_TIMEOUT: Duration = Duration::from_millis(200);

/// Handle to a running metrics HTTP listener. Drop to shut it down.
pub struct ServerHandle {
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl ServerHandle {
    /// Signal the listener loop to stop and block until the accept thread exits.
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Spawn an HTTP listener on `addr` that serves the Prometheus dump.
///
/// Returns the bound socket address (useful when `port = 0`) and a handle.
pub fn serve(addr: &str, registry: Arc<Registry>) -> std::io::Result<(String, ServerHandle)> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let bound = listener.local_addr()?.to_string();
    info!("metrics listening on http://{bound}/metrics");

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);

    let join = thread::Builder::new()
        .name("metrics-http".into())
        .spawn(move || {
            // Poll-accept so we can honour the shutdown flag promptly.
            while !shutdown_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _peer)) => {
                        let reg = Arc::clone(&registry);
                        thread::spawn(move || {
                            if let Err(e) = handle(stream, &reg) {
                                debug!("metrics request: {e}");
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_LOOP_TIMEOUT);
                    }
                    Err(e) => {
                        warn!("metrics accept: {e}");
                        thread::sleep(ACCEPT_LOOP_TIMEOUT);
                    }
                }
            }
            debug!("metrics listener stopped");
        })?;

    Ok((
        bound,
        ServerHandle {
            shutdown,
            join: Some(join),
        },
    ))
}

fn handle(mut stream: TcpStream, registry: &Registry) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Drain headers
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("");
    let path = parts.get(1).copied().unwrap_or("");

    if method != "GET" {
        return write_response(&mut stream, 405, "Method Not Allowed", "text/plain", b"");
    }

    match path {
        "/metrics" => {
            let body = registry.render_prometheus();
            write_response(
                &mut stream,
                200,
                "OK",
                "text/plain; version=0.0.4",
                body.as_bytes(),
            )
        }
        "/" | "/healthz" => write_response(&mut stream, 200, "OK", "text/plain", b"ok\n"),
        _ => write_response(&mut stream, 404, "Not Found", "text/plain", b""),
    }
}

fn write_response(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn http_get(addr: &str, path: &str) -> String {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn metrics_endpoint_returns_prometheus_dump() {
        let reg = Arc::new(Registry::new());
        reg.record_bytes_in("alice@test", 123);
        let (addr, handle) = serve("127.0.0.1:0", Arc::clone(&reg)).unwrap();
        let response = http_get(&addr, "/metrics");
        assert!(response.contains("200 OK"), "got: {response}");
        assert!(
            response.contains("wrongsv_uptime_seconds"),
            "got: {response}"
        );
        assert!(
            response.contains("wrongsv_user_bytes_in{email=\"alice@test\"} 123"),
            "got: {response}"
        );
        handle.shutdown();
    }

    #[test]
    fn unknown_path_returns_404() {
        let reg = Arc::new(Registry::new());
        let (addr, handle) = serve("127.0.0.1:0", reg).unwrap();
        let response = http_get(&addr, "/nope");
        assert!(response.contains("404 Not Found"), "got: {response}");
        handle.shutdown();
    }

    #[test]
    fn non_get_returns_405() {
        let reg = Arc::new(Registry::new());
        let (addr, handle) = serve("127.0.0.1:0", reg).unwrap();
        let mut s = std::net::TcpStream::connect(&addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.write_all(b"POST /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(out.contains("405 Method Not Allowed"), "got: {out}");
        handle.shutdown();
    }

    #[test]
    fn shutdown_stops_listener() {
        let reg = Arc::new(Registry::new());
        let (addr, handle) = serve("127.0.0.1:0", reg).unwrap();
        // Pre-shutdown: connect should succeed
        std::net::TcpStream::connect(&addr).unwrap();
        handle.shutdown();
        // Post-shutdown: connect should fail (port released)
        thread::sleep(Duration::from_millis(500));
        let res = std::net::TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            Duration::from_millis(200),
        );
        assert!(res.is_err(), "expected connection to fail after shutdown");
    }
}
