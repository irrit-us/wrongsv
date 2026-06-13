use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, trace, warn};
use wrongsv_vless::MemoryValidator;

use crate::config::MeekServerConfig;

use super::*;

const MAX_MEEK_HEADER_SIZE: usize = 16 * 1024;

#[derive(Clone)]
pub(crate) struct MeekConfig {
    pub path: String,
    pub host: Option<String>,
    pub max_request_bytes: usize,
    pub sessions: Arc<RequestSessionRegistry>,
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
    #[allow(dead_code)]
    pub tls_dest: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Http1BodyKind {
    Chunked,
    ContentLength(usize),
    UntilEof,
}

#[derive(Debug)]
struct MeekHttpRequest {
    session_id: String,
    body_kind: Http1BodyKind,
}

struct PrefixedReader<R> {
    prefix: Vec<u8>,
    offset: usize,
    inner: R,
}

impl<R> PrefixedReader<R> {
    fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<R: Read> Read for PrefixedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.offset < self.prefix.len() {
            let available = self.prefix.len() - self.offset;
            let n = available.min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.offset..self.offset + n]);
            self.offset += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

struct Http1BodyReader<R> {
    inner: R,
    mode: Http1BodyKind,
    chunk_remaining: usize,
    finished: bool,
}

impl<R> Http1BodyReader<R> {
    fn new(inner: R, mode: Http1BodyKind) -> Self {
        Self {
            inner,
            mode,
            chunk_remaining: 0,
            finished: false,
        }
    }
}

impl<R: Read> Http1BodyReader<R> {
    fn read_chunk_size(&mut self) -> io::Result<Option<usize>> {
        let mut line = Vec::new();
        if try_read_http1_line(&mut self.inner, &mut line)?.is_none() {
            return Ok(None);
        }
        let line = std::str::from_utf8(&line)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk-size line"))?;
        let chunk_len = line
            .trim()
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if chunk_len.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing chunk size",
            ));
        }
        usize::from_str_radix(chunk_len, 16)
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))
    }

    fn consume_crlf(&mut self) -> io::Result<()> {
        let mut tail = [0u8; 2];
        self.inner.read_exact(&mut tail)?;
        if tail != *b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing chunk terminator",
            ));
        }
        Ok(())
    }

    fn consume_trailers(&mut self) -> io::Result<()> {
        let mut line = Vec::new();
        loop {
            read_http1_line(&mut self.inner, &mut line)?;
            if line == b"\r\n" {
                return Ok(());
            }
        }
    }
}

impl<R: Read> Read for Http1BodyReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.finished {
            return Ok(0);
        }
        match self.mode {
            Http1BodyKind::ContentLength(ref mut remaining) => {
                if *remaining == 0 {
                    self.finished = true;
                    return Ok(0);
                }
                let limit = (*remaining).min(buf.len());
                let n = self.inner.read(&mut buf[..limit])?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed during request body",
                    ));
                }
                *remaining -= n;
                if *remaining == 0 {
                    self.finished = true;
                }
                Ok(n)
            }
            Http1BodyKind::UntilEof => {
                let n = match self.inner.read(buf) {
                    Ok(n) => n,
                    Err(ref e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        self.finished = true;
                        return Ok(0);
                    }
                    Err(e) => return Err(e),
                };
                if n == 0 {
                    self.finished = true;
                }
                Ok(n)
            }
            Http1BodyKind::Chunked => {
                if self.chunk_remaining == 0 {
                    let Some(chunk_size) = self.read_chunk_size()? else {
                        self.finished = true;
                        return Ok(0);
                    };
                    if chunk_size == 0 {
                        self.consume_trailers()?;
                        self.finished = true;
                        return Ok(0);
                    }
                    self.chunk_remaining = chunk_size;
                }

                let limit = self.chunk_remaining.min(buf.len());
                let n = self.inner.read(&mut buf[..limit])?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed during chunked request body",
                    ));
                }
                self.chunk_remaining -= n;
                if self.chunk_remaining == 0 {
                    self.consume_crlf()?;
                }
                Ok(n)
            }
        }
    }
}

pub(crate) fn parse_meek_config(mc: &MeekServerConfig) -> Result<MeekConfig, String> {
    let path = if mc.path.starts_with('/') {
        mc.path.clone()
    } else {
        format!("/{}", mc.path)
    };
    let (tls_config, tls_dest) = match &mc.tls {
        Some(tls) => {
            let (cert_pem, key_pem) = match (&tls.certificate, &tls.key) {
                (Some(c), Some(k)) => (c.clone(), k.clone()),
                _ => {
                    let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                        .map_err(|e| format!("meek tls cert: {e}"))?;
                    (cert, key)
                }
            };
            let server_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
                .map_err(|e| format!("meek tls config: {e}"))?;
            (Some(Arc::new(server_config)), tls.dest.clone())
        }
        None => (None, None),
    };
    let max_request_bytes = mc.max_request_bytes.max(1);
    let max_response_bytes = mc.max_response_bytes.max(1);
    let max_buffered_response_bytes = max_response_bytes.saturating_mul(16).max(max_response_bytes);
    let idle_timeout = if mc.idle_timeout == 0 {
        Duration::ZERO
    } else {
        Duration::from_secs(mc.idle_timeout)
    };
    Ok(MeekConfig {
        path,
        host: mc.host.clone(),
        max_request_bytes,
        sessions: Arc::new(RequestSessionRegistry::new(RequestSessionRegistryConfig {
            max_response_bytes,
            max_buffered_response_bytes,
            idle_timeout,
        })),
        tls_config,
        tls_dest,
    })
}

fn read_http1_line<R: Read>(reader: &mut R, buf: &mut Vec<u8>) -> io::Result<()> {
    match try_read_http1_line(reader, buf)? {
        Some(()) => Ok(()),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed while reading HTTP/1.1 line",
        )),
    }
}

fn try_read_http1_line<R: Read>(reader: &mut R, buf: &mut Vec<u8>) -> io::Result<Option<()>> {
    buf.clear();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte)?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed while reading HTTP/1.1 line",
                ))
            };
        }
        buf.push(byte[0]);
        if buf.len() > MAX_MEEK_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP/1.1 line too large",
            ));
        }
        if byte[0] == b'\n' {
            return Ok(Some(()));
        }
    }
}

fn normalize_host(value: &str) -> String {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return rest[..end].to_ascii_lowercase();
    }
    value
        .split(':')
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase()
}

fn host_matches(expected: &str, actual: &str) -> bool {
    normalize_host(expected) == normalize_host(actual)
}

fn parse_meek_http1_request(
    buf: &[u8],
    path: &str,
    host: Option<&str>,
) -> Result<(MeekHttpRequest, Vec<u8>), String> {
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "incomplete HTTP/1.1 headers".to_string())?;
    if header_end + 4 > MAX_MEEK_HEADER_SIZE {
        return Err(format!("header too large (>{MAX_MEEK_HEADER_SIZE}B)"));
    }

    let headers_buf = &buf[..header_end];
    let pipelined = buf[header_end + 4..].to_vec();
    let headers_str =
        std::str::from_utf8(headers_buf).map_err(|_| "invalid HTTP/1.1 headers".to_string())?;
    let mut lines = headers_str.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "missing HTTP/1.1 request line".to_string())?;

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "invalid HTTP/1.1 request line".to_string())?;
    if method != "POST" {
        return Err(format!("unsupported HTTP/1.1 method: {method}"));
    }
    let raw_path = parts
        .next()
        .ok_or_else(|| "invalid HTTP/1.1 request line".to_string())?;
    let version = parts
        .next()
        .ok_or_else(|| "invalid HTTP/1.1 request line".to_string())?;
    if !version.starts_with("HTTP/1.") {
        return Err(format!("unsupported HTTP version: {version}"));
    }

    let request_path = raw_path.split('?').next().unwrap_or(raw_path);
    let normalized_path = if request_path.starts_with('/') {
        request_path.to_string()
    } else {
        format!("/{request_path}")
    };
    if !normalized_path.starts_with(path) {
        return Err(format!(
            "path mismatch: expected prefix {path}, got {normalized_path}"
        ));
    }

    let mut request_host: Option<String> = None;
    let mut has_chunked_encoding = false;
    let mut content_length = None;
    let mut session_id: Option<String> = None;

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key.to_ascii_lowercase().as_str() {
            "host" => request_host = Some(normalize_host(value)),
            "x-session-id" => session_id = Some(value.to_string()),
            "transfer-encoding" => {
                has_chunked_encoding = value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("chunked"));
            }
            "content-length" => {
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid content-length: {value}"))?;
                content_length = Some(parsed);
            }
            _ => {}
        }
    }

    if let Some(expected_host) = host {
        let got = request_host.as_deref().unwrap_or("");
        if !host_matches(expected_host, got) {
            return Err(format!("host mismatch: expected {expected_host}, got {got}"));
        }
    }

    let session_id = session_id.ok_or_else(|| "missing X-Session-ID header".to_string())?;
    if session_id.is_empty() {
        return Err("empty X-Session-ID header".to_string());
    }

    let body_kind = if has_chunked_encoding {
        Http1BodyKind::Chunked
    } else if let Some(content_length) = content_length {
        Http1BodyKind::ContentLength(content_length)
    } else {
        Http1BodyKind::UntilEof
    };

    Ok((
        MeekHttpRequest {
            session_id,
            body_kind,
        },
        pipelined,
    ))
}

fn read_meek_request_body<R: Read>(reader: R, kind: Http1BodyKind, limit: usize) -> Result<Vec<u8>, String> {
    let mut body_reader = Http1BodyReader::new(reader, kind);
    let mut body = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = body_reader
            .read(&mut buf)
            .map_err(|e| format!("read request body: {e}"))?;
        if n == 0 {
            break;
        }
        if body.len() + n > limit {
            return Err(format!("request exceeds max_request_bytes ({limit})"));
        }
        body.extend_from_slice(&buf[..n]);
    }
    Ok(body)
}

fn write_meek_http1_response(stream: &mut TcpStream, body: &[u8]) -> io::Result<()> {
    stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\n\
             Cache-Control: no-store\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        )
        .as_bytes(),
    )?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush()
}

fn reject_meek_http1(stream: &mut TcpStream, status_line: &str) {
    let body = status_line.as_bytes();
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status_line}\r\n\
             Connection: close\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             \r\n",
            body.len()
        )
        .as_bytes(),
    );
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn spawn_meek_session(
    session_id: String,
    stream: RequestSessionStream,
    config: MeekConfig,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    metrics: Arc<wrongsv_metrics::Registry>,
) {
    std::thread::spawn(move || {
        let peer_label = format!("meek session={session_id}");
        let result =
            handle_vless_over_request_stream(stream, validator, kyber_sk, &peer_label, metrics);
        if let Err(e) = result {
            warn!("{peer_label} error: {e}");
        }
        config.sessions.remove(&session_id);
    });
}

pub(crate) fn handle_meek_connection(
    stream: TcpStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    meek_config: &MeekConfig,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} Meek connection");

    match &meek_config.tls_config {
        Some(tls_config) => {
            let plain = tls_relay(stream, tls_config, peer, "meek+tls")?;
            handle_meek_connection(
                plain,
                validator,
                kyber_sk,
                &MeekConfig {
                    tls_config: None,
                    ..meek_config.clone()
                },
                metrics,
            )
        }
        None => {
            let mut stream = stream;
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            stream.set_write_timeout(Some(Duration::from_secs(30)))?;
            stream.set_nodelay(true)?;

            let mut header_buf = Vec::new();
            stream_read_upgrade(&stream, &mut header_buf)?;
            let (request, initial_body) = match parse_meek_http1_request(
                &header_buf,
                &meek_config.path,
                meek_config.host.as_deref(),
            ) {
                Ok(request) => request,
                Err(e) => {
                    debug!("{peer} Meek rejected: {e}");
                    reject_meek_http1(&mut stream, "404 Not Found");
                    return Ok(());
                }
            };

            trace!("{peer} Meek request accepted session={}", request.session_id);
            let reader_stream = stream.try_clone()?;
            let body = match read_meek_request_body(
                PrefixedReader::new(initial_body, reader_stream),
                request.body_kind,
                meek_config.max_request_bytes,
            ) {
                Ok(body) => body,
                Err(e) => {
                    debug!("{peer} Meek body rejected: {e}");
                    reject_meek_http1(&mut stream, "400 Bad Request");
                    return Ok(());
                }
            };

            let lease = meek_config.sessions.acquire(&request.session_id);
            if let Some(session_stream) = lease.stream {
                spawn_meek_session(
                    request.session_id.clone(),
                    session_stream,
                    meek_config.clone(),
                    validator,
                    kyber_sk,
                    metrics.clone(),
                );
            }

            let response = lease
                .session
                .submit_roundtrip(&body, body.is_empty(), Duration::ZERO)
                .map_err(|e| format!("meek roundtrip: {e}"))?;
            write_meek_http1_response(&mut stream, &response)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Shutdown, SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::thread;

    use wrongsv_net_types::{Address, Port};
    use wrongsv_protocol::{ID, MemoryAccount, MemoryUser, RequestCommand, RequestHeader};
    use wrongsv_uuid::Uuid;
    use wrongsv_vless::Validator;
    use wrongsv_vless_encoding as encoding;

    const TEST_UUID: &str = "12345678-1234-1234-1234-123456789abc";

    fn test_validator() -> Arc<MemoryValidator> {
        let validator = Arc::new(MemoryValidator::new());
        let uuid = Uuid::parse_string(TEST_UUID).unwrap();
        validator
            .add(MemoryUser {
                account: MemoryAccount {
                    id: ID::new(uuid),
                    flow: String::new(),
                    encryption: String::new(),
                    udp: true,
                    xor_mode: 0,
                    seconds: 0,
                    padding: String::new(),
                    testpre: 0,
                    testseed: vec![],
                },
                email: "user@example.com".into(),
                level: 0,
            })
            .unwrap();
        validator
    }

    fn build_request(target: SocketAddr) -> RequestHeader {
        let uuid = Uuid::parse_string(TEST_UUID).unwrap();
        RequestHeader {
            version: 0,
            command: RequestCommand::Tcp,
            address: Address::parse(&target.ip().to_string()),
            port: Port(target.port()),
            user: MemoryUser {
                account: MemoryAccount {
                    id: ID::new(uuid),
                    flow: String::new(),
                    encryption: String::new(),
                    udp: true,
                    xor_mode: 0,
                    seconds: 0,
                    padding: String::new(),
                    testpre: 0,
                    testseed: vec![],
                },
                email: "user@example.com".into(),
                level: 0,
            },
        }
    }

    fn build_http_post(path: &str, session_id: &str, body: &[u8]) -> Vec<u8> {
        let mut request = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             X-Session-ID: {session_id}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        request
    }

    fn read_response_body(mut stream: TcpStream) -> Vec<u8> {
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        response.split_off(header_end + 4)
    }

    #[test]
    fn parse_http1_request_extracts_session_and_body_kind() {
        let request = b"POST /meek HTTP/1.1\r\n\
Host: Example.com:443\r\n\
X-Session-ID: abc123\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
4\r\n\
test\r\n";
        let (parsed, pipelined) =
            parse_meek_http1_request(request, "/meek", Some("example.com")).unwrap();
        assert_eq!(parsed.session_id, "abc123");
        assert_eq!(parsed.body_kind, Http1BodyKind::Chunked);
        assert_eq!(pipelined, b"4\r\ntest\r\n");
    }

    #[test]
    fn meek_connection_roundtrip_tcp_echo() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo_listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            stream.write_all(&buf[..n]).unwrap();
        });

        let validator = test_validator();
        let meek = parse_meek_config(&MeekServerConfig {
            path: "/meek".into(),
            host: None,
            max_request_bytes: 65_536,
            max_response_bytes: 65_536,
            idle_timeout: 5,
            tls: None,
        })
        .unwrap();
        let metrics = Arc::new(wrongsv_metrics::Registry::new());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();
        let validator_clone = Arc::clone(&validator);
        let metrics_clone = Arc::clone(&metrics);
        let meek_clone = meek.clone();
        let server_thread = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let mut served = 0usize;
            let mut idle_polls = 0usize;
            while served < 6 && idle_polls < 50 {
                match listener.accept() {
                    Ok((stream, _)) => {
                        served += 1;
                        idle_polls = 0;
                        handle_meek_connection(
                            stream,
                            Arc::clone(&validator_clone),
                            None,
                            &meek_clone,
                            Arc::clone(&metrics_clone),
                        )
                        .unwrap();
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        idle_polls += 1;
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept failed: {e}"),
                }
            }
        });

        let request = build_request(echo_addr);
        let mut body = bytes::BytesMut::new();
        encoding::encode_request_header(&mut body, &request, &encoding::Addons::default())
            .unwrap();
        body.extend_from_slice(b"hello meek");

        let mut first_stream = TcpStream::connect(server_addr).unwrap();
        first_stream
            .write_all(&build_http_post("/meek", "session-1", body.as_ref()))
            .unwrap();
        first_stream.shutdown(Shutdown::Write).unwrap();
        let mut collected = read_response_body(first_stream);
        for _ in 0..4 {
            let mut poll_stream = TcpStream::connect(server_addr).unwrap();
            poll_stream
                .write_all(&build_http_post("/meek", "session-1", &[]))
                .unwrap();
            poll_stream.shutdown(Shutdown::Write).unwrap();
            collected.extend_from_slice(&read_response_body(poll_stream));
        }

        assert!(!collected.is_empty());
        let mut cursor = std::io::Cursor::new(collected.as_slice());
        encoding::decode_response_header(&mut cursor, &request).unwrap();
        let payload = collected[cursor.position() as usize..].to_vec();

        assert_eq!(payload, b"hello meek");

        server_thread.join().unwrap();
        echo_thread.join().unwrap();
    }
}
