use std::io::{self, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use tokio::sync::mpsc as tokio_mpsc;

use http::StatusCode;
use tracing::{debug, trace};
use wrongsv_protocol::{RequestCommand, RequestHeader};
use wrongsv_vless::MemoryValidator;

use crate::config::XhttpServerConfig;

use super::*;

const MAX_XHTTP_HEADER_SIZE: usize = 16 * 1024;
const H2_PREFACE_PREFIX: &[u8; 3] = b"PRI";

fn is_graceful_h2_stream_end(error: &h2::Error) -> bool {
    matches!(
        error.reason(),
        Some(reason)
            if reason == h2::Reason::CANCEL
                || reason == h2::Reason::NO_ERROR
                || reason == h2::Reason::STREAM_CLOSED
    )
}

// ── Config ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct XhttpConfig {
    pub path: String,
    pub host: Option<String>,
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
    #[allow(dead_code)]
    pub tls_dest: Option<String>,
}

pub(crate) fn parse_xhttp_config(xc: &XhttpServerConfig) -> Result<XhttpConfig, String> {
    let (tls_config, tls_dest) = match &xc.tls {
        Some(tls) => {
            let (cert_pem, key_pem) = match (&tls.certificate, &tls.key) {
                (Some(c), Some(k)) => (c.clone(), k.clone()),
                _ => {
                    let (cert, key) = wrongsv_anytls::generate_self_signed_cert()
                        .map_err(|e| format!("xhttp tls cert: {e}"))?;
                    (cert, key)
                }
            };
            let server_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
                .map_err(|e| format!("xhttp tls config: {e}"))?;
            (Some(Arc::new(server_config)), tls.dest.clone())
        }
        None => (None, None),
    };
    let path = xc.path.clone().unwrap_or_else(|| "/xhttp".into());
    Ok(XhttpConfig {
        path,
        host: xc.host.clone(),
        tls_config,
        tls_dest,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XhttpWireProtocol {
    Http1,
    Http2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Http1BodyKind {
    Chunked,
    ContentLength(usize),
    UntilEof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Http1ResponseMode {
    Chunked,
    Raw,
}

#[derive(Debug)]
struct Http1XhttpRequest {
    path: String,
    body_kind: Http1BodyKind,
    response_mode: Http1ResponseMode,
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
        let chunk_len = line.trim().split(';').next().unwrap_or("").trim();
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

struct Http1ChunkedWriter {
    stream: TcpStream,
    finished: bool,
}

impl Http1ChunkedWriter {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            finished: false,
        }
    }

    fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.stream.write_all(b"0\r\n\r\n")?;
        self.stream.flush()?;
        self.finished = true;
        Ok(())
    }
}

impl Write for Http1ChunkedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP HTTP/1.1 response already finished",
            ));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        self.stream
            .write_all(format!("{:X}\r\n", buf.len()).as_bytes())?;
        self.stream.write_all(buf)?;
        self.stream.write_all(b"\r\n")?;
        self.stream.flush()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
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
        if buf.len() > MAX_XHTTP_HEADER_SIZE {
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

fn normalize_xhttp_host(value: &str) -> String {
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

fn xhttp_host_matches(expected: &str, actual: &str) -> bool {
    normalize_xhttp_host(expected) == normalize_xhttp_host(actual)
}

fn detect_xhttp_wire_protocol(stream: &TcpStream) -> io::Result<XhttpWireProtocol> {
    let mut peek = [0u8; H2_PREFACE_PREFIX.len()];
    let start = std::time::Instant::now();
    loop {
        match stream.peek(&mut peek) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before XHTTP preface",
                ));
            }
            Ok(n) if n >= H2_PREFACE_PREFIX.len() => {
                return if &peek[..H2_PREFACE_PREFIX.len()] == H2_PREFACE_PREFIX {
                    Ok(XhttpWireProtocol::Http2)
                } else {
                    Ok(XhttpWireProtocol::Http1)
                };
            }
            Ok(_) => {
                if start.elapsed() >= Duration::from_secs(30) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for XHTTP preface",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if start.elapsed() >= Duration::from_secs(30) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for XHTTP preface",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
}

fn parse_xhttp_http1_request(
    buf: &[u8],
    path: &str,
    host: Option<&str>,
) -> Result<(Http1XhttpRequest, Vec<u8>), String> {
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "incomplete HTTP/1.1 headers".to_string())?;
    if header_end + 4 > MAX_XHTTP_HEADER_SIZE {
        return Err(format!("header too large (>{MAX_XHTTP_HEADER_SIZE}B)"));
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
    if method != "POST" && method != "PUT" {
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
            "host" => request_host = Some(normalize_xhttp_host(value)),
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
        if !xhttp_host_matches(expected_host, got) {
            return Err(format!(
                "host mismatch: expected {expected_host}, got {got}"
            ));
        }
    }

    let body_kind = if has_chunked_encoding {
        Http1BodyKind::Chunked
    } else if let Some(content_length) = content_length {
        Http1BodyKind::ContentLength(content_length)
    } else {
        Http1BodyKind::UntilEof
    };

    Ok((
        Http1XhttpRequest {
            path: normalized_path,
            body_kind,
            response_mode: if method == "PUT" {
                Http1ResponseMode::Raw
            } else {
                Http1ResponseMode::Chunked
            },
        },
        pipelined,
    ))
}

fn reject_xhttp_http1(stream: &mut TcpStream) {
    let _ = stream.write_all(
        b"HTTP/1.1 404 Not Found\r\n\
          Connection: close\r\n\
          Content-Length: 0\r\n\
          \r\n",
    );
}

fn write_xhttp_http1_response(stream: &mut TcpStream, mode: Http1ResponseMode) -> io::Result<()> {
    match mode {
        Http1ResponseMode::Chunked => stream.write_all(
            b"HTTP/1.1 200 OK\r\n\
              X-Accel-Buffering: no\r\n\
              Cache-Control: no-store\r\n\
              Content-Type: text/event-stream\r\n\
              Transfer-Encoding: chunked\r\n\
              Connection: close\r\n\
              \r\n",
        )?,
        Http1ResponseMode::Raw => stream.write_all(
            b"HTTP/1.1 200 OK\r\n\
              Cache-Control: no-store\r\n\
              Content-Type: application/octet-stream\r\n\
              Connection: close\r\n\
              \r\n",
        )?,
    }
    stream.flush()
}

// ── XHTTP stream bridge ───────────────────────────────────────────────

pub(crate) struct XhttpStream {
    incoming_rx: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    outgoing_tx: tokio_mpsc::Sender<Vec<u8>>,
    eof: bool,
}

pub(crate) struct XhttpReader {
    incoming_rx: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    eof: bool,
}

#[derive(Clone)]
pub(crate) struct XhttpWriter {
    outgoing_tx: tokio_mpsc::Sender<Vec<u8>>,
}

impl XhttpStream {
    fn from_channels(
        incoming_rx: Receiver<Vec<u8>>,
        outgoing_tx: tokio_mpsc::Sender<Vec<u8>>,
    ) -> Self {
        XhttpStream {
            incoming_rx,
            pending: Vec::new(),
            outgoing_tx,
            eof: false,
        }
    }

    fn split(self) -> (XhttpReader, XhttpWriter) {
        (
            XhttpReader {
                incoming_rx: self.incoming_rx,
                pending: self.pending,
                eof: self.eof,
            },
            XhttpWriter {
                outgoing_tx: self.outgoing_tx,
            },
        )
    }
}

impl Read for XhttpReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }
        if self.eof {
            return Ok(0);
        }
        match self.incoming_rx.recv() {
            Ok(data) => {
                if data.len() <= buf.len() {
                    let n = data.len();
                    buf[..n].copy_from_slice(&data);
                    Ok(n)
                } else {
                    let n = buf.len();
                    buf[..n].copy_from_slice(&data[..n]);
                    self.pending.extend_from_slice(&data[n..]);
                    Ok(n)
                }
            }
            Err(_) => {
                self.eof = true;
                Ok(0)
            }
        }
    }
}

impl Write for XhttpWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outgoing_tx
            .blocking_send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for XhttpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }
        if self.eof {
            return Ok(0);
        }
        match self.incoming_rx.recv() {
            Ok(data) => {
                if data.len() <= buf.len() {
                    let n = data.len();
                    buf[..n].copy_from_slice(&data);
                    Ok(n)
                } else {
                    let n = buf.len();
                    buf[..n].copy_from_slice(&data[..n]);
                    self.pending.extend_from_slice(&data[n..]);
                    Ok(n)
                }
            }
            Err(_) => {
                self.eof = true;
                Ok(0)
            }
        }
    }
}

impl Write for XhttpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.eof {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP stream closed",
            ));
        }
        self.outgoing_tx
            .blocking_send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP stream closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ── HTTP/2 driver (async, runs in tokio) ──────────────────────────────

async fn drive_xhttp_connection(
    tcp: TcpStream,
    peer: std::net::SocketAddr,
    path: &str,
    host: Option<&str>,
    validator: Arc<MemoryValidator>,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tcp.set_nonblocking(true)?;
    let tcp = tokio::net::TcpStream::from_std(tcp)?;
    tcp.set_nodelay(true)?;

    let mut conn = h2::server::Builder::new()
        .initial_window_size(1_048_576) // 1 MiB — avoids flow-control stalls
        .handshake(tcp)
        .await
        .map_err(|e| format!("h2 handshake: {e}"))?;
    trace!("{peer} HTTP/2 handshake done");

    let (request_tx, mut request_rx) = tokio_mpsc::channel(32);
    let conn_handle = tokio::spawn(async move {
        loop {
            match conn.accept().await {
                Some(Ok(stream)) => {
                    if request_tx.send(Ok(stream)).await.is_err() {
                        break;
                    }
                }
                Some(Err(e)) => {
                    let _ = request_tx.send(Err(format!("h2 accept: {e}"))).await;
                    break;
                }
                None => break,
            }
        }
    });

    while let Some(item) = request_rx.recv().await {
        let (request, respond) = item.map_err(|e| format!("XHTTP connection error: {e}"))?;
        handle_xhttp_request_stream(
            request,
            respond,
            peer,
            path,
            host,
            Arc::clone(&validator),
            Arc::clone(&metrics),
        )
        .await?;
    }

    let _ = conn_handle.await;
    Ok(())
}

fn reject_xhttp(mut respond: h2::server::SendResponse<bytes::Bytes>) {
    let resp = http::Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(())
        .unwrap();
    let _ = respond.send_response(resp, true);
}

async fn handle_xhttp_request_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    peer: std::net::SocketAddr,
    path: &str,
    host: Option<&str>,
    validator: Arc<MemoryValidator>,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (parts, body) = request.into_parts();

    if parts.method != http::Method::POST {
        debug!("{peer} XHTTP rejected: method={}", parts.method);
        reject_xhttp(respond);
        return Ok(());
    }

    if !parts.uri.path().starts_with(path) {
        debug!(
            "{peer} XHTTP path mismatch: expected prefix {path}, got {}",
            parts.uri.path()
        );
        reject_xhttp(respond);
        return Ok(());
    }

    if let Some(expected_host) = host {
        let req_host = parts
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !xhttp_host_matches(expected_host, req_host) {
            debug!("{peer} XHTTP host mismatch: expected {expected_host}, got {req_host}");
            reject_xhttp(respond);
            return Ok(());
        }
    }

    trace!("{peer} XHTTP stream accepted at {path}");

    let resp = http::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .unwrap();
    let mut send = respond
        .send_response(resp, false)
        .map_err(|e| format!("send response: {e}"))?;

    let (incoming_tx, incoming_rx) = mpsc::sync_channel::<Vec<u8>>(64);
    let (outgoing_tx, outgoing_rx) = tokio_mpsc::channel::<Vec<u8>>(256);

    let relay_handle = tokio::task::spawn_blocking(move || {
        let xhttp_stream = XhttpStream::from_channels(incoming_rx, outgoing_tx);
        handle_vless_over_xhttp(xhttp_stream, validator, peer, metrics).map_err(|e| e.to_string())
    });

    let outgoing_handle =
        tokio::spawn(async move { drive_outgoing(&mut send, outgoing_rx, peer).await });
    let incoming_result = drive_incoming(body, &incoming_tx).await;
    drop(incoming_tx);

    let relay_result = relay_handle
        .await
        .map_err(|e| format!("XHTTP relay panic: {e}"))?;
    let outgoing_result = outgoing_handle
        .await
        .map_err(|e| format!("XHTTP outgoing panic: {e}"))?;

    outgoing_result?;
    relay_result.map_err(|e| format!("XHTTP relay: {e}"))?;
    incoming_result
}

async fn drive_incoming(
    mut body: h2::RecvStream,
    incoming_tx: &mpsc::SyncSender<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        match body.data().await {
            Some(Ok(data)) => {
                if incoming_tx.send(data.to_vec()).is_err() {
                    return Ok(()); // relay stopped
                }
            }
            Some(Err(e)) if is_graceful_h2_stream_end(&e) => return Ok(()),
            Some(Err(e)) => return Err(format!("h2 stream error: {e}").into()),
            None => return Ok(()),
        }
    }
}

async fn drive_outgoing(
    send: &mut h2::SendStream<bytes::Bytes>,
    mut outgoing_rx: tokio_mpsc::Receiver<Vec<u8>>,
    peer: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        match outgoing_rx.recv().await {
            Some(data) => match send.send_data(data.into(), false) {
                Ok(()) => {}
                Err(e) if is_graceful_h2_stream_end(&e) => return Ok(()),
                Err(e) => return Err(format!("h2 send data: {e}").into()),
            },
            None => {
                // Channel closed — relay finished
                let _ = send.send_data(bytes::Bytes::new(), true);
                trace!("{peer} XHTTP stream finished OK");
                return Ok(());
            }
        }
    }
}

fn drive_incoming_http1<R: Read>(
    mut body: R,
    incoming_tx: mpsc::SyncSender<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = [0u8; 8192];
    loop {
        let n = body.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        if incoming_tx.send(buf[..n].to_vec()).is_err() {
            return Ok(());
        }
    }
}

fn drive_outgoing_http1(
    mut stream: TcpStream,
    mode: Http1ResponseMode,
    mut outgoing_rx: tokio_mpsc::Receiver<Vec<u8>>,
    peer: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match mode {
        Http1ResponseMode::Chunked => {
            let mut writer = Http1ChunkedWriter::new(stream);
            while let Some(data) = outgoing_rx.blocking_recv() {
                writer.write_all(&data)?;
            }
            writer.finish()?;
        }
        Http1ResponseMode::Raw => {
            while let Some(data) = outgoing_rx.blocking_recv() {
                stream.write_all(&data)?;
                stream.flush()?;
            }
            let _ = stream.shutdown(std::net::Shutdown::Write);
        }
    }
    trace!("{peer} XHTTP/1.1 stream finished OK");
    Ok(())
}

fn drive_xhttp_http1_connection(
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
    path: &str,
    host: Option<&str>,
    validator: Arc<MemoryValidator>,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut header_buf = Vec::new();
    stream_read_upgrade(&stream, &mut header_buf)?;
    let (request, initial_body) = match parse_xhttp_http1_request(&header_buf, path, host) {
        Ok(request) => request,
        Err(e) => {
            debug!("{peer} XHTTP/1.1 rejected: {e}");
            reject_xhttp_http1(&mut stream);
            return Ok(());
        }
    };

    trace!("{peer} XHTTP/1.1 stream accepted at {}", request.path);
    stream.set_read_timeout(None)?;
    stream.set_nodelay(true)?;
    let reader_stream = stream.try_clone()?;
    write_xhttp_http1_response(&mut stream, request.response_mode)?;

    let body_reader = Http1BodyReader::new(
        PrefixedReader::new(initial_body, reader_stream),
        request.body_kind,
    );
    let (incoming_tx, incoming_rx) = mpsc::sync_channel::<Vec<u8>>(64);
    let (outgoing_tx, outgoing_rx) = tokio_mpsc::channel::<Vec<u8>>(256);

    let incoming_handle = std::thread::spawn(move || {
        drive_incoming_http1(body_reader, incoming_tx).map_err(|e| e.to_string())
    });
    let response_mode = request.response_mode;
    let outgoing_handle = std::thread::spawn(move || {
        drive_outgoing_http1(stream, response_mode, outgoing_rx, peer).map_err(|e| e.to_string())
    });

    let relay_result = handle_vless_over_xhttp(
        XhttpStream::from_channels(incoming_rx, outgoing_tx),
        validator,
        peer,
        metrics,
    )
    .map_err(|e| e.to_string());
    let incoming_result = incoming_handle
        .join()
        .map_err(|_| "XHTTP/1.1 incoming thread panicked".to_string())?;
    let outgoing_result = outgoing_handle
        .join()
        .map_err(|_| "XHTTP/1.1 outgoing thread panicked".to_string())?;

    relay_result.map_err(|e| format!("XHTTP/1.1 relay: {e}"))?;
    incoming_result.map_err(|e| format!("XHTTP/1.1 incoming: {e}"))?;
    outgoing_result.map_err(|e| format!("XHTTP/1.1 outgoing: {e}"))?;
    Ok(())
}

// ── Connection handler (sync entry point) ─────────────────────────────

pub(crate) fn handle_xhttp_connection(
    stream: TcpStream,
    validator: Arc<MemoryValidator>,
    xhttp_config: &XhttpConfig,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} XHTTP connection");

    match &xhttp_config.tls_config {
        Some(tls_config) => {
            // TLS+XHTTP: handshake, then relay through local TCP bridge
            // so the existing async h2 handler sees a plaintext stream.
            let plain = tls_relay(stream, tls_config, peer, "xhttp+tls")?;
            handle_xhttp_connection(
                plain,
                validator,
                &XhttpConfig {
                    tls_config: None,
                    ..xhttp_config.clone()
                },
                metrics,
            )
        }
        None => {
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            match detect_xhttp_wire_protocol(&stream)? {
                XhttpWireProtocol::Http2 => {
                    let rt = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()
                        .map_err(|e| format!("XHTTP runtime: {e}"))?;
                    rt.block_on(drive_xhttp_connection(
                        stream,
                        peer,
                        &xhttp_config.path,
                        xhttp_config.host.as_deref(),
                        validator,
                        metrics,
                    ))
                    .map_err(|e| format!("XHTTP: {e}").into())
                }
                XhttpWireProtocol::Http1 => drive_xhttp_http1_connection(
                    stream,
                    peer,
                    &xhttp_config.path,
                    xhttp_config.host.as_deref(),
                    validator,
                    metrics,
                )
                .map_err(|e| format!("XHTTP: {e}").into()),
            }
        }
    }
}

fn handle_vless_over_xhttp(
    mut stream: XhttpStream,
    validator: Arc<MemoryValidator>,
    peer: std::net::SocketAddr,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut first = vec![0u8; 8192];
    let n = stream.read(&mut first)?;
    if n == 0 {
        return Err("XHTTP closed before VLESS header".into());
    }
    first.truncate(n);
    trace!("{peer} XHTTP read {} bytes VLESS header", first.len());

    let VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    } = decode_vless_request(first, &validator, peer)?;

    let request = &decoded.header;
    let account = &request.user.account;

    log_vless_request(peer, request);
    trace!(
        "{peer} XHTTP flow={} use_vision={use_vision}",
        decoded.addons.flow
    );
    validate_vless_command(request, use_vision)?;
    let tap = wrongsv_metrics::MetricsTap::new(metrics, request.user.email.clone());
    let _conn_guard = tap.track_connection();

    let resp_buf = response_header_buf(request)?;
    stream.write_all(&resp_buf)?;

    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_xhttp_udp(&mut stream, request, remaining_body, tap)?;
        debug!("{peer} XHTTP UDP relay finished");
        return Ok(());
    }

    let target = connect_tcp_target(&request.address, request.port)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;

    if use_vision {
        relay_xhttp_vision(
            &mut stream,
            target,
            &decoded.user_sent_id,
            &account.testseed,
            remaining_body,
            tap,
        )?;
    } else {
        relay_xhttp_raw(stream, target, remaining_body, tap)?;
    }
    debug!("{peer} XHTTP relay finished");
    Ok(())
}

// ── XHTTP relay functions ─────────────────────────────────────────────

fn relay_xhttp_raw(
    client: XhttpStream,
    mut target: TcpStream,
    initial_data: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    target.set_nodelay(true)?;
    if !initial_data.is_empty() {
        metrics.record_in(initial_data.len() as u64);
        target.write_all(&initial_data)?;
    }
    let (mut reader, mut writer) = client.split();
    let mut target_write = target.try_clone()?;
    let mut target_read = target;
    let metrics_up = metrics.clone();
    let metrics_down = metrics;

    let up = std::thread::spawn(move || {
        let mut buf = [0u8; 32768];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    metrics_up.record_in(n as u64);
                    if let Err(e) = target_write.write_all(&buf[..n]) {
                        debug!("XHTTP uplink write error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("XHTTP uplink read error: {e}");
                    break;
                }
            }
        }
        let _ = target_write.shutdown(std::net::Shutdown::Write);
    });

    let down = std::thread::spawn(move || {
        let mut buf = [0u8; 32768];
        loop {
            match target_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    metrics_down.record_out(n as u64);
                    if let Err(e) = writer.write_all(&buf[..n]) {
                        debug!("XHTTP downlink write error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("XHTTP downlink read error: {e}");
                    break;
                }
            }
        }
    });

    let _ = up.join();
    let _ = down.join();
    Ok(())
}

fn relay_xhttp_vision(
    client: &mut XhttpStream,
    mut target: TcpStream,
    user_sent_id: &[u8],
    testseed: &[u32],
    initial_data: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    let up_seed = if testseed.len() >= 4 {
        testseed.to_vec()
    } else {
        vec![900, 500, 900, 256]
    };
    let mut up_state = wrongsv_vless::vision::TrafficState::new(user_sent_id);
    let mut down_state = wrongsv_vless::vision::TrafficState::new(user_sent_id);
    let mut down_user_uuid: Option<[u8; 16]> = Some(down_state.user_uuid);

    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_millis(10)))?;
    let mut buf = [0u8; 32768];

    if !initial_data.is_empty() {
        let unpadded = wrongsv_vless::vision::xtls_unpadding(&initial_data, &mut up_state, true);
        if !unpadded.is_empty() {
            metrics.record_in(unpadded.len() as u64);
            target.write_all(&unpadded)?;
            target.set_read_timeout(Some(Duration::from_millis(10)))?;
        }
    }

    loop {
        // Downlink: target → Vision encode → XHTTP
        let down_done = loop {
            match target.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => {
                    let mut encoded = Vec::with_capacity(n + 256);
                    {
                        struct BufWriter<'a>(&'a mut Vec<u8>);
                        impl Write for BufWriter<'_> {
                            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                                self.0.extend_from_slice(data);
                                Ok(data.len())
                            }
                            fn flush(&mut self) -> io::Result<()> {
                                Ok(())
                            }
                        }
                        let mut w = wrongsv_vless::vision::VisionWriter::new(
                            BufWriter(&mut encoded),
                            down_state.clone(),
                            false,
                            up_seed.clone(),
                        );
                        w.user_uuid = down_user_uuid.take();
                        w.write(&buf[..n])?;
                        w.flush()?;
                        down_state = w.state;
                        down_user_uuid = w.user_uuid;
                    }
                    if !encoded.is_empty() {
                        metrics.record_out(n as u64);
                        client.write_all(&encoded)?;
                    }
                    target.set_read_timeout(Some(Duration::from_millis(10)))?;
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    target.set_read_timeout(Some(Duration::from_millis(10)))?;
                    break false;
                }
                Err(e) => return Err(e.into()),
            }
        };

        // Uplink: XHTTP → Vision decode → target
        let up_done = loop {
            match client.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => {
                    let unpadded =
                        wrongsv_vless::vision::xtls_unpadding(&buf[..n], &mut up_state, true);
                    if !unpadded.is_empty() {
                        metrics.record_in(unpadded.len() as u64);
                        target.write_all(&unpadded)?;
                        target.set_read_timeout(Some(Duration::from_millis(10)))?;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break false,
                Err(e) => return Err(e.into()),
            }
        };

        if up_done {
            let _ = target.shutdown(std::net::Shutdown::Write);
        }
        if down_done {
            break;
        }
        if up_done && down_done {
            break;
        }
    }
    Ok(())
}

fn relay_xhttp_udp(
    client: &mut XhttpStream,
    request: &RequestHeader,
    remaining: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Cursor, ErrorKind};
    use wrongsv_vless_encoding::{LengthPacketReader, LengthPacketWriter, PacketReadError};

    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("XHTTP UDP relay to {target_addr}");

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(&target_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut buf = [0u8; 65535];

    if !remaining.is_empty() {
        let mut reader = LengthPacketReader::new(Cursor::new(&remaining));
        while let Ok(pkt) = reader.read_packet() {
            metrics.record_in(pkt.len() as u64);
            socket.send(&pkt)?;
        }
    }

    loop {
        let xhttp_data = {
            let mut tmp = [0u8; 65535];
            match client.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    let mut reader = LengthPacketReader::new(Cursor::new(&tmp[..n]));
                    let mut pkts = Vec::new();
                    loop {
                        match reader.read_packet() {
                            Ok(pkt) => pkts.push(pkt),
                            Err(PacketReadError::Io(ref e))
                                if e.kind() == ErrorKind::UnexpectedEof =>
                            {
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                    Some(pkts)
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => None,
                Err(e) => return Err(e.into()),
            }
        };

        if let Some(pkts) = xhttp_data {
            for pkt in pkts {
                metrics.record_in(pkt.len() as u64);
                socket.send(&pkt)?;
            }
        }

        match socket.recv(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                metrics.record_out(n as u64);
                let mut packet = Vec::with_capacity(n + 2);
                LengthPacketWriter::new(&mut packet).write_packet(&buf[..n])?;
                client.write_all(&packet)?;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_path() {
        let cfg = XhttpServerConfig {
            path: None,
            host: None,
            tls: None,
        };
        let xhttp = parse_xhttp_config(&cfg).unwrap();
        assert_eq!(xhttp.path, "/xhttp");
    }

    #[test]
    fn parse_custom_path() {
        let cfg = XhttpServerConfig {
            path: Some("/custom".into()),
            host: None,
            tls: None,
        };
        let xhttp = parse_xhttp_config(&cfg).unwrap();
        assert_eq!(xhttp.path, "/custom");
    }

    #[test]
    fn parse_with_host() {
        let cfg = XhttpServerConfig {
            path: None,
            host: Some("example.com".into()),
            tls: None,
        };
        let xhttp = parse_xhttp_config(&cfg).unwrap();
        assert_eq!(xhttp.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn parse_http1_chunked_request_with_host_port() {
        let request = b"POST /xhttp HTTP/1.1\r\n\
Host: Example.com:443\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
4\r\n\
test\r\n";
        let (parsed, pipelined) =
            parse_xhttp_http1_request(request, "/xhttp", Some("example.com")).unwrap();
        assert_eq!(parsed.path, "/xhttp");
        assert_eq!(parsed.body_kind, Http1BodyKind::Chunked);
        assert_eq!(parsed.response_mode, Http1ResponseMode::Chunked);
        assert_eq!(pipelined, b"4\r\ntest\r\n");
    }

    #[test]
    fn parse_http1_put_request_until_eof() {
        let request = b"PUT /xhttp HTTP/1.1\r\n\
Host: localhost\r\n\
\r\n\
\x00";
        let (parsed, pipelined) = parse_xhttp_http1_request(request, "/xhttp", None).unwrap();
        assert_eq!(parsed.path, "/xhttp");
        assert_eq!(parsed.body_kind, Http1BodyKind::UntilEof);
        assert_eq!(parsed.response_mode, Http1ResponseMode::Raw);
        assert_eq!(pipelined, b"\x00");
    }
}
