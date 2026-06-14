//! Naive proxy inbound (HTTP/2 CONNECT over TLS with padded framing).
//!
//! Implements naive v1: TLS + h2 CONNECT + HTTP Basic auth via
//! `Proxy-Authorization` + the `Padding` header capability flag + the
//! first-8 operations of each direction wrapped in the 3-byte
//! `[u16 BE payload_len][u8 padding_len]` framing.
//!
//! RST_STREAM obfuscation and the HTTP/3 variant are out of v1 scope —
//! see `docs/deferred-work.md`. The fallback-destination behavior
//! declared in the endpoint registry is not yet implemented on the
//! handler side; an unauthenticated request is rejected with
//! `407 Proxy Authentication Required` rather than relayed to
//! `tls.dest`.

use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, Method, Response, StatusCode};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, trace};

use crate::config::NaiveServerConfig;

use super::*;

// ── Config ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub(crate) struct NaiveUser {
    pub username: String,
    pub password: String,
    pub email: String,
}

#[derive(Clone)]
pub(crate) struct NaiveConfig {
    pub tls_config: Arc<rustls::ServerConfig>,
    pub users: Vec<NaiveUser>,
    pub padding_header_name: HeaderName,
    #[allow(dead_code)]
    pub tls_dest: Option<String>,
}

pub(crate) fn parse_naive_config(nc: &NaiveServerConfig) -> Result<NaiveConfig, String> {
    let (cert_pem, key_pem) = match (&nc.tls.certificate, &nc.tls.key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => wrongsv_anytls::generate_self_signed_cert()
            .map_err(|e| format!("naive tls cert: {e}"))?,
    };
    let mut server_config = wrongsv_anytls::build_tls_config(&cert_pem, &key_pem)
        .map_err(|e| format!("naive tls config: {e}"))?;
    server_config.alpn_protocols = vec![b"h2".to_vec()];

    let users = nc
        .users
        .iter()
        .map(|u| NaiveUser {
            username: u.username.clone(),
            password: u.password.clone(),
            email: u.email.clone(),
        })
        .collect();

    let padding_header_name = HeaderName::from_bytes(nc.padding_header_name.as_bytes())
        .map_err(|e| format!("naive padding header name: {e}"))?;

    Ok(NaiveConfig {
        tls_config: Arc::new(server_config),
        users,
        padding_header_name,
        tls_dest: nc.tls.dest.clone(),
    })
}

// ── Padded codec ──────────────────────────────────────────────────────
//
// Wire format for the first 8 operations in each direction:
//   [u16 BE payload_len][u8 padding_len]<payload><padding>
// After 8 ops in a given direction, the stream switches to raw
// passthrough — no further framing is applied or expected.

const NAIVE_PAD_OPS: usize = 8;
const NAIVE_PAD_MAX_PAYLOAD: usize = u16::MAX as usize;

enum PadDecodeState {
    Header,
    Payload { remaining: usize, padding: usize },
    Padding(usize),
    Passthrough,
}

struct NaivePadDecoder {
    buf: Vec<u8>,
    state: PadDecodeState,
    ops_remaining: usize,
}

impl NaivePadDecoder {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            state: PadDecodeState::Header,
            ops_remaining: NAIVE_PAD_OPS,
        }
    }

    fn feed_into(&mut self, input: &[u8], out: &mut Vec<u8>) {
        self.buf.extend_from_slice(input);
        loop {
            let next = match self.state {
                PadDecodeState::Passthrough => {
                    out.extend_from_slice(&self.buf);
                    self.buf.clear();
                    return;
                }
                PadDecodeState::Header => {
                    if self.buf.len() < 3 {
                        return;
                    }
                    let payload_len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
                    let padding = self.buf[2] as usize;
                    self.buf.drain(..3);
                    PadDecodeState::Payload {
                        remaining: payload_len,
                        padding,
                    }
                }
                PadDecodeState::Payload { remaining, padding } => {
                    let take = remaining.min(self.buf.len());
                    out.extend_from_slice(&self.buf[..take]);
                    self.buf.drain(..take);
                    let remaining = remaining - take;
                    if remaining == 0 {
                        PadDecodeState::Padding(padding)
                    } else {
                        self.state = PadDecodeState::Payload { remaining, padding };
                        return;
                    }
                }
                PadDecodeState::Padding(remaining) => {
                    let take = remaining.min(self.buf.len());
                    self.buf.drain(..take);
                    let remaining = remaining - take;
                    if remaining == 0 {
                        self.ops_remaining = self.ops_remaining.saturating_sub(1);
                        if self.ops_remaining == 0 {
                            PadDecodeState::Passthrough
                        } else {
                            PadDecodeState::Header
                        }
                    } else {
                        self.state = PadDecodeState::Padding(remaining);
                        return;
                    }
                }
            };
            self.state = next;
        }
    }
}

struct NaivePadEncoder {
    ops_remaining: usize,
}

impl NaivePadEncoder {
    fn new() -> Self {
        Self {
            ops_remaining: NAIVE_PAD_OPS,
        }
    }

    fn encode(&mut self, payload: &[u8]) -> Vec<u8> {
        if self.ops_remaining == 0 || payload.is_empty() {
            return payload.to_vec();
        }
        let mut rng = rand::thread_rng();
        let mut out = Vec::with_capacity(payload.len() + 256);
        let mut cursor = 0;
        while cursor < payload.len() && self.ops_remaining > 0 {
            let chunk_len = (payload.len() - cursor).min(NAIVE_PAD_MAX_PAYLOAD);
            let pad_len = (rng.next_u32() & 0xff) as u8;
            out.push((chunk_len >> 8) as u8);
            out.push(chunk_len as u8);
            out.push(pad_len);
            out.extend_from_slice(&payload[cursor..cursor + chunk_len]);
            if pad_len > 0 {
                let mut pad = vec![0u8; pad_len as usize];
                rng.fill_bytes(&mut pad);
                out.extend_from_slice(&pad);
            }
            cursor += chunk_len;
            self.ops_remaining -= 1;
        }
        if cursor < payload.len() {
            out.extend_from_slice(&payload[cursor..]);
        }
        out
    }
}

// ── HTTP Basic auth ───────────────────────────────────────────────────

fn match_basic_credential(value: &str, users: &[NaiveUser]) -> Option<NaiveUser> {
    use base64::Engine;
    let token = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token.trim())
        .ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    users
        .iter()
        .find(|u| u.username == user && u.password == pass)
        .cloned()
}

fn random_padding_header_value() -> String {
    // Reference impl emits 30-62 non-Huffman bytes — ASCII digits keep
    // the value out of the HPACK static dictionary so it costs roughly
    // its byte count on the wire.
    let mut rng = rand::thread_rng();
    let len = 30 + (rng.next_u32() as usize % 33);
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let digit = b'0' + (rng.next_u32() % 10) as u8;
        s.push(digit as char);
    }
    s
}

// ── Connection driver ─────────────────────────────────────────────────

fn is_graceful_naive_h2(error: &h2::Error) -> bool {
    matches!(
        error.reason(),
        Some(reason)
            if reason == h2::Reason::CANCEL
                || reason == h2::Reason::NO_ERROR
                || reason == h2::Reason::STREAM_CLOSED
    )
}

pub(crate) fn handle_naive_connection(
    stream: TcpStream,
    config: &NaiveConfig,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} Naive connection");
    let plain = tls_relay(stream, &config.tls_config, peer, "naive+tls")?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("Naive runtime: {e}"))?;
    rt.block_on(drive_naive_connection(plain, peer, config.clone(), metrics))
        .map_err(|e| format!("Naive: {e}"))?;
    Ok(())
}

async fn drive_naive_connection(
    tcp: TcpStream,
    peer: std::net::SocketAddr,
    config: NaiveConfig,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tcp.set_nonblocking(true)?;
    let tcp = tokio::net::TcpStream::from_std(tcp)?;
    tcp.set_nodelay(true)?;

    let mut conn = h2::server::Builder::new()
        .initial_window_size(1_048_576)
        .handshake(tcp)
        .await
        .map_err(|e| format!("h2 handshake: {e}"))?;
    trace!("{peer} Naive HTTP/2 handshake done");

    let config = Arc::new(config);
    while let Some(item) = conn.accept().await {
        let (request, respond) = item.map_err(|e| format!("Naive accept: {e}"))?;
        let config_clone = Arc::clone(&config);
        let metrics_clone = Arc::clone(&metrics);
        tokio::spawn(async move {
            if let Err(e) =
                handle_naive_request(request, respond, peer, config_clone, metrics_clone).await
            {
                debug!("{peer} Naive request error: {e}");
            }
        });
    }
    Ok(())
}

async fn handle_naive_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    peer: std::net::SocketAddr,
    config: Arc<NaiveConfig>,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (parts, body) = request.into_parts();

    if parts.method != Method::CONNECT {
        debug!("{peer} Naive rejected: method={}", parts.method);
        reject_naive(&mut respond, StatusCode::METHOD_NOT_ALLOWED);
        return Ok(());
    }

    let Some(authority) = parts.uri.authority().cloned() else {
        debug!("{peer} Naive rejected: missing :authority");
        reject_naive(&mut respond, StatusCode::BAD_REQUEST);
        return Ok(());
    };
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(443);
    if host.is_empty() {
        reject_naive(&mut respond, StatusCode::BAD_REQUEST);
        return Ok(());
    }

    let auth_header = parts
        .headers
        .get(http::header::PROXY_AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let user = match auth_header.and_then(|v| match_basic_credential(v, &config.users)) {
        Some(u) => u,
        None => {
            debug!("{peer} Naive rejected: missing/invalid Proxy-Authorization");
            reject_naive(&mut respond, StatusCode::PROXY_AUTHENTICATION_REQUIRED);
            return Ok(());
        }
    };

    let padding_capability = parts.headers.contains_key(&config.padding_header_name);

    info!(
        "{peer} Naive CONNECT user={} target={host}:{port} padded={padding_capability}",
        user.email,
    );

    let target_addr = format!("{host}:{port}");
    let target = match tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(&target_addr),
    )
    .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            debug!("{peer} Naive connect {target_addr}: {e}");
            reject_naive(&mut respond, StatusCode::BAD_GATEWAY);
            return Ok(());
        }
        Err(_) => {
            debug!("{peer} Naive connect {target_addr}: timeout");
            reject_naive(&mut respond, StatusCode::GATEWAY_TIMEOUT);
            return Ok(());
        }
    };
    target.set_nodelay(true)?;

    let mut resp = Response::builder().status(StatusCode::OK);
    if padding_capability && let Ok(v) = http::HeaderValue::from_str(&random_padding_header_value())
    {
        resp = resp.header(config.padding_header_name.clone(), v);
    }
    let send = respond
        .send_response(resp.body(()).unwrap(), false)
        .map_err(|e| format!("send response: {e}"))?;

    let tap = wrongsv_metrics::MetricsTap::new(metrics, user.email.clone());
    let _conn_guard = tap.track_connection();

    let (target_read, target_write) = target.into_split();
    let metrics_up = tap.clone();
    let metrics_down = tap;
    let use_padding = padding_capability;

    let uplink = drive_uplink(body, target_write, metrics_up, use_padding);
    let downlink = drive_downlink(send, target_read, metrics_down, use_padding);
    let (up, down) = tokio::join!(uplink, downlink);
    up?;
    down?;
    Ok(())
}

fn reject_naive(respond: &mut h2::server::SendResponse<Bytes>, status: StatusCode) {
    let resp = Response::builder().status(status).body(()).unwrap();
    let _ = respond.send_response(resp, true);
}

async fn drive_uplink(
    mut body: h2::RecvStream,
    mut target_write: tokio::net::tcp::OwnedWriteHalf,
    metrics: wrongsv_metrics::MetricsTap,
    use_padding: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut decoder = NaivePadDecoder::new();
    let mut decoded = Vec::with_capacity(8192);
    while let Some(chunk) = body.data().await {
        let data = match chunk {
            Ok(d) => d,
            Err(e) if is_graceful_naive_h2(&e) => break,
            Err(e) => return Err(format!("h2 recv: {e}").into()),
        };
        let n = data.len();
        if use_padding {
            decoded.clear();
            decoder.feed_into(&data, &mut decoded);
            if !decoded.is_empty() {
                metrics.record_in(decoded.len() as u64);
                target_write.write_all(&decoded).await?;
            }
        } else {
            metrics.record_in(n as u64);
            target_write.write_all(&data).await?;
        }
        let _ = body.flow_control().release_capacity(n);
    }
    let _ = target_write.shutdown().await;
    Ok(())
}

async fn drive_downlink(
    mut send: h2::SendStream<Bytes>,
    mut target_read: tokio::net::tcp::OwnedReadHalf,
    metrics: wrongsv_metrics::MetricsTap,
    use_padding: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut encoder = NaivePadEncoder::new();
    let mut buf = vec![0u8; 32768];
    loop {
        let n = target_read.read(&mut buf).await?;
        if n == 0 {
            let _ = send.send_data(Bytes::new(), true);
            break;
        }
        metrics.record_out(n as u64);
        let bytes = if use_padding {
            Bytes::from(encoder.encode(&buf[..n]))
        } else {
            Bytes::copy_from_slice(&buf[..n])
        };
        match send.send_data(bytes, false) {
            Ok(()) => {}
            Err(e) if is_graceful_naive_h2(&e) => break,
            Err(e) => return Err(format!("h2 send: {e}").into()),
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn roundtrip_padded_codec_single_op() {
        let mut enc = NaivePadEncoder::new();
        let mut dec = NaivePadDecoder::new();
        let payload = b"hello, world! this is a naive CONNECT payload.";
        let encoded = enc.encode(payload);
        let mut decoded = Vec::new();
        dec.feed_into(&encoded, &mut decoded);
        assert_eq!(&decoded, payload);
    }

    #[test]
    fn roundtrip_padded_codec_split_input() {
        let mut enc = NaivePadEncoder::new();
        let mut dec = NaivePadDecoder::new();
        let payload = b"the rain in spain stays mainly in the plain";
        let encoded = enc.encode(payload);
        let mut decoded = Vec::new();
        for byte in &encoded {
            dec.feed_into(std::slice::from_ref(byte), &mut decoded);
        }
        assert_eq!(&decoded, payload);
    }

    #[test]
    fn passthrough_after_eight_ops_encode() {
        let mut enc = NaivePadEncoder::new();
        for _ in 0..NAIVE_PAD_OPS {
            let _ = enc.encode(b"x");
        }
        assert_eq!(enc.ops_remaining, 0);
        let out = enc.encode(b"raw");
        assert_eq!(out, b"raw".to_vec());
    }

    #[test]
    fn passthrough_after_eight_ops_decode() {
        let mut enc = NaivePadEncoder::new();
        let mut dec = NaivePadDecoder::new();
        let mut all_encoded = Vec::new();
        let mut all_expected = Vec::new();
        for i in 0..NAIVE_PAD_OPS {
            let chunk = format!("op{i}-payload");
            all_expected.extend_from_slice(chunk.as_bytes());
            all_encoded.extend_from_slice(&enc.encode(chunk.as_bytes()));
        }
        all_encoded.extend_from_slice(b"raw-trailing");
        all_expected.extend_from_slice(b"raw-trailing");
        let mut decoded = Vec::new();
        dec.feed_into(&all_encoded, &mut decoded);
        assert_eq!(decoded, all_expected);
    }

    #[test]
    fn match_basic_credential_succeeds_with_correct_password() {
        let users = vec![NaiveUser {
            username: "alice".into(),
            password: "secret".into(),
            email: "alice@example.com".into(),
        }];
        let token = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        let result = match_basic_credential(&format!("Basic {token}"), &users);
        assert_eq!(
            result.map(|u| u.email).as_deref(),
            Some("alice@example.com")
        );
    }

    #[test]
    fn match_basic_credential_rejects_wrong_password() {
        let users = vec![NaiveUser {
            username: "alice".into(),
            password: "secret".into(),
            email: String::new(),
        }];
        let token = base64::engine::general_purpose::STANDARD.encode("alice:wrong");
        assert!(match_basic_credential(&format!("Basic {token}"), &users).is_none());
    }

    #[test]
    fn match_basic_credential_rejects_unknown_scheme() {
        let users = vec![NaiveUser {
            username: "alice".into(),
            password: "secret".into(),
            email: String::new(),
        }];
        let token = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        assert!(match_basic_credential(&format!("Bearer {token}"), &users).is_none());
    }

    #[test]
    fn padding_header_value_is_within_range_and_digits() {
        for _ in 0..100 {
            let v = random_padding_header_value();
            assert!(v.len() >= 30 && v.len() <= 62, "len={}", v.len());
            assert!(v.bytes().all(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn parse_naive_config_generates_self_signed_when_cert_missing() {
        let nc = NaiveServerConfig {
            users: vec![crate::config::NaiveUserConfig {
                username: "alice".into(),
                password: "secret".into(),
                email: "alice@example.com".into(),
            }],
            padding_header_name: "Padding".into(),
            tls: crate::config::NaiveTlsConfig::default(),
        };
        let parsed = parse_naive_config(&nc).unwrap();
        assert_eq!(parsed.users.len(), 1);
        assert_eq!(parsed.padding_header_name.as_str(), "padding");
    }
}
