use std::str::FromStr;

use base64::Engine as _;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Address to listen on, e.g. "0.0.0.0:443"
    pub listen: String,
    /// VLESS users
    #[serde(default)]
    pub users: Vec<UserConfig>,
    /// Optional encryption (base64-encoded key chain)
    #[serde(default)]
    pub decryption: Option<String>,
    /// Global default flow
    #[serde(default)]
    pub flow: Option<String>,
    /// ML-KEM-512 secret key seed (64 bytes, hex-encoded).
    /// When set, the server can decapsulate Kyber-encrypted session keys
    /// carried in client addons.
    #[serde(default)]
    pub kyber_secret_key: Option<String>,
    /// REALITY configuration. When set, TLS REALITY is enabled.
    #[serde(default)]
    pub reality: Option<RealityServerConfig>,
    /// AnyTLS configuration. When set, AnyTLS TLS disguise is enabled.
    #[serde(default)]
    pub anytls: Option<AnyTlsServerConfig>,
    /// Standard TLS configuration. When set, plain TLS 1.3 + VLESS is enabled.
    /// Compatible with clients that support VLESS + tls transport
    /// (sing-box, mihomo/flclash, xray-core).
    #[serde(default)]
    pub tls: Option<TlsServerConfig>,
    /// Shadowsocks AEAD/AEAD-2022 inbound configuration. When set, this listener
    /// accepts Shadowsocks instead of VLESS.
    #[serde(default)]
    pub shadowsocks: Option<ShadowsocksServerConfig>,
    /// Mixed plain proxy inbound configuration. When set, this listener
    /// accepts SOCKS4/4A, SOCKS5 CONNECT, and HTTP forward/CONNECT instead of VLESS.
    #[serde(default)]
    pub mixed: Option<MixedServerConfig>,
    /// Trojan TLS inbound configuration. When set, this listener accepts
    /// Trojan over TLS instead of VLESS.
    #[serde(default)]
    pub trojan: Option<TrojanServerConfig>,
    /// WebSocket carrier configuration. When set, the listener performs
    /// WebSocket upgrade after any TLS handshake, before VLESS.
    #[serde(default)]
    pub websocket: Option<WebSocketServerConfig>,
    /// HTTPUpgrade carrier configuration. When set, the listener performs
    /// a V2Ray HTTPUpgrade handshake before VLESS.
    #[serde(default)]
    pub httpupgrade: Option<HttpUpgradeServerConfig>,
    /// gRPC carrier configuration. When set, the listener performs an
    /// HTTP/2 + gRPC handshake before VLESS (V2Ray-compatible).
    #[serde(default)]
    pub grpc: Option<GrpcServerConfig>,
    /// XHTTP (SplitHTTP) carrier configuration. When set, the listener
    /// performs an HTTP/2 upgrade before VLESS, carrying raw bytes over
    /// HTTP/2 streams (V2Ray xray-compatible, stream-one mode).
    #[serde(default)]
    pub xhttp: Option<XhttpServerConfig>,
    /// Meek carrier configuration. When set, the listener accepts HTTP
    /// POST round-trips with `X-Session-ID` headers and carries VLESS
    /// over V2Ray-compatible request sessions.
    #[serde(default)]
    pub meek: Option<MeekServerConfig>,
    /// Google Docs Viewer carrier configuration. When set, the listener
    /// exposes the V2Ray gdocsviewer origin endpoint and carries VLESS
    /// over request sessions hidden behind viewer/text fetches.
    #[serde(default)]
    pub gdocsviewer: Option<GdocsViewerServerConfig>,
    /// WireGuard inbound configuration. When set, wrongsv exposes a
    /// userspace WireGuard endpoint that serves one or more virtual TCP
    /// services inside the tunnel.
    #[serde(default)]
    pub wireguard: Option<WireGuardServerConfig>,
    /// Hysteria2 inbound configuration. When set, the listener accepts
    /// Hysteria2 QUIC/TCP/UDP traffic instead of VLESS.
    #[serde(default)]
    pub hysteria2: Option<Hysteria2ServerConfig>,
    /// TUIC inbound configuration. When set, the listener accepts TUIC
    /// QUIC/TCP/UDP traffic instead of VLESS.
    #[serde(default)]
    pub tuic: Option<TuicServerConfig>,
    /// QUIC carrier configuration. When set, the listener uses QUIC as
    /// the transport layer for VLESS (VLESS over QUIC). This is a VLESS
    /// transport, not a separate protocol — it replaces TCP with QUIC
    /// streams.
    #[serde(default)]
    pub quic: Option<QuicServerConfig>,
    /// KCP (mKCP) carrier configuration. When set, the listener creates a
    /// UDP-based KCP endpoint sending VLESS over mKCP sessions. This is a
    /// VLESS transport layer, not a separate protocol.
    #[serde(default)]
    pub kcp: Option<KcpServerConfig>,
    /// WebTransport carrier configuration. When set, the listener creates
    /// an HTTP/3 WebTransport endpoint carrying VLESS over bidirectional
    /// streams. This is a VLESS transport layer over QUIC.
    #[serde(default)]
    pub webtransport: Option<WebTransportServerConfig>,
    /// ShadowTLS configuration. When set, the listener relays a ShadowTLS v3
    /// handshake and authenticated record layer before VLESS.
    #[serde(default)]
    pub shadowtls: Option<ShadowTlsServerConfig>,
    /// VMess AEAD configuration. When set, this listener accepts VMess
    /// instead of VLESS. Users are authenticated via UUID.
    #[serde(default)]
    pub vmess: Option<VmessServerConfig>,
    /// Optional metrics endpoint. When set, an HTTP listener exposes a
    /// Prometheus-format `/metrics` endpoint with per-user (by email) byte
    /// counters and system stats. Off by default.
    #[serde(default)]
    pub metrics: Option<wrongsv_metrics::MetricsConfig>,
}

/// REALITY server-side configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct RealityServerConfig {
    /// X25519 private key (32 bytes, hex-encoded).
    pub private_key: String,
    /// Allowed short IDs (hex-encoded, 8 hex chars = 4 bytes each).
    #[serde(default)]
    pub short_ids: Vec<String>,
    /// Fallback destination for spider mode (e.g. "www.microsoft.com:443").
    #[serde(default)]
    pub dest: Option<String>,
    /// Maximum allowed clock skew in seconds (default 300 = 5 min).
    #[serde(default = "default_max_time_diff")]
    pub max_time_diff: u64,
}

fn default_max_time_diff() -> u64 {
    300
}

/// AnyTLS server-side configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AnyTlsServerConfig {
    /// Password for SHA-256 authentication.
    pub password: String,
    /// Fallback destination for unauthenticated probes (e.g. "127.0.0.1:8080").
    #[serde(default)]
    pub dest: Option<String>,
    /// Optional TLS certificate PEM (self-signed if not provided).
    #[serde(default)]
    pub certificate: Option<String>,
    /// Optional TLS key PEM.
    #[serde(default)]
    pub key: Option<String>,
    /// Optional padding scheme string (same format as anytls-go).
    #[serde(default)]
    pub padding_scheme: Option<String>,
}

/// Standard TLS server-side configuration.
///
/// Enables plain TLS 1.3 + VLESS — compatible with sing-box, mihomo/flclash,
/// and xray-core clients using `tls` transport (not REALITY, not AnyTLS).
#[derive(Debug, Clone, Deserialize)]
pub struct TlsServerConfig {
    /// Optional TLS certificate PEM (self-signed if not provided).
    #[serde(default)]
    pub certificate: Option<String>,
    /// Optional TLS key PEM.
    #[serde(default)]
    pub key: Option<String>,
    /// Fallback destination for probes (optional).
    #[serde(default)]
    pub dest: Option<String>,
}

/// Shadowsocks server-side configuration.
///
/// Supports classic AEAD TCP/UDP and AEAD-2022 TCP/UDP methods shared by
/// Shadowsocks, Outline, sing-box, xray-core, mihomo, and GOST clients.
#[derive(Debug, Clone, Deserialize)]
pub struct ShadowsocksServerConfig {
    pub method: String,
    pub password: String,
    #[serde(default = "default_udp")]
    pub udp: bool,
    #[serde(default)]
    pub tcp_prefix: Option<String>,
    #[serde(default)]
    pub udp_prefix: Option<String>,
}

/// Mixed plain proxy server-side configuration.
///
/// Supports SOCKS4/4A, SOCKS5 CONNECT, and HTTP forward/CONNECT. Optional
/// credentials are shared between SOCKS5 username/password auth and HTTP Basic
/// proxy auth; SOCKS4/4A is rejected when credentials are set.
#[derive(Debug, Clone, Deserialize)]
pub struct MixedServerConfig {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// Trojan server-side user.
#[derive(Debug, Clone, Deserialize)]
pub struct TrojanUserConfig {
    pub password: String,
    #[serde(default)]
    pub email: String,
}

/// Trojan server-side configuration.
///
/// Supports Trojan over TLS TCP CONNECT. The top-level `password` is a
/// convenient single-user form; `[[trojan.users]]` adds one or more named
/// users for xray/sing-box-style deployments. Invalid post-TLS probes can be
/// forwarded as decrypted plaintext to `dest`.
#[derive(Debug, Clone, Deserialize)]
pub struct TrojanServerConfig {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub users: Vec<TrojanUserConfig>,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub dest: Option<String>,
}

/// WebSocket carrier TLS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct WebSocketTlsConfig {
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub dest: Option<String>,
}

/// WebSocket carrier configuration.
///
/// When WebSocket is enabled, the listener performs the HTTP WebSocket
/// upgrade handshake before VLESS protocol processing. WebSocket can be
/// used standalone (raw TCP + WS) or with optional TLS (TLS + WS).
#[derive(Debug, Clone, Deserialize)]
pub struct WebSocketServerConfig {
    /// URL path for the WebSocket endpoint (default "/").
    #[serde(default = "default_ws_path")]
    pub path: String,
    /// Optional Host header to validate on the server side.
    #[serde(default)]
    pub host: Option<String>,
    /// Optional TLS configuration for wss:// mode.
    #[serde(default)]
    pub tls: Option<WebSocketTlsConfig>,
}

fn default_ws_path() -> String {
    "/".to_string()
}

/// HTTPUpgrade carrier TLS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpUpgradeTlsConfig {
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub dest: Option<String>,
}

/// HTTPUpgrade carrier configuration.
///
/// HTTPUpgrade performs the V2Ray "fake websocket" HTTP/1.1 upgrade and then
/// relays raw VLESS bytes on the upgraded stream, without WebSocket frames.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpUpgradeServerConfig {
    /// URL path for the HTTPUpgrade endpoint (default "/").
    #[serde(default = "default_ws_path")]
    pub path: String,
    /// Optional Host header to validate on the server side.
    #[serde(default)]
    pub host: Option<String>,
    /// Optional maximum VLESS early-data bytes accepted from a custom header.
    #[serde(default)]
    pub max_early_data: usize,
    /// Optional header name carrying URL-safe base64 early data.
    #[serde(default)]
    pub early_data_header_name: Option<String>,
    /// Optional TLS configuration for HTTPS HTTPUpgrade mode.
    #[serde(default)]
    pub tls: Option<HttpUpgradeTlsConfig>,
}

/// gRPC carrier TLS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct GrpcTlsConfig {
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub dest: Option<String>,
}

/// gRPC carrier configuration.
///
/// Performs an HTTP/2 + gRPC handshake and carries VLESS data in gRPC
/// Hunk frames. Compatible with the V2Ray gRPC transport.
#[derive(Debug, Clone, Deserialize)]
pub struct GrpcServerConfig {
    /// gRPC service name (default "GunService").
    #[serde(default)]
    pub service_name: Option<String>,
    /// Optional TLS configuration for HTTPS+gRPC mode.
    #[serde(default)]
    pub tls: Option<GrpcTlsConfig>,
}

/// XHTTP (SplitHTTP) carrier server-side configuration.
///
/// This implements the V2Ray "SplitHTTP" transport (also called XHTTP).
/// In stream-one mode, a single HTTP/2 POST request carries bidirectional
/// raw bytes — no protobuf framing.
#[derive(Debug, Clone, Deserialize)]
pub struct XhttpServerConfig {
    /// HTTP path prefix (default "/xhttp").
    #[serde(default)]
    pub path: Option<String>,
    /// Optional host header to validate.
    #[serde(default)]
    pub host: Option<String>,
    /// Optional TLS configuration for HTTPS+XHTTP mode.
    #[serde(default)]
    pub tls: Option<GrpcTlsConfig>,
}

/// Meek carrier TLS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MeekTlsConfig {
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub dest: Option<String>,
}

/// Meek carrier server-side configuration.
///
/// Meek carries VLESS over stateless HTTP POST requests keyed by
/// `X-Session-ID`, compatible with the V2Ray meek transport.
#[derive(Debug, Clone, Deserialize)]
pub struct MeekServerConfig {
    /// URL path prefix for the meek endpoint (default "/").
    #[serde(default = "default_ws_path")]
    pub path: String,
    /// Optional Host header to validate on the server side.
    #[serde(default)]
    pub host: Option<String>,
    /// Maximum accepted request body size per HTTP round-trip.
    #[serde(default = "default_meek_body_bytes")]
    pub max_request_bytes: usize,
    /// Maximum response payload emitted per HTTP round-trip.
    #[serde(default = "default_meek_body_bytes")]
    pub max_response_bytes: usize,
    /// Idle session timeout in seconds.
    #[serde(default = "default_meek_idle_timeout")]
    pub idle_timeout: u64,
    /// Optional TLS configuration for HTTPS meek mode.
    #[serde(default)]
    pub tls: Option<MeekTlsConfig>,
}

fn default_meek_body_bytes() -> usize {
    65_536
}

fn default_meek_idle_timeout() -> u64 {
    300
}

/// Google Docs Viewer carrier TLS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct GdocsViewerTlsConfig {
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub dest: Option<String>,
}

/// Google Docs Viewer carrier server-side configuration.
///
/// This exposes the V2Ray `gdocsviewer` origin endpoint so a client can
/// disguise request sessions behind viewer/text fetches.
#[derive(Debug, Clone, Deserialize)]
pub struct GdocsViewerServerConfig {
    /// HTTP path prefix for the origin endpoint (default "/gdocsviewer").
    #[serde(default = "default_gdocsviewer_path")]
    pub path_prefix: String,
    /// Maximum decoded request payload size per viewer-origin fetch.
    #[serde(default = "default_gdocsviewer_request_bytes")]
    pub max_request_bytes: usize,
    /// Maximum raw response bytes emitted per viewer-origin fetch.
    #[serde(default = "default_meek_body_bytes")]
    pub max_response_bytes: usize,
    /// Optional base64-encoded 32-byte AES-256-GCM shared key.
    #[serde(default)]
    pub shared_key: Option<String>,
    /// Idle session timeout in seconds.
    #[serde(default = "default_meek_idle_timeout")]
    pub idle_timeout: u64,
    /// Optional TLS configuration for HTTPS origin URLs.
    #[serde(default)]
    pub tls: Option<GdocsViewerTlsConfig>,
}

fn default_gdocsviewer_path() -> String {
    "/gdocsviewer".to_string()
}

fn default_gdocsviewer_request_bytes() -> usize {
    1_100
}

/// WireGuard peer configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct WireGuardPeerConfig {
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    pub allowed_ips: Vec<String>,
}

/// A virtual TCP service exported inside the WireGuard tunnel.
#[derive(Debug, Clone, Deserialize)]
pub struct WireGuardForwardConfig {
    pub service: String,
    pub target: String,
}

/// WireGuard userspace server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct WireGuardServerConfig {
    pub private_key: String,
    #[serde(default = "default_wireguard_mtu")]
    pub mtu: u32,
    pub server_cidrs: Vec<String>,
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub peers: Vec<WireGuardPeerConfig>,
    #[serde(default)]
    pub forwards: Vec<WireGuardForwardConfig>,
}

fn default_wireguard_mtu() -> u32 {
    1400
}

/// Hysteria2 authentication user.
#[derive(Debug, Clone, Deserialize)]
pub struct Hysteria2UserConfig {
    /// Username for userpass auth.
    pub name: String,
    /// Password for this user.
    pub password: String,
    /// Optional email / metrics key for this user.
    #[serde(default)]
    pub email: Option<String>,
}

/// Hysteria2 TLS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Hysteria2TlsConfig {
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub dest: Option<String>,
}

/// Hysteria2 optional packet obfuscation configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Hysteria2ObfsConfig {
    /// Obfuscation type. Supported values: `salamander`, `gecko`.
    #[serde(rename = "type")]
    pub obfs_type: String,
    /// Shared obfuscation password / key.
    pub password: String,
    /// Optional Gecko minimum packet size.
    #[serde(default)]
    pub min_packet_size: Option<usize>,
    /// Optional Gecko maximum packet size.
    #[serde(default)]
    pub max_packet_size: Option<usize>,
}

/// Hysteria2 server-side configuration.
///
/// Supports password and `username:password` authentication, TCP relay,
/// and UDP relay over QUIC. Salamander and Gecko packet obfuscation are supported;
/// realm/NAT traversal is intentionally left for future slices.
#[derive(Debug, Clone, Deserialize)]
pub struct Hysteria2ServerConfig {
    /// Single-password authentication value.
    #[serde(default)]
    pub password: Option<String>,
    /// Userpass authentication entries.
    #[serde(default)]
    pub users: Vec<Hysteria2UserConfig>,
    /// Disable UDP forwarding.
    #[serde(default)]
    pub disable_udp: bool,
    /// Optional upload bandwidth hint in Mbps.
    #[serde(default)]
    pub up_mbps: Option<u64>,
    /// Optional download bandwidth hint in Mbps.
    #[serde(default)]
    pub down_mbps: Option<u64>,
    /// Ask clients to use BBR instead of Hysteria CC when bandwidth hints are absent.
    #[serde(default)]
    pub ignore_client_bandwidth: bool,
    /// Optional UDP session idle timeout in seconds.
    #[serde(default = "default_hysteria2_udp_idle_timeout")]
    pub udp_idle_timeout: u64,
    /// Optional packet obfuscation component.
    #[serde(default)]
    pub obfs: Option<Hysteria2ObfsConfig>,
    /// Optional TLS configuration for the QUIC listener.
    #[serde(default)]
    pub tls: Option<Hysteria2TlsConfig>,
}

fn default_hysteria2_udp_idle_timeout() -> u64 {
    60
}

/// TUIC authentication user.
#[derive(Debug, Clone, Deserialize)]
pub struct TuicUserConfig {
    /// Optional display name for logs.
    #[serde(default)]
    pub name: Option<String>,
    /// Optional email / metrics key for this user.
    #[serde(default)]
    pub email: Option<String>,
    /// TUIC user UUID.
    pub uuid: String,
    /// TUIC user password.
    pub password: String,
}

/// TUIC TLS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct TuicTlsConfig {
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub dest: Option<String>,
}

/// TUIC server-side configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct TuicServerConfig {
    #[serde(default)]
    pub users: Vec<TuicUserConfig>,
    #[serde(default = "default_tuic_congestion_control")]
    pub congestion_control: String,
    #[serde(default = "default_tuic_auth_timeout")]
    pub auth_timeout: u64,
    #[serde(default)]
    pub zero_rtt_handshake: bool,
    #[serde(default = "default_tuic_heartbeat")]
    pub heartbeat: u64,
    #[serde(default)]
    pub tls: Option<TuicTlsConfig>,
}

fn default_tuic_congestion_control() -> String {
    "cubic".to_string()
}

fn default_tuic_auth_timeout() -> u64 {
    3
}

fn default_tuic_heartbeat() -> u64 {
    10
}

/// QUIC carrier TLS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct QuicTlsConfig {
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub dest: Option<String>,
}

/// QUIC carrier server-side configuration.
///
/// When the QUIC carrier is enabled, the listener creates a QUIC endpoint
/// and carries VLESS over bidirectional QUIC streams. This is a VLESS
/// transport layer, compatible with xray's QUIC transport.
#[derive(Debug, Clone, Deserialize)]
pub struct QuicServerConfig {
    /// TLS configuration for the QUIC listener.
    #[serde(default)]
    pub tls: Option<QuicTlsConfig>,
    /// Whether to allow UDP relay over QUIC (default true).
    #[serde(default = "default_udp")]
    pub udp_relay: bool,
}

/// KCP (mKCP) carrier server-side configuration.
///
/// When the KCP carrier is enabled, the listener creates a UDP socket and
/// carries VLESS over KCP reliable transport sessions multiplexed over the
/// single UDP port. This is a VLESS transport layer, compatible with xray's
/// mKCP transport.
#[derive(Debug, Clone, Deserialize)]
pub struct KcpServerConfig {
    /// mKCP authentication seed (empty string = no auth).
    #[serde(default)]
    pub seed: Option<String>,
    /// KCP MTU (576..1460, default 1350).
    #[serde(default)]
    pub mtu: Option<usize>,
    /// Transmission interval in ms (10..100, default 50).
    #[serde(default)]
    pub tti: Option<u32>,
    /// mKCP segment wrapper header size (default 19: auth + DataSegment overhead).
    #[serde(default)]
    pub header_size: Option<usize>,
    /// Uplink capacity hint (bytes).
    #[serde(default)]
    pub uplink_capacity: Option<usize>,
    /// Downlink capacity hint (bytes).
    #[serde(default)]
    pub downlink_capacity: Option<usize>,
    /// KCP read buffer size (default is auto).
    #[serde(default)]
    pub read_buffer_size: Option<usize>,
    /// KCP write buffer size (default is auto).
    #[serde(default)]
    pub write_buffer_size: Option<usize>,
}

/// WebTransport carrier TLS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct WebTransportTlsConfig {
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub dest: Option<String>,
}

/// WebTransport carrier server-side configuration.
///
/// When the WebTransport carrier is enabled, the listener creates an
/// HTTP/3 WebTransport endpoint and carries VLESS over bidirectional
/// streams. This is a VLESS transport layer, comparable to the QUIC carrier
/// but with an HTTP/3 WebTransport session negotiation layer.
#[derive(Debug, Clone, Deserialize)]
pub struct WebTransportServerConfig {
    /// URL path for the WebTransport endpoint (default "/wt").
    #[serde(default = "default_wt_path")]
    pub path: String,
    /// Optional Host header to validate on the server side.
    #[serde(default)]
    pub host: Option<String>,
    /// Whether to allow UDP relay (default true).
    #[serde(default = "default_udp")]
    pub udp_relay: bool,
    /// TLS configuration for the QUIC listener (required for HTTP/3).
    #[serde(default)]
    pub tls: Option<WebTransportTlsConfig>,
}

fn default_wt_path() -> String {
    "/wt".to_string()
}

/// VMess AEAD user configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct VmessUserConfig {
    /// VMess user UUID string (standard format).
    pub id: String,
    /// Optional email / display name for logs.
    #[serde(default)]
    pub email: String,
}

/// VMess AEAD server-side configuration.
///
/// VMess is a standalone encrypted proxy protocol with UUID-based
/// authentication, AES-128-GCM header encryption, and chunked AES-128-GCM
/// body encryption. This is a non-VLESS inbound — it cannot be combined
/// with VLESS users, transport layers, or other non-VLESS inbounds.
///
/// Compatible with v2ray-core 4.28.1+ (AEAD) and xray-core VMess outbounds.
#[derive(Debug, Clone, Deserialize)]
pub struct VmessServerConfig {
    /// VMess users (UUIDs). At least one is required.
    #[serde(default)]
    pub users: Vec<VmessUserConfig>,
}

/// ShadowTLS server-side configuration.
///
/// ShadowTLS v3 authenticates the client through the ClientHello session-id
/// HMAC, relays the upstream TLS handshake, and then switches to an
/// authenticated record stream that carries VLESS.
#[derive(Debug, Clone, Deserialize)]
pub struct ShadowTlsServerConfig {
    /// Password used for ClientHello HMAC verification and record auth.
    pub password: String,
    /// Optional handshake / fallback destination for unauthenticated probes.
    /// When unset, wrongsv spins up a local TLS backend from `certificate`/`key`.
    #[serde(default)]
    pub dest: Option<String>,
    /// Optional TLS certificate PEM for the local handshake backend.
    #[serde(default)]
    pub certificate: Option<String>,
    /// Optional TLS key PEM for the local handshake backend.
    #[serde(default)]
    pub key: Option<String>,
}

pub(crate) fn is_strict_uuid_text(s: &str) -> bool {
    let mut hex_len = 0usize;
    for ch in s.chars() {
        if ch == '-' {
            continue;
        }
        if !ch.is_ascii_hexdigit() {
            return false;
        }
        hex_len += 1;
    }
    hex_len == 32
}

fn is_valid_cidr_text(value: &str) -> bool {
    let Some((ip_text, prefix_text)) = value.split_once('/') else {
        return false;
    };
    let Ok(ip) = std::net::IpAddr::from_str(ip_text) else {
        return false;
    };
    let Ok(prefix) = prefix_text.parse::<u8>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(_) => prefix <= 32,
        std::net::IpAddr::V6(_) => prefix <= 128,
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    /// UUID string
    pub id: String,
    /// Optional email
    #[serde(default)]
    pub email: String,
    /// Flow: "" or "xtls-rprx-vision"
    #[serde(default)]
    pub flow: String,
    /// Optional per-user encryption
    #[serde(default)]
    pub encryption: String,
    /// Allow UDP command (default true). When false, UDP requests are rejected.
    #[serde(default = "default_udp")]
    pub udp: bool,
}

fn default_udp() -> bool {
    true
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid UUID for user '{0}': {1}")]
    InvalidUuid(String, String),
    #[error("unknown flow '{0}' for user '{1}'")]
    UnknownFlow(String, String),
    #[error("unsupported Shadowsocks method '{0}'")]
    UnsupportedShadowsocksMethod(String),
    #[error("Shadowsocks salt prefixes must be at most 16 bytes")]
    ShadowsocksPrefixTooLong,
    #[error("Shadowsocks inbound cannot be combined with VLESS users")]
    ShadowsocksWithVlessUsers,
    #[error("Shadowsocks inbound cannot be combined with VLESS transport layers")]
    ShadowsocksWithVlessTransport,
    #[error("only one non-VLESS inbound can be configured")]
    MultipleInboundProtocols,
    #[error("mixed inbound cannot be combined with VLESS users")]
    MixedWithVlessUsers,
    #[error("mixed inbound cannot be combined with VLESS transport layers")]
    MixedWithVlessTransport,
    #[error("mixed inbound credentials require both username and password")]
    MixedIncompleteCredentials,
    #[error("mixed inbound credentials must be 1..=255 bytes for SOCKS5 username/password auth")]
    MixedInvalidCredentials,
    #[error("Trojan inbound cannot be combined with VLESS users")]
    TrojanWithVlessUsers,
    #[error("Trojan inbound cannot be combined with VLESS transport layers")]
    TrojanWithVlessTransport,
    #[error("Trojan inbound requires `password` or at least one `[[trojan.users]]` entry")]
    TrojanMissingUsers,
    #[error("Trojan passwords must be non-empty")]
    TrojanInvalidPassword,
    #[error("WebSocket inbound cannot be combined with other VLESS transport layers")]
    WebsocketWithVlessTransport,
    #[error("WebSocket inbound cannot be combined with non-VLESS protocols")]
    WebsocketWithNonVless,
    #[error("HTTPUpgrade inbound cannot be combined with other VLESS transport layers")]
    HttpUpgradeWithVlessTransport,
    #[error("HTTPUpgrade inbound cannot be combined with non-VLESS protocols")]
    HttpUpgradeWithNonVless,
    #[error("HTTPUpgrade early data requires a non-empty header name")]
    HttpUpgradeInvalidEarlyData,
    #[error("gRPC inbound cannot be combined with other VLESS transport layers")]
    GrpcWithVlessTransport,
    #[error("gRPC inbound cannot be combined with non-VLESS protocols")]
    GrpcWithNonVless,
    #[error("gRPC inbound requires VLESS users")]
    GrpcMissingUsers,
    #[error("XHTTP inbound cannot be combined with other VLESS transport layers")]
    XhttpWithVlessTransport,
    #[error("XHTTP inbound cannot be combined with non-VLESS protocols")]
    XhttpWithNonVless,
    #[error("XHTTP inbound requires VLESS users")]
    XhttpMissingUsers,
    #[error("XHTTP inbound cannot be combined with gRPC")]
    XhttpWithGrpc,
    #[error("Meek inbound cannot be combined with other VLESS transport layers")]
    MeekWithVlessTransport,
    #[error("Meek inbound cannot be combined with non-VLESS protocols")]
    MeekWithNonVless,
    #[error("Meek inbound requires VLESS users")]
    MeekMissingUsers,
    #[error("Google Docs Viewer inbound cannot be combined with other VLESS transport layers")]
    GdocsViewerWithVlessTransport,
    #[error("Google Docs Viewer inbound cannot be combined with non-VLESS protocols")]
    GdocsViewerWithNonVless,
    #[error("Google Docs Viewer inbound requires VLESS users")]
    GdocsViewerMissingUsers,
    #[error("Google Docs Viewer shared_key must be base64 for exactly 32 bytes")]
    GdocsViewerInvalidSharedKey,
    #[error("WireGuard inbound cannot be combined with VLESS users")]
    WireGuardWithVlessUsers,
    #[error("WireGuard inbound cannot be combined with VLESS transport layers")]
    WireGuardWithVlessTransport,
    #[error("WireGuard inbound cannot be combined with other non-VLESS protocols")]
    WireGuardWithNonVless,
    #[error("WireGuard inbound requires at least one peer")]
    WireGuardMissingPeers,
    #[error("WireGuard inbound requires at least one forward rule")]
    WireGuardMissingForwards,
    #[error("WireGuard keys must be base64 for exactly 32 bytes")]
    WireGuardInvalidKey,
    #[error("WireGuard CIDRs must be valid CIDR strings")]
    WireGuardInvalidCidr,
    #[error("WireGuard forward service endpoints must be valid socket addresses")]
    WireGuardInvalidService,
    #[error("WireGuard forward targets must be valid TCP socket addresses")]
    WireGuardInvalidTarget,
    #[error("Hysteria2 inbound cannot be combined with VLESS users")]
    Hysteria2WithVlessUsers,
    #[error("Hysteria2 inbound cannot be combined with VLESS transport layers")]
    Hysteria2WithVlessTransport,
    #[error("Hysteria2 inbound cannot be combined with non-VLESS protocols")]
    Hysteria2WithNonVless,
    #[error("Hysteria2 inbound requires `password` or at least one `[[hysteria2.users]]` entry")]
    Hysteria2MissingAuth,
    #[error("Hysteria2 user passwords must be non-empty")]
    Hysteria2InvalidPassword,
    #[error("Hysteria2 obfuscation type must be `salamander` or `gecko`")]
    Hysteria2InvalidObfsType,
    #[error("Hysteria2 salamander password must be at least 4 bytes")]
    Hysteria2InvalidObfsPassword,
    #[error("Hysteria2 Gecko packet-size range is invalid")]
    Hysteria2InvalidObfsPacketSize,
    #[error("TUIC inbound cannot be combined with VLESS users")]
    TuicWithVlessUsers,
    #[error("TUIC inbound cannot be combined with VLESS transport layers")]
    TuicWithVlessTransport,
    #[error("TUIC inbound cannot be combined with non-VLESS protocols")]
    TuicWithNonVless,
    #[error("TUIC inbound requires at least one `[[tuic.users]]` entry")]
    TuicMissingUsers,
    #[error("TUIC user passwords must be non-empty")]
    TuicInvalidPassword,
    #[error("TUIC user UUIDs must be valid UUID strings")]
    TuicInvalidUuid,
    #[error("TUIC congestion control must be one of `cubic`, `new_reno`, or `bbr`")]
    TuicInvalidCongestionControl,
    #[error("QUIC carrier uses TLS — provide TLS cert/key under [quic.tls]")]
    QuicMissingTls,
    #[error("QUIC carrier is a VLESS transport and cannot be combined with non-VLESS protocols")]
    QuicWithNonVless,
    #[error("QUIC carrier is a VLESS transport and cannot be combined with other VLESS transports")]
    QuicWithVlessTransport,
    #[error("QUIC carrier requires VLESS users")]
    QuicMissingUsers,
    #[error("KCP carrier is a VLESS transport and cannot be combined with non-VLESS protocols")]
    KcpWithNonVless,
    #[error("KCP carrier is a VLESS transport and cannot be combined with other VLESS transports")]
    KcpWithVlessTransport,
    #[error("KCP carrier requires VLESS users")]
    KcpMissingUsers,
    #[error("WebTransport carrier cannot be combined with non-VLESS protocols")]
    WebTransportWithNonVless,
    #[error("WebTransport carrier cannot be combined with other VLESS transports")]
    WebTransportWithVlessTransport,
    #[error("WebTransport carrier requires VLESS users")]
    WebTransportMissingUsers,
    #[error("ShadowTLS cannot be combined with non-VLESS protocols")]
    ShadowTlsWithNonVless,
    #[error("ShadowTLS cannot be combined with other VLESS transports")]
    ShadowTlsWithVlessTransport,
    #[error("ShadowTLS requires VLESS users")]
    ShadowTlsMissingUsers,
    #[error("VMess inbound cannot be combined with VLESS users")]
    VmessWithVlessUsers,
    #[error("VMess inbound cannot be combined with VLESS transport layers")]
    VmessWithVlessTransport,
    #[error("VMess inbound requires at least one `[[vmess.users]]` entry")]
    VmessMissingUsers,
    #[error("VMess user UUID is invalid: {0}")]
    VmessInvalidUuid(String),
    #[error("VMess user UUIDs must be unique")]
    VmessDuplicateUuid,
}

impl Config {
    // ── validation helpers ───────────────────────────────────────────────

    fn has_vless_users(&self) -> bool {
        !self.users.is_empty()
    }

    /// True when any VLESS transport layer (TLS/REALITY/AnyTLS or framing
    /// transports like WS/HTTPUpgrade/gRPC/XHTTP/QUIC/KCP) is configured.
    fn has_any_vless_transport(&self) -> bool {
        self.reality.is_some()
            || self.anytls.is_some()
            || self.tls.is_some()
            || self.websocket.is_some()
            || self.httpupgrade.is_some()
            || self.grpc.is_some()
            || self.xhttp.is_some()
            || self.meek.is_some()
            || self.gdocsviewer.is_some()
            || self.quic.is_some()
            || self.kcp.is_some()
            || self.webtransport.is_some()
            || self.shadowtls.is_some()
    }

    /// True when any non-VLESS standalone inbound (Shadowsocks, Mixed,
    /// Trojan, Hysteria2, or TUIC) is configured. XHTTP is omitted here
    /// because it serves as both a VLESS framing transport and a standalone
    /// inbound depending on context — it is handled explicitly in validate().
    fn has_any_non_vless_inbound(&self) -> bool {
        self.shadowsocks.is_some()
            || self.mixed.is_some()
            || self.trojan.is_some()
            || self.hysteria2.is_some()
            || self.tuic.is_some()
            || self.vmess.is_some()
            || self.wireguard.is_some()
    }

    /// True when any stream-based framing transport (WebSocket,
    /// HTTPUpgrade, gRPC, XHTTP) is configured — i.e. transports that wrap
    /// TCP in a higher-level protocol. Does NOT include QUIC/KCP.
    fn has_any_stream_framing(&self) -> bool {
        self.websocket.is_some()
            || self.httpupgrade.is_some()
            || self.grpc.is_some()
            || self.xhttp.is_some()
            || self.meek.is_some()
            || self.gdocsviewer.is_some()
    }

    /// True when any TLS-layer transport (REALITY, AnyTLS, plain TLS) is
    /// configured.
    fn has_any_tls_layer(&self) -> bool {
        self.reality.is_some()
            || self.anytls.is_some()
            || self.tls.is_some()
            || self.shadowtls.is_some()
    }

    // ── validate ─────────────────────────────────────────────────────────

    pub fn validate(&self) -> Result<(), ConfigError> {
        // -- validate users --
        for user in &self.users {
            wrongsv_uuid::Uuid::parse_string(&user.id).map_err(
                |e: wrongsv_uuid::ParseUuidError| {
                    ConfigError::InvalidUuid(user.email.clone(), e.to_string())
                },
            )?;
            if !user.flow.is_empty() && user.flow != "xtls-rprx-vision" {
                return Err(ConfigError::UnknownFlow(
                    user.flow.clone(),
                    user.email.clone(),
                ));
            }
        }

        // -- at most one non-VLESS inbound --
        let non_vless_count = [
            self.shadowsocks.is_some(),
            self.mixed.is_some(),
            self.trojan.is_some(),
            self.hysteria2.is_some(),
            self.tuic.is_some(),
            self.xhttp.is_some(),
            self.vmess.is_some(),
            self.wireguard.is_some(),
        ]
        .into_iter()
        .filter(|&e| e)
        .count();
        if non_vless_count > 1 {
            return Err(ConfigError::MultipleInboundProtocols);
        }

        // -- non-VLESS inbounds (Shadowsocks, Mixed, Trojan, Hysteria2, TUIC) --
        if let Some(shadowsocks) = &self.shadowsocks {
            self.check_non_vless_no_users(ConfigError::ShadowsocksWithVlessUsers)?;
            self.check_non_vless_no_transports(ConfigError::ShadowsocksWithVlessTransport)?;
            wrongsv_shadowsocks::Method::parse(&shadowsocks.method).map_err(|_| {
                ConfigError::UnsupportedShadowsocksMethod(shadowsocks.method.clone())
            })?;
            if shadowsocks
                .tcp_prefix
                .as_deref()
                .is_some_and(|p| p.len() > 16)
                || shadowsocks
                    .udp_prefix
                    .as_deref()
                    .is_some_and(|p| p.len() > 16)
            {
                return Err(ConfigError::ShadowsocksPrefixTooLong);
            }
        }

        if let Some(mixed) = &self.mixed {
            self.check_non_vless_no_users(ConfigError::MixedWithVlessUsers)?;
            self.check_non_vless_no_transports(ConfigError::MixedWithVlessTransport)?;
            match (&mixed.username, &mixed.password) {
                (None, None) => {}
                (Some(u), Some(p))
                    if !u.is_empty() && u.len() <= 255 && !p.is_empty() && p.len() <= 255 => {}
                (Some(_), Some(_)) => return Err(ConfigError::MixedInvalidCredentials),
                _ => return Err(ConfigError::MixedIncompleteCredentials),
            }
        }

        if let Some(trojan) = &self.trojan {
            self.check_non_vless_no_users(ConfigError::TrojanWithVlessUsers)?;
            self.check_non_vless_no_transports(ConfigError::TrojanWithVlessTransport)?;
            let has_top_level_password = trojan.password.as_deref().is_some_and(|p| !p.is_empty());
            if trojan.password.as_deref().is_some_and(str::is_empty)
                || trojan.users.iter().any(|u| u.password.is_empty())
            {
                return Err(ConfigError::TrojanInvalidPassword);
            }
            if !has_top_level_password && trojan.users.is_empty() {
                return Err(ConfigError::TrojanMissingUsers);
            }
        }

        if let Some(hysteria2) = &self.hysteria2 {
            self.check_non_vless_no_users(ConfigError::Hysteria2WithVlessUsers)?;
            self.check_non_vless_no_transports(ConfigError::Hysteria2WithVlessTransport)?;
            if self.has_any_non_vless_inbound_except_hysteria2() {
                return Err(ConfigError::Hysteria2WithNonVless);
            }
            if hysteria2.password.as_deref().is_some_and(str::is_empty)
                || hysteria2.users.iter().any(|u| u.password.is_empty())
            {
                return Err(ConfigError::Hysteria2InvalidPassword);
            }
            if hysteria2.password.as_deref().is_none_or(str::is_empty) && hysteria2.users.is_empty()
            {
                return Err(ConfigError::Hysteria2MissingAuth);
            }
            if let Some(obfs) = &hysteria2.obfs {
                if !matches!(obfs.obfs_type.as_str(), "salamander" | "gecko") {
                    return Err(ConfigError::Hysteria2InvalidObfsType);
                }
                if obfs.password.len() < 4 {
                    return Err(ConfigError::Hysteria2InvalidObfsPassword);
                }
                if obfs.obfs_type == "gecko" {
                    let min = obfs.min_packet_size.unwrap_or(512);
                    let max = obfs.max_packet_size.unwrap_or(1200);
                    if min == 0 || max == 0 || min > max || max > 2048 {
                        return Err(ConfigError::Hysteria2InvalidObfsPacketSize);
                    }
                }
            }
        }

        if let Some(tuic) = &self.tuic {
            self.check_non_vless_no_users(ConfigError::TuicWithVlessUsers)?;
            self.check_non_vless_no_transports(ConfigError::TuicWithVlessTransport)?;
            if self.has_any_non_vless_inbound_except_tuic() {
                return Err(ConfigError::TuicWithNonVless);
            }
            if tuic.users.is_empty() {
                return Err(ConfigError::TuicMissingUsers);
            }
            if !matches!(
                tuic.congestion_control.as_str(),
                "cubic" | "new_reno" | "bbr"
            ) {
                return Err(ConfigError::TuicInvalidCongestionControl);
            }
            if tuic.users.iter().any(|u| u.password.is_empty()) {
                return Err(ConfigError::TuicInvalidPassword);
            }
            if tuic.users.iter().any(|u| !is_strict_uuid_text(&u.uuid)) {
                return Err(ConfigError::TuicInvalidUuid);
            }
        }

        // -- VMess non-VLESS inbound --
        if let Some(vmess) = &self.vmess {
            self.check_non_vless_no_users(ConfigError::VmessWithVlessUsers)?;
            self.check_non_vless_no_transports(ConfigError::VmessWithVlessTransport)?;
            if vmess.users.is_empty() {
                return Err(ConfigError::VmessMissingUsers);
            }
            // Validate UUID format
            for user in &vmess.users {
                wrongsv_uuid::Uuid::parse_string(&user.id)
                    .map_err(|e| ConfigError::VmessInvalidUuid(format!("{}: {}", user.id, e)))?;
            }
            // Detect duplicate UUIDs
            if vmess.users.len() > 1 {
                let mut seen = std::collections::HashSet::new();
                for u in &vmess.users {
                    if !seen.insert(&u.id) {
                        return Err(ConfigError::VmessDuplicateUuid);
                    }
                }
            }
        }

        if let Some(wireguard) = &self.wireguard {
            self.check_non_vless_no_users(ConfigError::WireGuardWithVlessUsers)?;
            self.check_non_vless_no_transports(ConfigError::WireGuardWithVlessTransport)?;
            if self.has_any_non_vless_inbound_except_wireguard() {
                return Err(ConfigError::WireGuardWithNonVless);
            }
            if wireguard.peers.is_empty() {
                return Err(ConfigError::WireGuardMissingPeers);
            }
            if wireguard.forwards.is_empty() {
                return Err(ConfigError::WireGuardMissingForwards);
            }
            let decode_key = |value: &str| {
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .ok()
                    .filter(|decoded| decoded.len() == 32)
            };
            if decode_key(&wireguard.private_key).is_none()
                || wireguard
                    .peers
                    .iter()
                    .any(|peer| decode_key(&peer.public_key).is_none())
                || wireguard.peers.iter().any(|peer| {
                    peer.preshared_key
                        .as_deref()
                        .is_some_and(|psk| decode_key(psk).is_none())
                })
            {
                return Err(ConfigError::WireGuardInvalidKey);
            }
            for cidr in &wireguard.server_cidrs {
                if !is_valid_cidr_text(cidr) {
                    return Err(ConfigError::WireGuardInvalidCidr);
                }
            }
            for cidr in wireguard.peers.iter().flat_map(|peer| peer.allowed_ips.iter()) {
                if !is_valid_cidr_text(cidr) {
                    return Err(ConfigError::WireGuardInvalidCidr);
                }
            }
            for forward in &wireguard.forwards {
                if forward.service.parse::<std::net::SocketAddr>().is_err() {
                    return Err(ConfigError::WireGuardInvalidService);
                }
                if forward.target.parse::<std::net::SocketAddr>().is_err() {
                    return Err(ConfigError::WireGuardInvalidTarget);
                }
            }
        }

        // -- VLESS framing transports --
        if let Some(_ws) = &self.websocket {
            self.check_framing_transport(
                "websocket",
                ConfigError::WebsocketWithNonVless,
                ConfigError::WebsocketWithVlessTransport,
            )?;
        }

        if let Some(httpupgrade) = &self.httpupgrade {
            self.check_framing_transport(
                "httpupgrade",
                ConfigError::HttpUpgradeWithNonVless,
                ConfigError::HttpUpgradeWithVlessTransport,
            )?;
            if httpupgrade.max_early_data > 0
                && httpupgrade
                    .early_data_header_name
                    .as_deref()
                    .is_none_or(str::is_empty)
            {
                return Err(ConfigError::HttpUpgradeInvalidEarlyData);
            }
        }

        if let Some(_grpc) = &self.grpc {
            self.check_framing_transport(
                "grpc",
                ConfigError::GrpcWithNonVless,
                ConfigError::GrpcWithVlessTransport,
            )?;
            if !self.has_vless_users() {
                return Err(ConfigError::GrpcMissingUsers);
            }
        }

        if let Some(_xhttp) = &self.xhttp {
            self.check_framing_transport(
                "xhttp",
                ConfigError::XhttpWithNonVless,
                ConfigError::XhttpWithVlessTransport,
            )?;
            if !self.has_vless_users() {
                return Err(ConfigError::XhttpMissingUsers);
            }
        }

        if let Some(_meek) = &self.meek {
            self.check_framing_transport(
                "meek",
                ConfigError::MeekWithNonVless,
                ConfigError::MeekWithVlessTransport,
            )?;
            if !self.has_vless_users() {
                return Err(ConfigError::MeekMissingUsers);
            }
        }

        if let Some(gdocsviewer) = &self.gdocsviewer {
            self.check_framing_transport(
                "gdocsviewer",
                ConfigError::GdocsViewerWithNonVless,
                ConfigError::GdocsViewerWithVlessTransport,
            )?;
            if !self.has_vless_users() {
                return Err(ConfigError::GdocsViewerMissingUsers);
            }
            if let Some(shared_key) = &gdocsviewer.shared_key {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(shared_key)
                    .map_err(|_| ConfigError::GdocsViewerInvalidSharedKey)?;
                if decoded.len() != 32 {
                    return Err(ConfigError::GdocsViewerInvalidSharedKey);
                }
            }
        }

        // -- VLESS datagram transports --
        if let Some(_quic) = &self.quic {
            self.check_datagram_transport(
                "quic",
                ConfigError::QuicWithNonVless,
                ConfigError::QuicWithVlessTransport,
                ConfigError::QuicMissingUsers,
            )?;
        }

        if let Some(_kcp) = &self.kcp {
            self.check_datagram_transport(
                "kcp",
                ConfigError::KcpWithNonVless,
                ConfigError::KcpWithVlessTransport,
                ConfigError::KcpMissingUsers,
            )?;
        }

        if let Some(_wt) = &self.webtransport {
            self.check_datagram_transport(
                "webtransport",
                ConfigError::WebTransportWithNonVless,
                ConfigError::WebTransportWithVlessTransport,
                ConfigError::WebTransportMissingUsers,
            )?;
        }

        // -- VLESS TLS-layer transports (ShadowTLS) --
        if let Some(_st) = &self.shadowtls {
            // ShadowTLS is a TLS-layer transport. Cannot combine with
            // non-VLESS inbounds, stream framing, datagram transports, or
            // other TLS-layer transports.
            if self.has_any_non_vless_inbound()
                || self.has_any_stream_framing()
                || self.quic.is_some()
                || self.kcp.is_some()
                || self.webtransport.is_some()
            {
                return Err(ConfigError::ShadowTlsWithNonVless);
            }
            if self.reality.is_some() || self.anytls.is_some() || self.tls.is_some() {
                return Err(ConfigError::ShadowTlsWithVlessTransport);
            }
            if !self.has_vless_users() {
                return Err(ConfigError::ShadowTlsMissingUsers);
            }
        }

        Ok(())
    }

    // ── per-category helpers (called from validate) ──────────────────────

    fn check_non_vless_no_users(&self, err: ConfigError) -> Result<(), ConfigError> {
        if self.has_vless_users() {
            return Err(err);
        }
        Ok(())
    }

    fn check_non_vless_no_transports(&self, err: ConfigError) -> Result<(), ConfigError> {
        if self.has_any_vless_transport() {
            return Err(err);
        }
        Ok(())
    }

    /// Validate a VLESS framing transport (WebSocket, HTTPUpgrade, gRPC,
    /// XHTTP). Ensures the transport is not combined with non-VLESS inbounds
    /// or conflicting VLESS transport layers.
    fn check_framing_transport(
        &self,
        name: &str,
        non_vless_err: ConfigError,
        transport_err: ConfigError,
    ) -> Result<(), ConfigError> {
        // Must not be combined with non-VLESS inbounds or other framing
        // transports (the current transport itself is already Some by the
        // time this is called, so other same-category Some values mean
        // conflict).
        let framing_conflicts = match name {
            "websocket" => {
                self.has_any_non_vless_inbound()
                    || self.httpupgrade.is_some()
                    || self.grpc.is_some()
                    || self.xhttp.is_some()
                    || self.meek.is_some()
                    || self.gdocsviewer.is_some()
                    || self.quic.is_some()
                    || self.kcp.is_some()
            }
            "httpupgrade" => {
                self.has_any_non_vless_inbound()
                    || self.websocket.is_some()
                    || self.grpc.is_some()
                    || self.xhttp.is_some()
                    || self.meek.is_some()
                    || self.gdocsviewer.is_some()
                    || self.quic.is_some()
                    || self.kcp.is_some()
            }
            "grpc" => {
                self.has_any_non_vless_inbound()
                    || self.websocket.is_some()
                    || self.httpupgrade.is_some()
                    || self.xhttp.is_some()
                    || self.meek.is_some()
                    || self.gdocsviewer.is_some()
                    || self.quic.is_some()
                    || self.kcp.is_some()
            }
            "xhttp" => {
                self.has_any_non_vless_inbound()
                    || self.websocket.is_some()
                    || self.httpupgrade.is_some()
                    || self.grpc.is_some()
                    || self.meek.is_some()
                    || self.gdocsviewer.is_some()
                    || self.quic.is_some()
                    || self.kcp.is_some()
            }
            "meek" => {
                self.has_any_non_vless_inbound()
                    || self.websocket.is_some()
                    || self.httpupgrade.is_some()
                    || self.grpc.is_some()
                    || self.xhttp.is_some()
                    || self.gdocsviewer.is_some()
                    || self.quic.is_some()
                    || self.kcp.is_some()
            }
            "gdocsviewer" => {
                self.has_any_non_vless_inbound()
                    || self.websocket.is_some()
                    || self.httpupgrade.is_some()
                    || self.grpc.is_some()
                    || self.xhttp.is_some()
                    || self.meek.is_some()
                    || self.quic.is_some()
                    || self.kcp.is_some()
            }
            _ => unreachable!("unknown framing transport: {name}"),
        };
        if framing_conflicts {
            return Err(non_vless_err);
        }

        // Must not be combined with TLS-layer transports
        if self.has_any_tls_layer() {
            return Err(transport_err);
        }

        Ok(())
    }

    /// Validate a VLESS datagram transport (QUIC, KCP). These cannot be
    /// combined with non-VLESS inbounds, TLS-layer transports, stream
    /// framing transports, or the *other* datagram transport.
    fn check_datagram_transport(
        &self,
        name: &str,
        non_vless_err: ConfigError,
        transport_err: ConfigError,
        missing_users_err: ConfigError,
    ) -> Result<(), ConfigError> {
        if self.has_any_non_vless_inbound() || self.has_any_stream_framing() {
            return Err(non_vless_err);
        }
        // Also reject the other datagram transport
        let datagram_conflict = match name {
            "quic" => self.kcp.is_some() || self.webtransport.is_some(),
            "kcp" => self.quic.is_some() || self.webtransport.is_some(),
            "webtransport" => self.quic.is_some() || self.kcp.is_some(),
            _ => unreachable!("unknown datagram transport: {name}"),
        };
        if self.has_any_tls_layer() || datagram_conflict {
            return Err(transport_err);
        }
        if !self.has_vless_users() {
            return Err(missing_users_err);
        }
        Ok(())
    }

    fn has_any_non_vless_inbound_except_hysteria2(&self) -> bool {
        self.shadowsocks.is_some()
            || self.mixed.is_some()
            || self.trojan.is_some()
            || self.vmess.is_some()
            || self.wireguard.is_some()
    }

    fn has_any_non_vless_inbound_except_tuic(&self) -> bool {
        self.shadowsocks.is_some()
            || self.mixed.is_some()
            || self.trojan.is_some()
            || self.hysteria2.is_some()
            || self.vmess.is_some()
            || self.wireguard.is_some()
    }

    fn has_any_non_vless_inbound_except_wireguard(&self) -> bool {
        self.shadowsocks.is_some()
            || self.mixed.is_some()
            || self.trojan.is_some()
            || self.hysteria2.is_some()
            || self.tuic.is_some()
            || self.vmess.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_toml_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "test@example.com"
flow = "xtls-rprx-vision"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.listen, "0.0.0.0:443");
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].flow, "xtls-rprx-vision");
        config.validate().unwrap();
    }

    #[test]
    fn test_validate_invalid_uuid() {
        let config = Config {
            listen: "0.0.0.0:443".into(),
            users: vec![UserConfig {
                id: "this-is-too-long-to-be-a-short-name-and-also-not-a-valid-uuid".into(),
                email: "bad@test.com".into(),
                flow: String::new(),
                encryption: String::new(),
                udp: true,
            }],
            decryption: None,
            flow: None,
            kyber_secret_key: None,
            reality: None,
            anytls: None,
            tls: None,
            shadowsocks: None,
            mixed: None,
            trojan: None,
            websocket: None,
            httpupgrade: None,
            grpc: None,
            xhttp: None,
            meek: None,
            gdocsviewer: None,
            wireguard: None,
            hysteria2: None,
            tuic: None,
            quic: None,
            kcp: None,
            webtransport: None,
            shadowtls: None,
            vmess: None,
            metrics: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_flow() {
        let config = Config {
            listen: "0.0.0.0:443".into(),
            users: vec![UserConfig {
                id: "12345678-1234-1234-1234-123456789abc".into(),
                email: "bad@test.com".into(),
                flow: "xtls-rprx-vision-udp443".into(), // not valid for standalone server
                encryption: String::new(),
                udp: true,
            }],
            decryption: None,
            flow: None,
            kyber_secret_key: None,
            reality: None,
            anytls: None,
            tls: None,
            shadowsocks: None,
            mixed: None,
            trojan: None,
            websocket: None,
            httpupgrade: None,
            grpc: None,
            xhttp: None,
            meek: None,
            gdocsviewer: None,
            wireguard: None,
            hysteria2: None,
            tuic: None,
            quic: None,
            kcp: None,
            webtransport: None,
            shadowtls: None,
            vmess: None,
            metrics: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_parse_shadowsocks_config() {
        let toml = r#"
listen = "0.0.0.0:8388"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"
tcp_prefix = "HTTP/1.1 "
udp_prefix = "k{\u0001 "
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let shadowsocks = config.shadowsocks.unwrap();
        assert_eq!(shadowsocks.method, "chacha20-ietf-poly1305");
        assert_eq!(shadowsocks.password, "secret");
        assert!(shadowsocks.udp);
        assert_eq!(shadowsocks.tcp_prefix.as_deref(), Some("HTTP/1.1 "));
        assert_eq!(shadowsocks.udp_prefix.as_deref(), Some("k{\u{1} "));
    }

    #[test]
    fn test_shadowsocks_rejects_long_salt_prefix() {
        let toml = r#"
listen = "0.0.0.0:8388"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"
tcp_prefix = "12345678901234567"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowsocksPrefixTooLong)
        ));
    }

    #[test]
    fn test_shadowsocks_rejects_vless_users() {
        let toml = r#"
listen = "0.0.0.0:8388"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowsocksWithVlessUsers)
        ));
    }

    #[test]
    fn test_shadowsocks_rejects_vless_transport() {
        let toml = r#"
listen = "0.0.0.0:8388"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"

[tls]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowsocksWithVlessTransport)
        ));
    }

    #[test]
    fn test_parse_mixed_config() {
        let toml = r#"
listen = "127.0.0.1:1080"

[mixed]
username = "admin"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let mixed = config.mixed.unwrap();
        assert_eq!(mixed.username.as_deref(), Some("admin"));
        assert_eq!(mixed.password.as_deref(), Some("secret"));
    }

    #[test]
    fn test_mixed_rejects_vless_users() {
        let toml = r#"
listen = "127.0.0.1:1080"

[mixed]

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MixedWithVlessUsers)
        ));
    }

    #[test]
    fn test_mixed_rejects_vless_transport() {
        let toml = r#"
listen = "127.0.0.1:1080"

[mixed]

[tls]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MixedWithVlessTransport)
        ));
    }

    #[test]
    fn test_mixed_rejects_shadowsocks_inbound() {
        let toml = r#"
listen = "127.0.0.1:1080"

[mixed]

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MultipleInboundProtocols)
        ));
    }

    #[test]
    fn test_mixed_rejects_incomplete_credentials() {
        let toml = r#"
listen = "127.0.0.1:1080"

[mixed]
username = "admin"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MixedIncompleteCredentials)
        ));
    }

    #[test]
    fn test_parse_trojan_single_password_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[trojan]
password = "secret"
dest = "127.0.0.1:8080"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let trojan = config.trojan.unwrap();
        assert_eq!(trojan.password.as_deref(), Some("secret"));
        assert_eq!(trojan.dest.as_deref(), Some("127.0.0.1:8080"));
    }

    #[test]
    fn test_parse_trojan_users_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[trojan]

[[trojan.users]]
password = "secret-a"
email = "a@example.com"

[[trojan.users]]
password = "secret-b"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let trojan = config.trojan.unwrap();
        assert_eq!(trojan.users.len(), 2);
        assert_eq!(trojan.users[0].email, "a@example.com");
        assert_eq!(trojan.users[1].password, "secret-b");
    }

    #[test]
    fn test_trojan_rejects_missing_users() {
        let toml = r#"
listen = "0.0.0.0:443"

[trojan]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::TrojanMissingUsers)
        ));
    }

    #[test]
    fn test_trojan_rejects_vless_users() {
        let toml = r#"
listen = "0.0.0.0:443"

[trojan]
password = "secret"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::TrojanWithVlessUsers)
        ));
    }

    #[test]
    fn test_trojan_rejects_vless_transport() {
        let toml = r#"
listen = "0.0.0.0:443"

[trojan]
password = "secret"

[tls]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::TrojanWithVlessTransport)
        ));
    }

    #[test]
    fn test_trojan_rejects_other_non_vless_inbound() {
        let toml = r#"
listen = "0.0.0.0:443"

[trojan]
password = "secret"

[mixed]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MultipleInboundProtocols)
        ));
    }

    #[test]
    fn test_parse_hysteria2_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[hysteria2]
password = "secret"
down_mbps = 200
ignore_client_bandwidth = true
disable_udp = true

[[hysteria2.users]]
name = "alice"
password = "alice-password"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let hysteria2 = config.hysteria2.unwrap();
        assert_eq!(hysteria2.password.as_deref(), Some("secret"));
        assert_eq!(hysteria2.down_mbps, Some(200));
        assert!(hysteria2.ignore_client_bandwidth);
        assert!(hysteria2.disable_udp);
        assert_eq!(hysteria2.users.len(), 1);
        assert_eq!(hysteria2.users[0].name, "alice");
    }

    #[test]
    fn test_parse_hysteria2_salamander_obfs_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[hysteria2]
password = "secret"

[hysteria2.obfs]
type = "salamander"
password = "obfs-secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let hysteria2 = config.hysteria2.unwrap();
        let obfs = hysteria2.obfs.expect("obfs config should be present");
        assert_eq!(obfs.obfs_type, "salamander");
        assert_eq!(obfs.password, "obfs-secret");
    }

    #[test]
    fn test_parse_hysteria2_gecko_obfs_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[hysteria2]
password = "secret"

[hysteria2.obfs]
type = "gecko"
password = "obfs-secret"
min_packet_size = 640
max_packet_size = 1200
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let hysteria2 = config.hysteria2.unwrap();
        let obfs = hysteria2.obfs.expect("obfs config should be present");
        assert_eq!(obfs.obfs_type, "gecko");
        assert_eq!(obfs.min_packet_size, Some(640));
        assert_eq!(obfs.max_packet_size, Some(1200));
    }

    #[test]
    fn test_hysteria2_rejects_missing_auth() {
        let toml = r#"
listen = "0.0.0.0:443"

[hysteria2]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Hysteria2MissingAuth)
        ));
    }

    #[test]
    fn test_hysteria2_rejects_empty_passwords() {
        let toml = r#"
listen = "0.0.0.0:443"

[hysteria2]
password = ""

[[hysteria2.users]]
name = "alice"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Hysteria2InvalidPassword)
        ));
    }

    #[test]
    fn test_hysteria2_rejects_invalid_obfs_type() {
        let toml = r#"
listen = "0.0.0.0:443"

[hysteria2]
password = "secret"

[hysteria2.obfs]
type = "unknown"
password = "obfs-secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Hysteria2InvalidObfsType)
        ));
    }

    #[test]
    fn test_hysteria2_rejects_short_obfs_password() {
        let toml = r#"
listen = "0.0.0.0:443"

[hysteria2]
password = "secret"

[hysteria2.obfs]
type = "salamander"
password = "abc"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Hysteria2InvalidObfsPassword)
        ));
    }

    #[test]
    fn test_hysteria2_rejects_invalid_gecko_packet_range() {
        let toml = r#"
listen = "0.0.0.0:443"

[hysteria2]
password = "secret"

[hysteria2.obfs]
type = "gecko"
password = "obfs-secret"
min_packet_size = 1500
max_packet_size = 1200
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Hysteria2InvalidObfsPacketSize)
        ));
    }

    #[test]
    fn test_hysteria2_rejects_vless_users() {
        let toml = r#"
listen = "0.0.0.0:443"

[hysteria2]
password = "secret"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Hysteria2WithVlessUsers)
        ));
    }

    #[test]
    fn test_parse_tuic_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[tuic]
congestion_control = "bbr"
auth_timeout = 5
zero_rtt_handshake = true
heartbeat = 12

[[tuic.users]]
name = "alice"
uuid = "12345678-1234-1234-1234-123456789abc"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let tuic = config.tuic.unwrap();
        assert_eq!(tuic.congestion_control, "bbr");
        assert_eq!(tuic.auth_timeout, 5);
        assert!(tuic.zero_rtt_handshake);
        assert_eq!(tuic.heartbeat, 12);
        assert_eq!(tuic.users.len(), 1);
        assert_eq!(tuic.users[0].name.as_deref(), Some("alice"));
    }

    #[test]
    fn test_tuic_rejects_missing_users() {
        let toml = r#"
listen = "0.0.0.0:443"

[tuic]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::TuicMissingUsers)
        ));
    }

    #[test]
    fn test_tuic_rejects_invalid_congestion_control() {
        let toml = r#"
listen = "0.0.0.0:443"

[tuic]
congestion_control = "fast"

[[tuic.users]]
uuid = "12345678-1234-1234-1234-123456789abc"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::TuicInvalidCongestionControl)
        ));
    }

    #[test]
    fn test_tuic_rejects_invalid_uuid() {
        let toml = r#"
listen = "0.0.0.0:443"

[tuic]

[[tuic.users]]
uuid = "not-a-uuid"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::TuicInvalidUuid)
        ));
    }

    // ── WebSocket config tests ────────────────────────────────────────────────

    #[test]
    fn test_parse_websocket_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[websocket]
path = "/ws"
host = "example.com"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let ws = config.websocket.unwrap();
        assert_eq!(ws.path, "/ws");
        assert_eq!(ws.host.as_deref(), Some("example.com"));
        assert!(ws.tls.is_none());
    }

    #[test]
    fn test_parse_websocket_tls_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[websocket]
path = "/"

[websocket.tls]
certificate = '''-----BEGIN CERTIFICATE-----...'''
key = '''-----BEGIN PRIVATE KEY-----...'''
dest = "127.0.0.1:8080"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let ws = config.websocket.unwrap();
        assert_eq!(ws.path, "/");
        let tls = ws.tls.as_ref().unwrap();
        assert!(tls.certificate.is_some());
        assert_eq!(tls.dest.as_deref(), Some("127.0.0.1:8080"));
    }

    #[test]
    fn test_websocket_accepts_vless_users() {
        // WebSocket + VLESS users is the normal, expected configuration.
        let toml = r#"
listen = "0.0.0.0:443"

[websocket]
path = "/"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn test_websocket_rejects_non_vless() {
        let toml = r#"
listen = "0.0.0.0:443"

[websocket]
path = "/"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        // The non-VLESS inbound validation triggers first
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowsocksWithVlessTransport)
        ));
    }

    #[test]
    fn test_websocket_rejects_other_vless_transport() {
        let toml = r#"
listen = "0.0.0.0:443"

[websocket]
path = "/"

[tls]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::WebsocketWithVlessTransport)
        ));
    }

    // ── HTTPUpgrade config tests ─────────────────────────────────────────────

    #[test]
    fn test_parse_httpupgrade_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[httpupgrade]
path = "/up"
host = "example.com"
max_early_data = 128
early_data_header_name = "X-ED"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let httpupgrade = config.httpupgrade.unwrap();
        assert_eq!(httpupgrade.path, "/up");
        assert_eq!(httpupgrade.host.as_deref(), Some("example.com"));
        assert_eq!(httpupgrade.max_early_data, 128);
        assert_eq!(httpupgrade.early_data_header_name.as_deref(), Some("X-ED"));
        assert!(httpupgrade.tls.is_none());
    }

    #[test]
    fn test_parse_httpupgrade_tls_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[httpupgrade]
path = "/up"

[httpupgrade.tls]
certificate = '''-----BEGIN CERTIFICATE-----...'''
key = '''-----BEGIN PRIVATE KEY-----...'''
dest = "127.0.0.1:8080"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let httpupgrade = config.httpupgrade.unwrap();
        assert_eq!(httpupgrade.path, "/up");
        let tls = httpupgrade.tls.as_ref().unwrap();
        assert!(tls.certificate.is_some());
        assert_eq!(tls.dest.as_deref(), Some("127.0.0.1:8080"));
    }

    #[test]
    fn test_httpupgrade_rejects_missing_early_data_header_name() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[httpupgrade]
max_early_data = 64
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::HttpUpgradeInvalidEarlyData)
        ));
    }

    #[test]
    fn test_httpupgrade_rejects_non_vless() {
        let toml = r#"
listen = "0.0.0.0:443"

[httpupgrade]
path = "/"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowsocksWithVlessTransport)
        ));
    }

    #[test]
    fn test_httpupgrade_rejects_other_vless_transport() {
        let toml = r#"
listen = "0.0.0.0:443"

[httpupgrade]
path = "/"

[tls]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::HttpUpgradeWithVlessTransport)
        ));
    }

    #[test]
    fn test_httpupgrade_rejects_websocket_transport() {
        let toml = r#"
listen = "0.0.0.0:443"

[httpupgrade]
path = "/up"

[websocket]
path = "/ws"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::WebsocketWithNonVless)
        ));
    }

    // ── QUIC carrier config tests ─────────────────────────────────────────

    #[test]
    fn test_parse_quic_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[quic]
udp_relay = false

[quic.tls]
certificate = '''-----BEGIN CERTIFICATE-----...'''
key = '''-----BEGIN PRIVATE KEY-----...'''
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let quic = config.quic.unwrap();
        assert!(!quic.udp_relay);
        assert!(quic.tls.is_some());
    }

    #[test]
    fn test_quic_accepts_vless_users() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[quic]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn test_quic_rejects_missing_users() {
        let toml = r#"
listen = "0.0.0.0:443"

[quic]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::QuicMissingUsers)
        ));
    }

    #[test]
    fn test_quic_rejects_non_vless() {
        let toml = r#"
listen = "0.0.0.0:443"

[quic]

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowsocksWithVlessTransport)
        ));
    }

    #[test]
    fn test_quic_rejects_other_vless_transport() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[quic]

[tls]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::QuicWithVlessTransport)
        ));
    }

    // ── KCP carrier config tests ─────────────────────────────────────────

    #[test]
    fn test_parse_kcp_config() {
        let toml = r#"
listen = "0.0.0.0:8388"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[kcp]
seed = "my-secret"
mtu = 1400
tti = 20
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let kcp = config.kcp.unwrap();
        assert_eq!(kcp.seed.as_deref(), Some("my-secret"));
        assert_eq!(kcp.mtu, Some(1400));
        assert_eq!(kcp.tti, Some(20));
    }

    #[test]
    fn test_kcp_accepts_vless_users() {
        let toml = r#"
listen = "0.0.0.0:8388"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[kcp]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn test_kcp_rejects_missing_users() {
        let toml = r#"
listen = "0.0.0.0:8388"

[kcp]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::KcpMissingUsers)
        ));
    }

    #[test]
    fn test_kcp_rejects_non_vless() {
        let toml = r#"
listen = "0.0.0.0:8388"

[kcp]

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowsocksWithVlessTransport)
        ));
    }

    #[test]
    fn test_kcp_rejects_other_vless_transport() {
        let toml = r#"
listen = "0.0.0.0:8388"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[kcp]

[tls]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::KcpWithVlessTransport)
        ));
    }

    // ── WebTransport config validation ──────────────────────────────────

    #[test]
    fn test_parse_webtransport_config() {
        let toml = r#"
listen = "0.0.0.0:8388"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[webtransport]
path = "/wt"
udp_relay = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let wt = config.webtransport.unwrap();
        assert_eq!(wt.path, "/wt");
        assert!(!wt.udp_relay);
    }

    #[test]
    fn test_webtransport_accepts_vless_users() {
        let toml = r#"
listen = "0.0.0.0:8388"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[webtransport]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn test_webtransport_rejects_missing_users() {
        let toml = r#"
listen = "0.0.0.0:8388"

[webtransport]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::WebTransportMissingUsers)
        ));
    }

    #[test]
    fn test_webtransport_rejects_non_vless() {
        let toml = r#"
listen = "0.0.0.0:8388"

[webtransport]

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowsocksWithVlessTransport)
        ));
    }

    #[test]
    fn test_webtransport_rejects_other_vless_transport() {
        let toml = r#"
listen = "0.0.0.0:8388"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[webtransport]

[tls]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::WebTransportWithVlessTransport)
        ));
    }

    #[test]
    fn test_webtransport_rejects_other_datagram_transport() {
        let toml = r#"
listen = "0.0.0.0:8388"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[webtransport]

[quic]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::QuicWithVlessTransport)
        ));
    }

    // ── ShadowTLS config validation ──────────────────────────────────────

    #[test]
    fn test_parse_shadowtls_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[shadowtls]
password = "secret"
dest = "127.0.0.1:8080"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let st = config.shadowtls.unwrap();
        assert_eq!(st.password, "secret");
        assert_eq!(st.dest.as_deref(), Some("127.0.0.1:8080"));
    }

    #[test]
    fn test_shadowtls_accepts_vless_users() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[shadowtls]
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn test_shadowtls_rejects_missing_users() {
        let toml = r#"
listen = "0.0.0.0:443"

[shadowtls]
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowTlsMissingUsers)
        ));
    }

    #[test]
    fn test_shadowtls_rejects_non_vless() {
        let toml = r#"
listen = "0.0.0.0:443"

[shadowtls]
password = "secret"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowsocksWithVlessTransport)
        ));
    }

    #[test]
    fn test_shadowtls_rejects_other_tls_layer() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[shadowtls]
password = "secret"

[tls]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowTlsWithVlessTransport)
        ));
    }

    #[test]
    fn test_shadowtls_rejects_framing_transport() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[shadowtls]
password = "secret"

[websocket]
path = "/"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        // Websocket validation runs before ShadowTLS — it detects the TLS-layer
        // conflict via has_any_tls_layer() → WebsocketWithVlessTransport
        assert!(matches!(
            config.validate(),
            Err(ConfigError::WebsocketWithVlessTransport)
        ));
    }

    // ── VMess config validation ────────────────────────────────────────

    #[test]
    fn test_parse_vmess_config() {
        let toml = r#"
listen = "0.0.0.0:16823"

[vmess]

[[vmess.users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"

[[vmess.users]]
id = "87654321-1234-1234-1234-123456789abc"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let vmess = config.vmess.unwrap();
        assert_eq!(vmess.users.len(), 2);
        assert_eq!(vmess.users[0].email, "user@example.com");
        assert_eq!(vmess.users[1].id, "87654321-1234-1234-1234-123456789abc");
    }

    #[test]
    fn test_vmess_rejects_missing_users() {
        let toml = r#"
listen = "0.0.0.0:16823"

[vmess]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::VmessMissingUsers)
        ));
    }

    #[test]
    fn test_vmess_rejects_vless_users() {
        let toml = r#"
listen = "0.0.0.0:16823"

[vmess]

[[vmess.users]]
id = "12345678-1234-1234-1234-123456789abc"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::VmessWithVlessUsers)
        ));
    }

    #[test]
    fn test_vmess_rejects_vless_transport() {
        let toml = r#"
listen = "0.0.0.0:16823"

[vmess]

[[vmess.users]]
id = "12345678-1234-1234-1234-123456789abc"

[tls]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::VmessWithVlessTransport)
        ));
    }

    #[test]
    fn test_vmess_rejects_other_non_vless_inbound() {
        let toml = r#"
listen = "0.0.0.0:16823"

[vmess]

[[vmess.users]]
id = "12345678-1234-1234-1234-123456789abc"

[mixed]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MultipleInboundProtocols)
        ));
    }

    #[test]
    fn test_vmess_rejects_invalid_uuid() {
        let toml = r#"
listen = "0.0.0.0:16823"

[vmess]

[[vmess.users]]
id = "this-is-too-long-to-be-a-short-name-and-also-not-a-valid-uuid"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::VmessInvalidUuid(_))
        ));
    }

    #[test]
    fn test_vmess_rejects_duplicate_uuid() {
        let toml = r#"
listen = "0.0.0.0:16823"

[vmess]

[[vmess.users]]
id = "12345678-1234-1234-1234-123456789abc"

[[vmess.users]]
id = "12345678-1234-1234-1234-123456789abc"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::VmessDuplicateUuid)
        ));
    }
}
