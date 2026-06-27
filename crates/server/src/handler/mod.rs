use std::net::{TcpListener, UdpSocket};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};
use wrongsv_protocol::{ID, MemoryAccount, MemoryUser};
use wrongsv_uuid::Uuid;
use wrongsv_vless::{MemoryValidator, Validator};

use crate::config::Config;
use crate::mixed_proxy::{self};
use crate::trojan::{self};

/// Parse an optional config section: `Some(cfg) => Some(parse(cfg)?)`, `None => None`.
macro_rules! parse_opt {
    ($config:expr, $parse:expr) => {{
        match $config {
            Some(cfg) => Some($parse(cfg)?),
            None => None,
        }
    }};
}

// ── Sub-module declarations ──
pub(crate) mod ctrlc_handler;
pub(crate) use ctrlc_handler::*;
pub(crate) mod relay;
pub(crate) use relay::*;
pub(crate) mod vless;
pub(crate) use vless::*;
pub(crate) mod reality;
pub(crate) use reality::*;
pub(crate) mod tls;
pub(crate) use tls::*;
pub(crate) mod websocket;
pub(crate) use websocket::*;
pub(crate) mod httpupgrade;
pub(crate) use httpupgrade::*;
pub(crate) mod grpc;
pub(crate) use grpc::*;
pub(crate) mod xhttp;
pub(crate) use xhttp::*;
pub(crate) mod request_transport;
pub(crate) use request_transport::*;
pub(crate) mod meek;
pub(crate) use meek::*;
pub(crate) mod gdocsviewer;
pub(crate) use gdocsviewer::*;
pub(crate) mod wireguard;
pub(crate) use wireguard::*;
pub(crate) mod hysteria2;
pub(crate) use hysteria2::*;
pub(crate) mod tuic;
pub(crate) use tuic::*;
pub(crate) mod anytls;
pub(crate) use anytls::*;
pub(crate) mod shadowsocks;
pub(crate) use shadowsocks::*;
pub(crate) mod mixed;
pub(crate) use mixed::*;
pub(crate) mod trojan_handler;
pub(crate) use trojan_handler::*;
pub(crate) mod quic;
pub(crate) use quic::*;
pub(crate) mod quic_obfs;
pub(crate) use quic_obfs::*;
pub(crate) mod kcp;
pub(crate) use kcp::*;
pub(crate) mod webtransport;
pub(crate) use webtransport::*;
pub(crate) mod shadowtls;
pub(crate) use shadowtls::*;
pub(crate) mod tls_relay;
pub(crate) use tls_relay::*;
pub(crate) mod vmess_handler;
pub(crate) use vmess_handler::*;
pub(crate) mod naive;
pub(crate) use naive::*;
pub(crate) mod snell;
pub(crate) use snell::*;
pub(crate) mod experimental;
pub(crate) use experimental::*;

#[derive(Clone, Debug)]
pub struct ShutdownSignal {
    shutdown: Arc<AtomicBool>,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ServerHandle {
    shutdown: ShutdownSignal,
    thread: Option<thread::JoinHandle<()>>,
}

impl ServerHandle {
    pub fn shutdown(&self) {
        self.shutdown.shutdown();
    }

    pub fn join(mut self) -> thread::Result<()> {
        self.shutdown();
        match self.thread.take() {
            Some(thread) => thread.join(),
            None => Ok(()),
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Decode a hex string into a fixed-size byte array.
fn decode_hex<const N: usize>(hex: &str) -> Result<[u8; N], String> {
    let hex = hex.trim();
    if hex.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, hex.len()));
    }
    let mut bytes = [0u8; N];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(chunk[0]).ok_or_else(|| format!("invalid hex at position {}", i * 2))?;
        let lo =
            hex_val(chunk[1]).ok_or_else(|| format!("invalid hex at position {}", i * 2 + 1))?;
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
    metrics: Arc<wrongsv_metrics::Registry>,
    reality_config: Option<wrongsv_reality::RealityConfig>,
    anytls_config: Option<wrongsv_anytls::AnyTlsConfig>,
    tls_config: Option<TlsConfig>,
    shadowsocks_config: Option<wrongsv_shadowsocks::ServerConfig>,
    mixed_config: Option<mixed_proxy::MixedProxyConfig>,
    trojan_config: Option<trojan::TrojanConfig>,
    ws_config: Option<WebSocketConfig>,
    httpupgrade_config: Option<HttpUpgradeConfig>,
    grpc_config: Option<GrpcConfig>,
    xhttp_config: Option<XhttpConfig>,
    meek_config: Option<MeekConfig>,
    gdocsviewer_config: Option<GdocsViewerConfig>,
    wireguard_config: Option<WireGuardConfig>,
    hysteria2_config: Option<Hysteria2Config>,
    tuic_config: Option<TuicConfig>,
    quic_config: Option<QuicConfig>,
    kcp_config: Option<KcpConfig>,
    webtransport_config: Option<WebTransportConfig>,
    shadowtls_config: Option<ShadowTlsConfig>,
    vmess_config: Option<VmessHandlerConfig>,
    naive_config: Option<NaiveConfig>,
    snell_config: Option<SnellHandlerConfig>,
    lua_config: Option<crate::config::LuaServerConfig>,
    masque_config: Option<crate::config::MasqueServerConfig>,
    trusttunnel_config: Option<crate::config::TrustTunnelServerConfig>,
    brook_config: Option<crate::config::BrookServerConfig>,
    vlite_config: Option<crate::config::VliteServerConfig>,
    tor_config: Option<crate::config::TorServerConfig>,
    ssh_config: Option<crate::config::SshServerConfig>,
    juicity_config: Option<crate::config::JuicityServerConfig>,
    mieru_config: Option<crate::config::MieruServerConfig>,
    sudoku_config: Option<crate::config::SudokuServerConfig>,
    vless_encryption_config: Option<crate::config::VlessEncryptionServerConfig>,
    shadowquic_config: Option<crate::config::ShadowquicServerConfig>,
    anytls_reality_config: Option<crate::config::AnytlsRealityServerConfig>,
}

impl InboundServer {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        config.validate()?;
        let reality_config = parse_opt!(&config.reality, parse_reality_config);
        let anytls_config = parse_opt!(&config.anytls, parse_anytls_config);
        let tls_config = parse_opt!(&config.tls, parse_tls_config);
        let shadowsocks_config = parse_opt!(&config.shadowsocks, parse_shadowsocks_config);
        let mixed_config = parse_opt!(&config.mixed, parse_mixed_config);
        let trojan_config = parse_opt!(&config.trojan, parse_trojan_config);
        let ws_config = match &config.websocket {
            Some(wc) => {
                let cfg = parse_ws_config(wc)?;
                info!(
                    "WebSocket enabled on path '{}'{}",
                    cfg.path,
                    if cfg.tls_config.is_some() {
                        " (TLS + WS)"
                    } else {
                        " (WS)"
                    }
                );
                Some(cfg)
            }
            None => None,
        };
        let httpupgrade_config = match &config.httpupgrade {
            Some(hc) => {
                let cfg = parse_httpupgrade_config(hc)?;
                info!(
                    "HTTPUpgrade enabled on path '{}'{}",
                    cfg.path,
                    if cfg.tls_config.is_some() {
                        " (TLS + HTTPUpgrade)"
                    } else {
                        " (HTTPUpgrade)"
                    }
                );
                Some(cfg)
            }
            None => None,
        };
        let grpc_config = match &config.grpc {
            Some(gc) => {
                let cfg = parse_grpc_config(gc)?;
                info!(
                    "gRPC enabled on /{}/Tun{}",
                    cfg.service_name,
                    if cfg.tls_config.is_some() {
                        " (TLS + gRPC)"
                    } else {
                        " (gRPC)"
                    }
                );
                Some(cfg)
            }
            None => None,
        };
        let xhttp_config = match &config.xhttp {
            Some(xc) => {
                let cfg = parse_xhttp_config(xc)?;
                info!(
                    "XHTTP enabled on {}prefix={}{}",
                    if let Some(ref h) = cfg.host {
                        format!("host={h}, ")
                    } else {
                        String::new()
                    },
                    cfg.path,
                    if cfg.tls_config.is_some() {
                        " (TLS + XHTTP)"
                    } else {
                        " (XHTTP)"
                    }
                );
                Some(cfg)
            }
            None => None,
        };
        let meek_config = match &config.meek {
            Some(mc) => {
                let cfg = parse_meek_config(mc)?;
                info!(
                    "Meek enabled on {}{}",
                    cfg.path,
                    if cfg.tls_config.is_some() {
                        " (TLS + Meek)"
                    } else {
                        " (Meek)"
                    }
                );
                Some(cfg)
            }
            None => None,
        };
        let gdocsviewer_config = match &config.gdocsviewer {
            Some(gc) => {
                let cfg = parse_gdocsviewer_config(gc)?;
                info!(
                    "Google Docs Viewer enabled on {}{}",
                    cfg.path_prefix,
                    if cfg.tls_config.is_some() {
                        " (TLS origin)"
                    } else {
                        " (origin)"
                    }
                );
                Some(cfg)
            }
            None => None,
        };
        let wireguard_config = match &config.wireguard {
            Some(wc) => {
                let cfg = parse_wireguard_config(&config.listen, wc)?;
                info!(
                    "WireGuard enabled on {} ({} peer(s), {} forward(s))",
                    config.listen,
                    cfg.peers.len(),
                    cfg.forwards.len()
                );
                Some(cfg)
            }
            None => None,
        };
        let hysteria2_config = match &config.hysteria2 {
            Some(hc) => {
                let cfg = parse_hysteria2_config(hc)?;
                info!(
                    "Hysteria2 enabled{}",
                    if cfg.disable_udp {
                        " (TCP only)"
                    } else {
                        " (TCP + UDP)"
                    }
                );
                Some(cfg)
            }
            None => None,
        };
        let tuic_config = match &config.tuic {
            Some(tc) => {
                let cfg = parse_tuic_config(tc)?;
                info!("TUIC enabled (QUIC/TCP/UDP)");
                Some(cfg)
            }
            None => None,
        };
        let quic_config = match &config.quic {
            Some(qc) => {
                let cfg = parse_quic_config(qc)?;
                info!(
                    "QUIC carrier enabled (VLESS over QUIC{})",
                    if cfg.udp_relay { " + UDP" } else { "" }
                );
                Some(cfg)
            }
            None => None,
        };
        let kcp_config = match &config.kcp {
            Some(kc) => {
                let cfg = parse_kcp_config(kc)?;
                info!(
                    "KCP enabled on {} (tti={}ms, mtu={})",
                    config.listen, cfg.tti, cfg.mtu
                );
                Some(cfg)
            }
            None => None,
        };
        let webtransport_config = match &config.webtransport {
            Some(wc) => {
                let cfg = parse_webtransport_config(wc)?;
                info!(
                    "WebTransport enabled on path '{}'{}",
                    cfg.path,
                    if cfg.udp_relay {
                        " (TCP + UDP)"
                    } else {
                        " (TCP only)"
                    }
                );
                Some(cfg)
            }
            None => None,
        };
        let shadowtls_config = match &config.shadowtls {
            Some(sc) => {
                let cfg = parse_shadowtls_config(sc)?;
                info!(
                    "ShadowTLS enabled{}",
                    if cfg.dest.is_some() {
                        " (with fallback)"
                    } else {
                        ""
                    }
                );
                Some(cfg)
            }
            None => None,
        };
        let vmess_config = match &config.vmess {
            Some(vc) => {
                let cfg = parse_vmess_handler_config(vc)?;
                info!("VMess enabled ({} user(s))", cfg.users.len());
                Some(cfg)
            }
            None => None,
        };
        let naive_config = match &config.naive {
            Some(nc) => {
                let cfg = parse_naive_config(nc)?;
                info!(
                    "Naive enabled ({} user(s), padding header '{}')",
                    cfg.users.len(),
                    cfg.padding_header_name.as_str()
                );
                Some(cfg)
            }
            None => None,
        };
        let snell_config = match &config.snell {
            Some(sc) => {
                let cfg = parse_snell_config(sc)?;
                info!("Snell enabled (v{})", cfg.version().as_u8());
                Some(cfg)
            }
            None => None,
        };
        let lua_config = config.lua.clone();
        if lua_config.is_some() {
            info!("Lua enabled");
        }
        let masque_config = config.masque.clone();
        if masque_config.is_some() {
            info!("Masque enabled");
        }
        let trusttunnel_config = config.trusttunnel.clone();
        if trusttunnel_config.is_some() {
            info!("TrustTunnel enabled");
        }
        let brook_config = config.brook.clone();
        if brook_config.is_some() {
            info!("Brook enabled");
        }
        let vlite_config = config.vlite.clone();
        if vlite_config.is_some() {
            info!("Vlite enabled");
        }
        let tor_config = config.tor.clone();
        if tor_config.is_some() {
            info!("Tor enabled");
        }
        let ssh_config = config.ssh.clone();
        if ssh_config.is_some() {
            info!("SSH enabled");
        }
        let juicity_config = config.juicity.clone();
        if juicity_config.is_some() {
            info!("Juicity enabled");
        }
        let mieru_config = config.mieru.clone();
        if mieru_config.is_some() {
            info!("Mieru enabled");
        }
        let sudoku_config = config.sudoku.clone();
        if sudoku_config.is_some() {
            info!("Sudoku enabled");
        }
        let vless_encryption_config = config.vless_encryption.clone();
        if vless_encryption_config.is_some() {
            info!("VLESS-Encryption enabled");
        }
        let shadowquic_config = config.shadowquic.clone();
        if shadowquic_config.is_some() {
            info!("ShadowQUIC enabled");
        }
        let anytls_reality_config = config.anytls_reality.clone();
        if anytls_reality_config.is_some() {
            info!("AnyTLS-Reality enabled");
        }
        if let Some(ref rc) = reality_config {
            let rpk_hex: String = rc
                .cert_material
                .raw_pubkey
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            info!("REALITY raw_pubkey (for client cert verification): {rpk_hex}");
        }
        if anytls_config.is_some() {
            info!("AnyTLS enabled");
        }
        if tls_config.is_some() {
            info!("TLS enabled");
        }
        if let Some(ref sc) = shadowsocks_config {
            info!("Shadowsocks enabled ({})", sc.method.name());
        }
        if mixed_config.is_some() {
            info!("Mixed proxy enabled (SOCKS4/4A + SOCKS5 + HTTP proxy)");
        }
        if trojan_config.is_some() {
            info!("Trojan over TLS enabled");
        }
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
                    udp: user.udp,
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
            metrics: Arc::new(wrongsv_metrics::Registry::new()),
            reality_config,
            anytls_config,
            tls_config,
            shadowsocks_config,
            mixed_config,
            trojan_config,
            ws_config,
            httpupgrade_config,
            grpc_config,
            xhttp_config,
            meek_config,
            gdocsviewer_config,
            wireguard_config,
            hysteria2_config,
            tuic_config,
            quic_config,
            kcp_config,
            webtransport_config,
            shadowtls_config,
            vmess_config,
            naive_config,
            snell_config,
            lua_config,
            masque_config,
            trusttunnel_config,
            brook_config,
            vlite_config,
            tor_config,
            ssh_config,
            juicity_config,
            mieru_config,
            sudoku_config,
            vless_encryption_config,
            shadowquic_config,
            anytls_reality_config,
        })
    }

    pub fn spawn(self) -> ServerHandle {
        self.spawn_with_shutdown(ShutdownSignal::new())
    }

    /// Hex-encoded REALITY cert raw_pubkey, if REALITY is configured.
    ///
    /// Callers (e.g. the evaluator orchestrator) need this to verify the
    /// server's HMAC-signed cert; without it the client must skip the check.
    pub fn reality_raw_pubkey_hex(&self) -> Option<String> {
        self.reality_config.as_ref().map(|rc| {
            rc.cert_material
                .raw_pubkey
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        })
    }

    pub fn spawn_with_shutdown(self, shutdown: ShutdownSignal) -> ServerHandle {
        let run_shutdown = shutdown.clone();
        let thread = thread::spawn(move || {
            if let Err(e) = self.run_until_shutdown(run_shutdown) {
                error!("server error: {e}");
            }
        });
        ServerHandle {
            shutdown,
            thread: Some(thread),
        }
    }

    /// Run the server loop. Returns on fatal error or graceful shutdown (SIGINT/SIGTERM).
    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let shutdown = ShutdownSignal::new();
        install_ctrlc_handler(shutdown.clone())?;
        self.run_until_shutdown(shutdown)
    }

    /// If a metrics endpoint is configured, bind the HTTP listener and return
    /// its handle. The caller holds the handle for the lifetime of the run
    /// loop; dropping it shuts the listener down.
    fn start_metrics_listener(
        &self,
    ) -> Result<Option<wrongsv_metrics::ServerHandle>, Box<dyn std::error::Error>> {
        let Some(ref cfg) = self.config.metrics else {
            return Ok(None);
        };
        let addr = cfg.socket_addr();
        let (_bound, handle) = wrongsv_metrics::serve(&addr, Arc::clone(&self.metrics))?;
        Ok(Some(handle))
    }

    /// Run the server loop until the provided shutdown signal is set.
    pub fn run_until_shutdown(
        &self,
        shutdown: ShutdownSignal,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _metrics_handle = self.start_metrics_listener()?;
        if let Some(config) = self.hysteria2_config.clone() {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let metrics = Arc::clone(&self.metrics);
            return runtime
                .block_on(run_hysteria2_endpoint(
                    &self.config.listen,
                    config,
                    metrics,
                    shutdown,
                ))
                .map_err(|e| std::io::Error::other(e.to_string()).into());
        }
        if let Some(config) = self.tuic_config.clone() {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let metrics = Arc::clone(&self.metrics);
            return runtime
                .block_on(run_tuic_endpoint(
                    &self.config.listen,
                    config,
                    metrics,
                    shutdown,
                ))
                .map_err(|e| std::io::Error::other(e.to_string()).into());
        }
        if let Some(config) = self.quic_config.clone() {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let validator = Arc::clone(&self.validator);
            return runtime
                .block_on(run_quic_endpoint(
                    &self.config.listen,
                    config,
                    validator,
                    shutdown,
                ))
                .map_err(|e| std::io::Error::other(e.to_string()).into());
        }
        if let Some(config) = self.kcp_config.clone() {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let validator = Arc::clone(&self.validator);
            return runtime
                .block_on(run_kcp_endpoint(
                    &self.config.listen,
                    config,
                    validator,
                    shutdown,
                ))
                .map_err(|e| std::io::Error::other(e.to_string()).into());
        }
        if let Some(config) = self.webtransport_config.clone() {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let validator = Arc::clone(&self.validator);
            return runtime
                .block_on(run_webtransport_endpoint(
                    &self.config.listen,
                    config,
                    validator,
                    shutdown,
                ))
                .map_err(|e| std::io::Error::other(e.to_string()).into());
        }
        if let Some(config) = self.wireguard_config.clone() {
            return run_wireguard_endpoint(config, shutdown)
                .map_err(|e| std::io::Error::other(e.to_string()).into());
        }
        let listener = TcpListener::bind(&self.config.listen)?;
        self.run_with_listener(listener, shutdown)
    }

    fn run_with_listener(
        &self,
        listener: TcpListener,
        shutdown: ShutdownSignal,
    ) -> Result<(), Box<dyn std::error::Error>> {
        listener.set_nonblocking(true)?;
        let listener_protocol = if self.shadowsocks_config.is_some() {
            "Shadowsocks"
        } else if self.mixed_config.is_some() {
            "Mixed proxy"
        } else if self.trojan_config.is_some() {
            "Trojan"
        } else if self.vmess_config.is_some() {
            "VMess"
        } else if self.naive_config.is_some() {
            "Naive"
        } else if self.snell_config.is_some() {
            "Snell"
        } else if self.lua_config.is_some() {
            "Lua"
        } else if self.masque_config.is_some() {
            "Masque"
        } else if self.trusttunnel_config.is_some() {
            "TrustTunnel"
        } else if self.brook_config.is_some() {
            "Brook"
        } else if self.vlite_config.is_some() {
            "Vlite"
        } else if self.tor_config.is_some() {
            "Tor"
        } else if self.ssh_config.is_some() {
            "SSH"
        } else if self.juicity_config.is_some() {
            "Juicity"
        } else if self.mieru_config.is_some() {
            "Mieru"
        } else if self.sudoku_config.is_some() {
            "Sudoku"
        } else if self.vless_encryption_config.is_some() {
            "VLESS-Encryption"
        } else if self.shadowquic_config.is_some() {
            "ShadowQUIC"
        } else if self.anytls_reality_config.is_some() {
            "AnyTLS-Reality"
        } else if self.hysteria2_config.is_some() {
            "Hysteria2"
        } else if self.tuic_config.is_some() {
            "TUIC"
        } else if self.httpupgrade_config.is_some() {
            "VLESS HTTPUpgrade"
        } else if self.grpc_config.is_some() {
            "VLESS gRPC"
        } else if self.xhttp_config.is_some() {
            "VLESS XHTTP"
        } else if self.meek_config.is_some() {
            "VLESS Meek"
        } else if self.gdocsviewer_config.is_some() {
            "VLESS Google Docs Viewer"
        } else if self.wireguard_config.is_some() {
            "WireGuard"
        } else if self.webtransport_config.is_some() {
            "VLESS WebTransport"
        } else {
            "VLESS"
        };
        info!(
            "{listener_protocol} server listening on {}",
            self.config.listen
        );

        let validator = Arc::clone(&self.validator);
        let metrics = Arc::clone(&self.metrics);
        let reality_config = self.reality_config.clone();
        let anytls_config = self.anytls_config.clone();
        let tls_config = self.tls_config.clone();
        let shadowsocks_config = self.shadowsocks_config.clone();
        let mixed_config = self.mixed_config.clone();
        let trojan_config = self.trojan_config.clone();
        let ws_config = self.ws_config.clone();
        let httpupgrade_config = self.httpupgrade_config.clone();
        let grpc_config = self.grpc_config.clone();
        let xhttp_config = self.xhttp_config.clone();
        let meek_config = self.meek_config.clone();
        let gdocsviewer_config = self.gdocsviewer_config.clone();
        let shadowtls_config = self.shadowtls_config.clone();
        let vmess_config = self.vmess_config.clone();
        let naive_config = self.naive_config.clone();
        let snell_config = self.snell_config.clone();
        let lua_config = self.lua_config.clone();
        let masque_config = self.masque_config.clone();
        let trusttunnel_config = self.trusttunnel_config.clone();
        let brook_config = self.brook_config.clone();
        let vlite_config = self.vlite_config.clone();
        let tor_config = self.tor_config.clone();
        let ssh_config = self.ssh_config.clone();
        let juicity_config = self.juicity_config.clone();
        let mieru_config = self.mieru_config.clone();
        let sudoku_config = self.sudoku_config.clone();
        let vless_encryption_config = self.vless_encryption_config.clone();
        let shadowquic_config = self.shadowquic_config.clone();
        let anytls_reality_config = self.anytls_reality_config.clone();
        let hysteria2_enabled = self.hysteria2_config.is_some();
        let tuic_enabled = self.tuic_config.is_some();
        let webtransport_enabled = self.webtransport_config.is_some();
        let shadowsocks_udp_socket =
            match (&self.shadowsocks_config, self.config.shadowsocks.as_ref()) {
                (Some(_), Some(raw_config)) if raw_config.udp => {
                    let socket = UdpSocket::bind(&self.config.listen)?;
                    socket.set_nonblocking(true)?;
                    info!("Shadowsocks UDP relay listening on {}", self.config.listen);
                    Some(socket)
                }
                _ => None,
            };

        loop {
            if shutdown.is_shutdown_requested() {
                info!("server stopped");
                break;
            }
            if let (Some(socket), Some(config)) =
                (shadowsocks_udp_socket.as_ref(), shadowsocks_config.as_ref())
            {
                drain_shadowsocks_udp(socket, config);
            }
            match listener.accept() {
                Ok((stream, addr)) => {
                    debug!("accepted connection from {}", addr);
                    let v = Arc::clone(&validator);
                    let m = Arc::clone(&metrics);
                    let rc = reality_config.clone();
                    let ac = anytls_config.clone();
                    let tc = tls_config.clone();
                    let sc = shadowsocks_config.clone();
                    let mc = mixed_config.clone();
                    let trc = trojan_config.clone();
                    let wsc = ws_config.clone();
                    let huc = httpupgrade_config.clone();
                    let gc = grpc_config.clone();
                    let xc = xhttp_config.clone();
                    let mkc = meek_config.clone();
                    let gdc = gdocsviewer_config.clone();
                    let stc = shadowtls_config.clone();
                    let vmc = vmess_config.clone();
                    let nc = naive_config.clone();
                    let snc = snell_config.clone();
                    let luc = lua_config.clone();
                    let msc = masque_config.clone();
                    let ttc = trusttunnel_config.clone();
                    let brc = brook_config.clone();
                    let vlc = vlite_config.clone();
                    let trc_ex = tor_config.clone();
                    let ssc_ex = ssh_config.clone();
                    let jcc = juicity_config.clone();
                    let mrc = mieru_config.clone();
                    let sdc = sudoku_config.clone();
                    let vec = vless_encryption_config.clone();
                    let sqc = shadowquic_config.clone();
                    let arc = anytls_reality_config.clone();
                    thread::spawn(move || {
                        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                            if let Some(ref rc) = rc {
                                handle_reality_connection(stream, v, rc, m)
                            } else if let Some(ref ac) = ac {
                                handle_anytls_connection(stream, v, ac, m)
                            } else if let Some(ref stc) = stc {
                                handle_shadowtls_connection(stream, v, stc, m)
                            } else if let Some(ref wc) = wsc {
                                handle_ws_connection(stream, v, wc)
                            } else if let Some(ref hc) = huc {
                                handle_httpupgrade_connection(stream, v, hc, m)
                            } else if let Some(ref gc) = gc {
                                handle_grpc_connection(stream, v, gc, m)
                            } else if let Some(ref xc) = xc {
                                handle_xhttp_connection(stream, v, xc, m)
                            } else if let Some(ref mkc) = mkc {
                                handle_meek_connection(stream, v, mkc, m)
                            } else if let Some(ref gdc) = gdc {
                                handle_gdocsviewer_connection(stream, v, gdc, m)
                            } else if hysteria2_enabled {
                                Err(
                                    "Hysteria2 inbound uses QUIC and does not accept TCP sockets"
                                        .into(),
                                )
                            } else if tuic_enabled {
                                Err("TUIC inbound uses QUIC and does not accept TCP sockets".into())
                            } else if webtransport_enabled {
                                Err("WebTransport inbound uses QUIC and does not accept TCP sockets".into())
                            } else if let Some(ref tc) = tc {
                                handle_tls_connection(stream, v, tc, m)
                            } else if let Some(ref sc) = sc {
                                handle_shadowsocks_connection(stream, sc)
                            } else if let Some(ref mc) = mc {
                                handle_mixed_proxy_connection(stream, mc)
                            } else if let Some(ref trc) = trc {
                                handle_trojan_connection(stream, trc, m)
                            } else if let Some(ref vmc) = vmc {
                                handle_vmess_connection(stream, vmc, m)
                            } else if let Some(ref nc) = nc {
                                handle_naive_connection(stream, nc, m)
                            } else if let Some(ref snc) = snc {
                                handle_snell_connection(stream, snc)
                            } else if let Some(ref _luc) = luc {
                                handle_lua_connection(stream)
                            } else if let Some(ref _msc) = msc {
                                handle_masque_connection(stream)
                            } else if let Some(ref _ttc) = ttc {
                                handle_trusttunnel_connection(stream)
                            } else if let Some(ref _brc) = brc {
                                handle_brook_connection(stream)
                            } else if let Some(ref _vlc) = vlc {
                                handle_vlite_connection(stream)
                            } else if let Some(ref _trc_ex) = trc_ex {
                                handle_tor_connection(stream)
                            } else if let Some(ref _ssc_ex) = ssc_ex {
                                handle_ssh_connection(stream)
                            } else if let Some(ref _jcc) = jcc {
                                handle_juicity_connection(stream)
                            } else if let Some(ref _mrc) = mrc {
                                handle_mieru_connection(stream)
                            } else if let Some(ref _sdc) = sdc {
                                handle_sudoku_connection(stream)
                            } else if let Some(ref _vec) = vec {
                                handle_vless_encryption_connection(stream)
                            } else if let Some(ref _sqc) = sqc {
                                handle_shadowquic_connection(stream)
                            } else if let Some(ref _arc) = arc {
                                handle_anytls_reality_connection(stream)
                            } else {
                                handle_connection(stream, v, m)
                            }
                        }));
                        match result {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => warn!("connection error: {}", e),
                            Err(panic) => {
                                let msg = panic
                                    .downcast_ref::<&str>()
                                    .copied()
                                    .or_else(|| panic.downcast_ref::<String>().map(|s| s.as_str()))
                                    .unwrap_or("unknown panic");
                                error!("connection thread panicked: {msg}");
                            }
                        }
                        trace!("connection thread finished");
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(200));
                    continue;
                }
                Err(e) => {
                    error!("accept error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }
}
