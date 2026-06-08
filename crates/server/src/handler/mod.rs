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
    kyber_sk: Option<[u8; 64]>,
    reality_config: Option<wrongsv_reality::RealityConfig>,
    anytls_config: Option<wrongsv_anytls::AnyTlsConfig>,
    tls_config: Option<TlsConfig>,
    shadowsocks_config: Option<wrongsv_shadowsocks::ServerConfig>,
    mixed_config: Option<mixed_proxy::MixedProxyConfig>,
    trojan_config: Option<trojan::TrojanConfig>,
    ws_config: Option<WebSocketConfig>,
    httpupgrade_config: Option<HttpUpgradeConfig>,
    grpc_config: Option<GrpcConfig>,
    hysteria2_config: Option<Hysteria2Config>,
    tuic_config: Option<TuicConfig>,
}

impl InboundServer {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        config.validate()?;
        let kyber_sk = match &config.kyber_secret_key {
            Some(hex) => Some(decode_hex::<64>(hex).map_err(|e| format!("kyber_secret_key: {e}"))?),
            None => None,
        };
        let reality_config = match &config.reality {
            Some(rc) => Some(parse_reality_config(rc)?),
            None => None,
        };
        let anytls_config = match &config.anytls {
            Some(ac) => Some(parse_anytls_config(ac)?),
            None => None,
        };
        let tls_config = match &config.tls {
            Some(tc) => Some(parse_tls_config(tc)?),
            None => None,
        };
        let shadowsocks_config = match &config.shadowsocks {
            Some(sc) => Some(parse_shadowsocks_config(sc)?),
            None => None,
        };
        let mixed_config = match &config.mixed {
            Some(mc) => Some(parse_mixed_config(mc)?),
            None => None,
        };
        let trojan_config = match &config.trojan {
            Some(tc) => Some(parse_trojan_config(tc)?),
            None => None,
        };
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
            kyber_sk,
            reality_config,
            anytls_config,
            tls_config,
            shadowsocks_config,
            mixed_config,
            trojan_config,
            ws_config,
            httpupgrade_config,
            grpc_config,
            hysteria2_config,
            tuic_config,
        })
    }

    pub fn spawn(self) -> ServerHandle {
        self.spawn_with_shutdown(ShutdownSignal::new())
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

    /// Run the server loop until the provided shutdown signal is set.
    pub fn run_until_shutdown(
        &self,
        shutdown: ShutdownSignal,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(config) = self.hysteria2_config.clone() {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            return runtime
                .block_on(run_hysteria2_endpoint(
                    &self.config.listen,
                    config,
                    shutdown,
                ))
                .map_err(|e| std::io::Error::other(e.to_string()).into());
        }
        if let Some(config) = self.tuic_config.clone() {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            return runtime
                .block_on(run_tuic_endpoint(&self.config.listen, config, shutdown))
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
        } else if self.hysteria2_config.is_some() {
            "Hysteria2"
        } else if self.tuic_config.is_some() {
            "TUIC"
        } else if self.httpupgrade_config.is_some() {
            "VLESS HTTPUpgrade"
        } else if self.grpc_config.is_some() {
            "VLESS gRPC"
        } else {
            "VLESS"
        };
        info!(
            "{listener_protocol} server listening on {}",
            self.config.listen
        );

        let validator = Arc::clone(&self.validator);
        let kyber_sk = self.kyber_sk;
        let reality_config = self.reality_config.clone();
        let anytls_config = self.anytls_config.clone();
        let tls_config = self.tls_config.clone();
        let shadowsocks_config = self.shadowsocks_config.clone();
        let mixed_config = self.mixed_config.clone();
        let trojan_config = self.trojan_config.clone();
        let ws_config = self.ws_config.clone();
        let httpupgrade_config = self.httpupgrade_config.clone();
        let grpc_config = self.grpc_config.clone();
        let hysteria2_enabled = self.hysteria2_config.is_some();
        let tuic_enabled = self.tuic_config.is_some();
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
                    let rc = reality_config.clone();
                    let ac = anytls_config.clone();
                    let tc = tls_config.clone();
                    let sc = shadowsocks_config.clone();
                    let mc = mixed_config.clone();
                    let trc = trojan_config.clone();
                    let wsc = ws_config.clone();
                    let huc = httpupgrade_config.clone();
                    let gc = grpc_config.clone();
                    thread::spawn(move || {
                        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                            if let Some(ref rc) = rc {
                                handle_reality_connection(stream, v, kyber_sk, rc)
                            } else if let Some(ref ac) = ac {
                                handle_anytls_connection(stream, v, kyber_sk, ac)
                            } else if let Some(ref wc) = wsc {
                                handle_ws_connection(stream, v, kyber_sk, wc)
                            } else if let Some(ref hc) = huc {
                                handle_httpupgrade_connection(stream, v, kyber_sk, hc)
                            } else if let Some(ref gc) = gc {
                                handle_grpc_connection(stream, v, kyber_sk, gc)
                            } else if hysteria2_enabled {
                                Err(
                                    "Hysteria2 inbound uses QUIC and does not accept TCP sockets"
                                        .into(),
                                )
                            } else if tuic_enabled {
                                Err("TUIC inbound uses QUIC and does not accept TCP sockets".into())
                            } else if let Some(ref tc) = tc {
                                handle_tls_connection(stream, v, kyber_sk, tc)
                            } else if let Some(ref sc) = sc {
                                handle_shadowsocks_connection(stream, sc)
                            } else if let Some(ref mc) = mc {
                                handle_mixed_proxy_connection(stream, mc)
                            } else if let Some(ref trc) = trc {
                                handle_trojan_connection(stream, trc)
                            } else {
                                handle_connection(stream, v, kyber_sk)
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
