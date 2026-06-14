use std::process;

use clap::{Parser, Subcommand, ValueEnum};
use tracing::{error, info};
use wrongsv_server::Config;

mod client_config;
mod endpoint_registry;
mod protocol_model;

#[derive(Debug, ValueEnum, Clone, Copy, PartialEq)]
#[allow(clippy::enum_variant_names)]
enum Transport {
    /// REALITY TLS (X25519 ECDH + HKDF auth)
    Reality,
    /// AnyTLS (SHA-256 password auth over TLS)
    #[clap(name = "anytls")]
    AnyTls,
    /// Plain TLS 1.3 (compatible with sing-box/mihomo TLS transport)
    Tls,
    /// Raw TCP (no TLS layer)
    Raw,
    /// WebSocket carrier (optional TLS)
    #[clap(name = "ws")]
    WebSocket,
    /// HTTPUpgrade carrier
    #[clap(name = "httpupgrade")]
    HttpUpgrade,
    /// gRPC carrier (HTTP/2 + gRPC frames)
    #[clap(name = "grpc")]
    Grpc,
    /// XHTTP (SplitHTTP) carrier
    #[clap(name = "xhttp")]
    Xhttp,
    /// Meek request transport
    #[clap(name = "meek")]
    Meek,
    /// Google Docs Viewer request transport
    #[clap(name = "gdocsviewer")]
    GdocsViewer,
    /// QUIC carrier
    #[clap(name = "quic")]
    Quic,
    /// KCP (mKCP) carrier
    #[clap(name = "kcp")]
    Kcp,
    /// WebTransport carrier (HTTP/3)
    #[clap(name = "webtransport")]
    WebTransport,
    /// ShadowTLS (TLS 1.3 + HMAC auth)
    #[clap(name = "shadowtls")]
    ShadowTls,
    /// VMess AEAD (AES-128-GCM encrypted proxy)
    #[clap(name = "vmess")]
    Vmess,
    /// WireGuard tunnel service
    #[clap(name = "wireguard")]
    WireGuard,
}

#[derive(Debug, ValueEnum, Clone, Copy, PartialEq)]
enum ClientFormat {
    /// mihomo / FlClash / v2rayN format (flat keys)
    Mihomo,
    /// sing-box format (nested tls object)
    #[clap(name = "sing-box")]
    SingBox,
    /// Xray JSON format (settings/streamSettings structure)
    #[clap(name = "xray")]
    Xray,
    /// Hiddify format (sing-box-compatible with subscription wrapper)
    #[clap(name = "hiddify")]
    Hiddify,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the multi-protocol evaluator orchestrator (server side)
    EvalServer {
        /// Listen address for the control channel
        #[arg(long, default_value = "127.0.0.1:19999")]
        listen: String,
        /// Shared authentication token (auto-generated if not provided)
        #[arg(long)]
        token: Option<String>,
        /// Comma-separated protocol list (default: all 14 combinations)
        #[arg(long)]
        protocols: Option<String>,
        /// Test duration per protocol in seconds
        #[arg(long, default_value = "10")]
        duration: u64,
        /// Bind address for spawned proxy servers (use 0.0.0.0 for remote clients)
        #[arg(long, default_value = "127.0.0.1")]
        proxy_bind: String,
        /// Fixed proxy port (use with SSH -L forwarding for genuine remote eval).
        /// When set, the proxy uses this port instead of a random ephemeral one.
        #[arg(long)]
        fixed_proxy_port: Option<u16>,
    },
    /// Run a multi-protocol evaluation against an evaluator server
    EvalClient {
        /// Evaluator server address
        #[arg(long, default_value = "127.0.0.1:19999")]
        server: String,
        /// Shared authentication token
        #[arg(long)]
        token: String,
        /// Test duration per protocol in seconds
        #[arg(long, default_value = "10")]
        duration: u64,
        /// Output file base name (extensions .json/.csv are appended)
        #[arg(long, default_value = "eval-result")]
        output: String,
    },
}

#[derive(Parser)]
#[command(name = "wrongsv", about = "VLESS proxy server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to TOML config file (optional — uses compile-time defaults if omitted)
    #[arg(short, long)]
    config: Option<String>,

    /// Write a client config JSON to the given path
    #[arg(long)]
    write_client_config: Option<String>,

    /// Print a client config JSON to stdout
    #[arg(long)]
    print_client_config: bool,

    /// Print normalized endpoint diagnostics JSON to stdout
    #[arg(long)]
    print_endpoint_diagnostics: bool,

    /// Server hostname or IP for the generated client config
    #[arg(long, default_value = "YOUR_SERVER_IP")]
    server_host: String,

    /// TLS SNI / server_name for the generated client config
    #[arg(long, default_value = "YOUR_SNI")]
    servername: String,

    /// Label for the generated client config
    #[arg(long, default_value = "wrongsv")]
    client_name: String,

    /// Override profile detection (reality, anytls, tls, raw, ws, httpupgrade, grpc, xhttp, meek, gdocsviewer, quic, kcp, webtransport, shadowtls, vmess, wireguard)
    #[arg(long)]
    transport: Option<Transport>,

    /// Client config format: mihomo (default), sing-box, xray, hiddify
    #[arg(long, default_value = "mihomo")]
    format: ClientFormat,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // -- subcommand dispatch --
    if let Some(cmd) = cli.command {
        match cmd {
            Commands::EvalServer {
                listen,
                token,
                protocols,
                duration,
                proxy_bind,
                fixed_proxy_port,
            } => {
                // Auto-generate token if not provided
                let token = token.unwrap_or_else(|| {
                    let mut bytes = [0u8; 16];
                    std::fs::File::open("/dev/urandom")
                        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes))
                        .unwrap_or_else(|_| {
                            // Fallback: time-based
                            let t = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default();
                            bytes[0..8].copy_from_slice(&t.as_nanos().to_be_bytes());
                            bytes[8..16].copy_from_slice(&(t.as_nanos() >> 32).to_be_bytes());
                        });
                    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                    eprintln!("\x1b[1;33m╔══════════════════════════════════════╗");
                    eprintln!("\x1b[1;33m║  Auto-generated auth token:          ║");
                    eprintln!("\x1b[1;33m║  {hex}  ║");
                    eprintln!("\x1b[1;33m║  Pass --token with eval-client to    ║");
                    eprintln!("\x1b[1;33m║  use a different token.              ║");
                    eprintln!("\x1b[1;33m╚══════════════════════════════════════╝\x1b[0m");
                    hex
                });
                let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                if let Err(e) = rt.block_on(wrongsv_evaluator_server::run_orchestrator(
                    &listen,
                    &token,
                    protocols.as_deref(),
                    None, // stacks — use --protocols mode
                    duration,
                    &proxy_bind,
                    fixed_proxy_port,
                )) {
                    error!("evaluator server error: {e}");
                    process::exit(1);
                }
                return;
            }
            Commands::EvalClient {
                server,
                token,
                duration,
                output,
            } => {
                match wrongsv_evaluator_client::runner::run_evaluation(
                    &server,
                    &token,
                    duration,
                    &[],
                ) {
                    Ok(results) => {
                        // Export JSON
                        let json_path = format!("{output}.json");
                        let json = wrongsv_evaluator_client::export::export_json(&results);
                        std::fs::write(&json_path, &json)
                            .unwrap_or_else(|e| error!("failed to write {json_path}: {e}"));
                        println!("JSON results written to {json_path}");

                        // Export CSV
                        let csv_path = format!("{output}.csv");
                        let csv = wrongsv_evaluator_client::export::export_csv(&results);
                        std::fs::write(&csv_path, &csv)
                            .unwrap_or_else(|e| error!("failed to write {csv_path}: {e}"));
                        println!("CSV results written to {csv_path}");
                    }
                    Err(e) => {
                        error!("evaluation failed: {e}");
                        process::exit(1);
                    }
                }
                return;
            }
        }
    }

    // -- client config generation (doesn't need a running server) --
    if cli.print_client_config {
        let vals = client_config::resolve_client_values(
            cli.config.as_deref(),
            cli.transport,
            &cli.servername,
        );
        let json = client_config::generate_client_config(
            cli.format,
            &cli.server_host,
            &cli.client_name,
            &vals,
        )
        .unwrap_or_else(|e| {
            error!("failed to generate client config: {e}");
            process::exit(1);
        });
        println!("{json}");
        return;
    }
    if cli.print_endpoint_diagnostics {
        let vals = client_config::resolve_client_values(
            cli.config.as_deref(),
            cli.transport,
            &cli.servername,
        );
        let diagnostics = client_config::build_endpoint_diagnostics(&vals, Some(cli.format));
        let json = serde_json::to_string_pretty(&diagnostics).unwrap_or_else(|e| {
            error!("failed to serialize endpoint diagnostics: {e}");
            process::exit(1);
        });
        println!("{json}");
        return;
    }
    if let Some(ref path) = cli.write_client_config {
        let vals = client_config::resolve_client_values(
            cli.config.as_deref(),
            cli.transport,
            &cli.servername,
        );
        let json = client_config::generate_client_config(
            cli.format,
            &cli.server_host,
            &cli.client_name,
            &vals,
        )
        .unwrap_or_else(|e| {
            error!("failed to generate client config: {e}");
            process::exit(1);
        });
        std::fs::write(path, json).expect("failed to write client config");
        info!("client config written to {path}");
        return;
    }

    // -- load config --
    let config = match cli.config {
        Some(ref path) => match load_config(path) {
            Ok(c) => c,
            Err(e) => {
                error!("failed to load config: {e}");
                process::exit(1);
            }
        },
        None => {
            let c = build_default_config();
            info!(
                "using compile-time defaults: listen={}, uuid={}",
                c.listen,
                c.users.first().map(|u| u.id.as_str()).unwrap_or("none")
            );
            if let Err(e) = c.validate() {
                error!("built-in config invalid: {e}");
                process::exit(1);
            }
            c
        }
    };

    let server = match wrongsv_server::InboundServer::new(config) {
        Ok(s) => s,
        Err(e) => {
            error!("failed to initialize server: {e}");
            process::exit(1);
        }
    };

    info!("starting wrongsv server...");
    if let Err(e) = server.run() {
        error!("server error: {e}");
        process::exit(1);
    }
}

fn build_default_config() -> Config {
    use wrongsv_server::config::UserConfig;
    let uuid = option_env!("BUILD_UUID").unwrap_or("00000000-0000-4000-8000-000000000000");
    let port = option_env!("BUILD_PORT").unwrap_or("443");
    let kyber = option_env!("BUILD_KYBER_SK_HEX").map(String::from);
    Config {
        listen: format!("0.0.0.0:{port}"),
        users: vec![UserConfig {
            id: uuid.to_string(),
            email: String::new(),
            flow: "xtls-rprx-vision".into(),
            encryption: String::new(),
            udp: true,
        }],
        decryption: None,
        flow: Some("xtls-rprx-vision".into()),
        kyber_secret_key: kyber,
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
    }
}

fn load_config(path: &str) -> Result<wrongsv_server::Config, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: wrongsv_server::Config = toml::from_str(&content)?;
    Ok(config)
}
