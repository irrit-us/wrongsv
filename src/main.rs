use std::process;

use clap::{Parser, ValueEnum};
use tracing::{error, info};
use wrongsv_server::Config;

mod client_config;

#[derive(Debug, ValueEnum, Clone, Copy, PartialEq)]
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
    /// QUIC carrier
    #[clap(name = "quic")]
    Quic,
    /// KCP (mKCP) carrier
    #[clap(name = "kcp")]
    Kcp,
}

#[derive(ValueEnum, Clone, Copy, PartialEq)]
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

#[derive(Parser)]
#[command(name = "wrongsv", about = "VLESS proxy server")]
struct Cli {
    /// Path to TOML config file (optional — uses compile-time defaults if omitted)
    #[arg(short, long)]
    config: Option<String>,

    /// Write a client config JSON to the given path
    #[arg(long)]
    write_client_config: Option<String>,

    /// Print a client config JSON to stdout
    #[arg(long)]
    print_client_config: bool,

    /// Server hostname or IP for the generated client config
    #[arg(long, default_value = "YOUR_SERVER_IP")]
    server_host: String,

    /// TLS SNI / server_name for the generated client config
    #[arg(long, default_value = "YOUR_SNI")]
    servername: String,

    /// Label for the generated client config
    #[arg(long, default_value = "wrongsv")]
    client_name: String,

    /// Override transport type detection (reality, anytls, tls, raw, ws, httpupgrade, grpc, xhttp, quic, kcp)
    #[arg(long)]
    transport: Option<Transport>,

    /// Client config format: mihomo (default) or sing-box
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
        );
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
        );
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
        hysteria2: None,
        tuic: None,
        quic: None,
        kcp: None,
    }
}

fn load_config(path: &str) -> Result<wrongsv_server::Config, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: wrongsv_server::Config = toml::from_str(&content)?;
    Ok(config)
}
