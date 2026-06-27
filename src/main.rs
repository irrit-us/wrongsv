use std::process;

use clap::{Parser, Subcommand, ValueEnum};
use tracing::{error, info};
use wrongsv_server::Config;

mod client_config;
mod endpoint;
mod main_config;

pub(crate) use endpoint::EndpointProfile as Transport;

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
    /// Generate one complete randomized main TOML config from cooperative components
    #[command(name = "generate-main-config", alias = "generate-main-configs")]
    GenerateMainConfig(main_config::GenerateMainConfigArgs),
    /// Start the multi-protocol evaluator orchestrator (server side)
    #[command(after_long_help = "\
Examples:
  wrongsv eval-server --listen 0.0.0.0:19999 --token TOKEN --proxy-bind 0.0.0.0
  wrongsv eval-server --protocols reality,anytls,grpc+tls --duration 30

Supported protocol names include:
  reality, anytls, tls, raw, ws, ws+tls, httpupgrade, httpupgrade+tls,
  grpc, grpc+tls, xhttp, xhttp+tls, quic, kcp, webtransport, shadowtls, vmess")]
    EvalServer {
        /// Listen address for the control channel
        #[arg(long, default_value = "127.0.0.1:19999")]
        listen: String,
        /// Shared authentication token (auto-generated if not provided)
        #[arg(long)]
        token: Option<String>,
        /// Comma-separated protocol list (default: all 17 combinations)
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
    #[command(after_long_help = "\
Examples:
  wrongsv eval-client --server 203.0.113.10:19999 --token TOKEN --duration 30 --output eval-remote

Outputs:
  The command writes <output>.json and <output>.csv, for example eval-remote.json and eval-remote.csv.")]
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
#[command(after_long_help = "\
Examples:
  wrongsv --config server.toml
  wrongsv --config server.toml --print-endpoint-diagnostics --server-host 203.0.113.10 --servername www.microsoft.com
  wrongsv generate-main-config --cluster anytls,vision --output-dir generated-anytls
  wrongsv eval-server --token TOKEN
  wrongsv eval-client --server 127.0.0.1:19999 --token TOKEN")]
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

    /// Override endpoint profile detection (use --transport as a compatibility alias)
    #[arg(long = "profile", alias = "transport")]
    profile: Option<Transport>,

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
            Commands::GenerateMainConfig(args) => {
                if let Err(e) = main_config::run(args) {
                    error!("{e}");
                    process::exit(1);
                }
                return;
            }
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
            cli.profile,
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
            cli.profile,
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
            cli.profile,
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
        naive: None,
        snell: None,
        lua: None,
        masque: None,
        trusttunnel: None,
        brook: None,
        vlite: None,
        tor: None,
        ssh: None,
        juicity: None,
        mieru: None,
        sudoku: None,
        vless_encryption: None,
        shadowquic: None,
        anytls_reality: None,
        metrics: None,
    }
}

fn load_config(path: &str) -> Result<wrongsv_server::Config, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: wrongsv_server::Config = toml::from_str(&content)?;
    Ok(config)
}

#[cfg(test)]
mod cli_help_tests {
    use super::*;
    use clap::CommandFactory;

    fn subcommand_help(name: &str) -> String {
        let mut command = Cli::command();
        command
            .find_subcommand_mut(name)
            .unwrap_or_else(|| panic!("missing subcommand {name}"))
            .render_long_help()
            .to_string()
    }

    #[test]
    fn public_help_includes_examples_and_supported_values() {
        let root_help = Cli::command().render_long_help().to_string();
        assert!(root_help.contains("Examples:"));
        assert!(root_help.contains("generate-main-config --cluster anytls,vision"));
        assert!(root_help.contains("Possible values:"));

        let generate_help = subcommand_help("generate-main-config");
        assert!(generate_help.contains("Supported cooperative clusters:"));
        assert!(generate_help.contains("anytls-vision"));
        assert!(generate_help.contains("anytls-reality"));

        let eval_server_help = subcommand_help("eval-server");
        assert!(eval_server_help.contains("all 17 combinations"));
        assert!(eval_server_help.contains("grpc+tls"));
        assert!(eval_server_help.contains("Examples:"));

        let eval_client_help = subcommand_help("eval-client");
        assert!(eval_client_help.contains("Examples:"));
        assert!(eval_client_help.contains("eval-remote.json"));
        assert!(eval_client_help.contains("eval-remote.csv"));
    }
}
