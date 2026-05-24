use std::process;

use clap::Parser;
use tracing::{error, info};
use wrongsv_server::Config;

#[derive(Parser)]
#[command(name = "wrongsv", about = "VLESS proxy server")]
struct Cli {
    /// Path to TOML config file (optional — uses compile-time defaults if omitted)
    #[arg(short, long)]
    config: Option<String>,

    /// Write a v2rayN-compatible client config JSON to the given path
    #[arg(long)]
    write_client_config: Option<String>,

    /// Print a v2rayN-compatible client config JSON to stdout
    #[arg(long)]
    print_client_config: bool,

    /// Server hostname or IP for the generated client config
    #[arg(long, default_value = "YOUR_SERVER_IP")]
    server_host: String,

    /// REALITY SNI for the generated client config
    #[arg(long, default_value = "YOUR_SNI")]
    servername: String,

    /// Label for the generated client config
    #[arg(long, default_value = "wrongsv")]
    client_name: String,
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
        print_client_config(&cli);
        return;
    }
    if let Some(ref path) = cli.write_client_config {
        write_client_config(path, &cli);
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
        }],
        decryption: None,
        flow: Some("xtls-rprx-vision".into()),
        kyber_secret_key: kyber,
    }
}

fn load_config(path: &str) -> Result<wrongsv_server::Config, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: wrongsv_server::Config = toml::from_str(&content)?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// client config generation (v2rayN / v2rayNG compatible JSON)
// ---------------------------------------------------------------------------

fn client_config_json(cli: &Cli) -> String {
    let uuid = option_env!("BUILD_UUID").unwrap_or("00000000-0000-4000-8000-000000000000");
    let port = option_env!("BUILD_PORT").unwrap_or("443");
    let short_id = option_env!("BUILD_SHORT_ID").unwrap_or("00000000");
    let x25519_pk = option_env!("BUILD_X25519_PK").unwrap_or("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    format!(
        r#"{{
  "name": "{name}",
  "type": "vless",
  "server": "{server}",
  "port": {port},
  "uuid": "{uuid}",
  "udp": true,
  "tls": true,
  "skip-cert-verify": false,
  "flow": "xtls-rprx-vision",
  "client-fingerprint": "chrome",
  "servername": "{sni}",
  "reality-opts": {{
    "public-key": "{pk}",
    "short-id": "{sid}"
  }}
}}"#,
        name = cli.client_name,
        server = cli.server_host,
        port = port,
        uuid = uuid,
        sni = cli.servername,
        pk = x25519_pk,
        sid = short_id,
    )
}

fn print_client_config(cli: &Cli) {
    println!("{}", client_config_json(cli));
}

fn write_client_config(path: &str, cli: &Cli) {
    std::fs::write(path, client_config_json(cli)).expect("failed to write client config");
}
