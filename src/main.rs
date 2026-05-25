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
        reality: None,
    }
}

fn load_config(path: &str) -> Result<wrongsv_server::Config, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: wrongsv_server::Config = toml::from_str(&content)?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// client config generation (Xray-compatible JSON)
// ---------------------------------------------------------------------------

struct ClientConfigValues {
    uuid: String,
    port: String,
    short_id: String,
    x25519_pk: String,
    servername: String,
}

/// Resolve values for the generated client config.
///
/// If a TOML config is provided AND the user hasn't overridden --servername
/// from its default, TOML values for uuid/port/reality are used. Otherwise
/// compile-time BUILD_* defaults are used.
fn resolve_client_values(cli: &Cli) -> ClientConfigValues {
    let build_uuid = || option_env!("BUILD_UUID").unwrap_or("00000000-0000-4000-8000-000000000000");
    let build_port = || option_env!("BUILD_PORT").unwrap_or("443");
    let build_sid = || option_env!("BUILD_SHORT_ID").unwrap_or("00000000");
    let build_pk =
        || option_env!("BUILD_X25519_PK").unwrap_or("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    let toml_config = cli.config.as_ref().and_then(|path| {
        let content = std::fs::read_to_string(path).ok()?;
        toml::from_str::<wrongsv_server::Config>(&content).ok()
    });

    match toml_config {
        Some(ref cfg) => {
            let uuid = cfg
                .users
                .first()
                .map(|u| u.id.as_str())
                .unwrap_or(build_uuid());
            let port = cfg.listen.rsplit(':').next().unwrap_or(build_port());
            let (pk, sid) = match &cfg.reality {
                Some(rc) => {
                    let pk = wrongsv_reality::private_key_hex_to_public_b64(&rc.private_key)
                        .unwrap_or_else(|_| build_pk().to_string());
                    let sid = rc
                        .short_ids
                        .first()
                        .cloned()
                        .unwrap_or_else(|| build_sid().to_string());
                    (pk, sid)
                }
                None => (build_pk().to_string(), build_sid().to_string()),
            };
            // Default servername from reality.dest hostname if user didn't override
            let servername = if cli.servername == "YOUR_SNI" {
                cfg.reality
                    .as_ref()
                    .and_then(|rc| rc.dest.as_ref())
                    .and_then(|d| d.split(':').next())
                    .unwrap_or(&cli.servername)
                    .to_string()
            } else {
                cli.servername.clone()
            };

            ClientConfigValues {
                uuid: uuid.to_string(),
                port: port.to_string(),
                short_id: sid,
                x25519_pk: pk,
                servername,
            }
        }
        None => ClientConfigValues {
            uuid: build_uuid().to_string(),
            port: build_port().to_string(),
            short_id: build_sid().to_string(),
            x25519_pk: build_pk().to_string(),
            servername: cli.servername.clone(),
        },
    }
}

fn client_config_json(cli: &Cli) -> String {
    let vals = resolve_client_values(cli);

    format!(
        r#"{{
  "name": "{name}",
  "type": "vless",
  "server": "{server}",
  "port": {port},
  "uuid": "{uuid}",
  "encryption": "none",
  "flow": "xtls-rprx-vision",
  "fingerprint": "chrome",
  "servername": "{sni}",
  "reality-opts": {{
    "publicKey": "{pk}",
    "shortId": "{sid}"
  }}
}}"#,
        name = cli.client_name,
        server = cli.server_host,
        port = vals.port,
        uuid = vals.uuid,
        sni = vals.servername,
        pk = vals.x25519_pk,
        sid = vals.short_id,
    )
}

fn print_client_config(cli: &Cli) {
    println!("{}", client_config_json(cli));
}

fn write_client_config(path: &str, cli: &Cli) {
    std::fs::write(path, client_config_json(cli)).expect("failed to write client config");
}
