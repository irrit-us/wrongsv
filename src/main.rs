use std::process;

use clap::{Parser, ValueEnum};
use tracing::{error, info};
use wrongsv_server::Config;

#[derive(ValueEnum, Clone, Copy, PartialEq)]
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
}

#[derive(ValueEnum, Clone, Copy, PartialEq)]
enum ClientFormat {
    /// mihomo / FlClash / v2rayN format (flat keys)
    Mihomo,
    /// sing-box format (nested tls object)
    #[clap(name = "sing-box")]
    SingBox,
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

    /// Override transport type detection (reality, anytls, tls, raw)
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
    }
}

fn load_config(path: &str) -> Result<wrongsv_server::Config, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: wrongsv_server::Config = toml::from_str(&content)?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// client config generation
// ---------------------------------------------------------------------------

struct ClientConfigValues {
    uuid: String,
    port: String,
    short_id: String,
    x25519_pk: String,
    servername: String,
    transport: Transport,
    ws_path: String,
}

/// Resolve values for the generated client config from TOML config or defaults.
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

    // Determine transport: explicit --transport flag, or detect from config
    let transport = cli.transport.unwrap_or_else(|| match &toml_config {
        Some(cfg) if cfg.reality.is_some() => Transport::Reality,
        Some(cfg) if cfg.anytls.is_some() => Transport::AnyTls,
        Some(cfg) if cfg.websocket.is_some() => Transport::WebSocket,
        Some(cfg) if cfg.tls.is_some() => Transport::Tls,
        _ => Transport::Raw,
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
            // Default servername from reality.dest or tls servername
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
            let ws_path = cfg
                .websocket
                .as_ref()
                .map(|w| {
                    let p = &w.path;
                    if p.starts_with('/') {
                        p.clone()
                    } else {
                        format!("/{p}")
                    }
                })
                .unwrap_or_else(|| "/".to_string());

            ClientConfigValues {
                uuid: uuid.to_string(),
                port: port.to_string(),
                short_id: sid,
                x25519_pk: pk,
                servername,
                transport,
                ws_path,
            }
        }
        None => ClientConfigValues {
            uuid: build_uuid().to_string(),
            port: build_port().to_string(),
            short_id: build_sid().to_string(),
            x25519_pk: build_pk().to_string(),
            servername: cli.servername.clone(),
            ws_path: "/".to_string(),
            transport,
        },
    }
}

fn client_config_json(cli: &Cli) -> String {
    let vals = resolve_client_values(cli);
    match cli.format {
        ClientFormat::Mihomo => mihomo_format(cli, &vals),
        ClientFormat::SingBox => singbox_format(cli, &vals),
    }
}

// -- mihomo / FlClash / v2rayN format (flat keys) --

fn mihomo_format(cli: &Cli, vals: &ClientConfigValues) -> String {
    let reality_opts = match vals.transport {
        Transport::Reality => format!(
            ",\n  \"reality-opts\": {{\n    \"public-key\": \"{}\",\n    \"short-id\": \"{}\"\n  }}",
            vals.x25519_pk, vals.short_id
        ),
        _ => String::new(),
    };
    let transport = match vals.transport {
        Transport::WebSocket => format!(
            ",\n  \"network\": \"ws\",\n  \"ws-opts\": {{\n    \"path\": \"{}\"\n  }}",
            vals.ws_path
        ),
        _ => String::new(),
    };
    let tls_line = match vals.transport {
        Transport::Raw | Transport::WebSocket => String::new(),
        _ => format!(
            ",\n  \"tls\": true,\n  \"client-fingerprint\": \"chrome\",\n  \"servername\": \"{sni}\"",
            sni = vals.servername,
        ),
    };

    format!(
        r#"{{
  "name": "{name}",
  "type": "vless",
  "server": "{server}",
  "port": {port},
  "uuid": "{uuid}",
  "encryption": "none",
  "flow": "xtls-rprx-vision",
  "udp": true{tls}{reality}{transport}
}}"#,
        name = cli.client_name,
        server = cli.server_host,
        port = vals.port,
        uuid = vals.uuid,
        tls = tls_line,
        reality = reality_opts,
        transport = transport,
    )
}

// -- sing-box format (nested tls object) --

fn singbox_format(cli: &Cli, vals: &ClientConfigValues) -> String {
    let tls_lines = match vals.transport {
        Transport::Reality => vec![
            r#"      "tls": {"#.to_string(),
            r#"        "enabled": true,"#.to_string(),
            format!(r#"        "server_name": "{}","#, vals.servername),
            r#"        "utls": { "enabled": true, "fingerprint": "chrome" },"#.to_string(),
            r#"        "reality": {"#.to_string(),
            r#"          "enabled": true,"#.to_string(),
            format!(r#"          "public_key": "{}","#, vals.x25519_pk),
            format!(r#"          "short_id": "{}""#, vals.short_id),
            r#"        }"#.to_string(),
            r#"      }"#.to_string(),
        ],
        Transport::Tls | Transport::AnyTls => vec![
            r#"      "tls": {"#.to_string(),
            r#"        "enabled": true,"#.to_string(),
            format!(r#"        "server_name": "{}","#, vals.servername),
            r#"        "insecure": true,"#.to_string(),
            r#"        "utls": { "enabled": true, "fingerprint": "chrome" }"#.to_string(),
            r#"      }"#.to_string(),
        ],
        Transport::Raw | Transport::WebSocket => vec![],
    };

    let transport_lines = match vals.transport {
        Transport::WebSocket => vec![
            r#"      "transport": {"#.to_string(),
            r#"        "type": "ws","#.to_string(),
            format!(r#"        "path": "{}""#, vals.ws_path),
            r#"      }"#.to_string(),
        ],
        _ => vec![],
    };

    let flow_line = format!(
        r#"      "flow": ""{}"#,
        if !tls_lines.is_empty() || !transport_lines.is_empty() {
            ","
        } else {
            ""
        }
    );

    let mut lines = vec![
        r#"{"#.to_string(),
        r#"  "inbounds": [{ "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 10809 }],"#.to_string(),
        r#"  "outbounds": ["#.to_string(),
        r#"    {"#.to_string(),
        format!(r#"      "type": "vless","#),
        format!(r#"      "tag": "proxy","#),
        format!(r#"      "server": "{}","#, cli.server_host),
        format!(r#"      "server_port": {},"#, vals.port),
        format!(r#"      "uuid": "{}","#, vals.uuid),
        flow_line,
    ];
    for line in tls_lines {
        lines.push(line);
    }
    for line in transport_lines {
        lines.push(line);
    }
    lines.push(r#"    },"#.to_string());
    lines.push(r#"    {"type": "direct", "tag": "direct"}"#.to_string());
    lines.push(r#"  ]"#.to_string());
    lines.push(r#"}"#.to_string());

    lines.join("\n")
}

fn print_client_config(cli: &Cli) {
    println!("{}", client_config_json(cli));
}

fn write_client_config(path: &str, cli: &Cli) {
    std::fs::write(path, client_config_json(cli)).expect("failed to write client config");
}
