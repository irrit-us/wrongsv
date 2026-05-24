use std::process;

use clap::Parser;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "wrongsv", about = "VLESS proxy server")]
struct Cli {
    /// Path to TOML config file
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let config = match load_config(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to load config: {}", e);
            process::exit(1);
        }
    };

    let server = match wrongsv_server::InboundServer::new(config) {
        Ok(s) => s,
        Err(e) => {
            error!("failed to initialize server: {}", e);
            process::exit(1);
        }
    };

    info!("starting wrongsv server...");
    if let Err(e) = server.run() {
        error!("server error: {}", e);
        process::exit(1);
    }
}

fn load_config(path: &str) -> Result<wrongsv_server::Config, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: wrongsv_server::Config = toml::from_str(&content)?;
    Ok(config)
}
