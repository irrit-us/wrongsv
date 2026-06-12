//! Evaluator server binary — starts the evaluation orchestrator.
//!
//! Usage:
//!   eval-server --listen 0.0.0.0:19999 --token my-token [--duration 3] [--protocols kcp,raw,tls] [--stack tier1] [--fixed-proxy-port 40000]

use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser)]
#[command(name = "eval-server")]
struct Cli {
    /// Listen address for the control channel
    #[arg(long, default_value = "0.0.0.0:19999")]
    listen: String,

    /// Authentication token
    #[arg(long, default_value = "eval-token")]
    token: String,

    /// Test duration in seconds per protocol
    #[arg(long, default_value = "3")]
    duration: u64,

    /// Comma-separated list of protocols to test (omit for all)
    #[arg(long)]
    protocols: Option<String>,

    /// Comma-separated list of stacks to test: tier1,tier2,tier3,tier4,post-quantum,legacy (or "all")
    /// When set, only the protocols in the selected stacks are tested, and a
    /// stack-level pass/fail summary is emitted.
    #[arg(long)]
    stack: Option<String>,

    /// Fixed proxy port (required for SSH tunnel remote evaluation)
    #[arg(long)]
    fixed_proxy_port: Option<u16>,

    /// Bind address for proxy servers (default: 127.0.0.1)
    #[arg(long, default_value = "127.0.0.1")]
    proxy_bind: String,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    // Validate listen address
    let _addr: SocketAddr = cli.listen.parse()?;

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(wrongsv_evaluator_server::orchestrator::run_orchestrator(
        &cli.listen,
        &cli.token,
        cli.protocols.as_deref(),
        cli.stack.as_deref(),
        cli.duration,
        &cli.proxy_bind,
        cli.fixed_proxy_port,
    ))?;

    Ok(())
}
