//! Evaluator client binary — connects to eval-server and runs all tests.
//!
//! Usage:
//!   eval-client --server 127.0.0.1:19999 --token my-token [--duration 3]

use clap::Parser;

#[derive(Parser)]
#[command(name = "eval-client")]
struct Cli {
    /// Evaluator server address (control channel)
    #[arg(long, default_value = "127.0.0.1:19999")]
    server: String,

    /// Authentication token
    #[arg(long, default_value = "eval-token")]
    token: String,

    /// Test duration in seconds per protocol
    #[arg(long, default_value = "3")]
    duration: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    println!("connecting to eval-server at {}...", cli.server);

    let results =
        wrongsv_evaluator_client::runner::run_evaluation(&cli.server, &cli.token, cli.duration)?;

    println!();
    println!("{:=<60}", "");
    println!(
        "{:20} {:>8} {:>12} {:>12} {:>6}",
        "Protocol", "Latency", "Upload", "Download", "Loss"
    );
    println!("{:-<60}", "");
    for r in &results {
        println!(
            "{:20} {:>6.2}ms {:>8.2} Mbps {:>8.2} Mbps {:>5.1}%",
            r.protocol,
            r.latency_ms.avg,
            r.bandwidth_mbps.upload,
            r.bandwidth_mbps.download,
            r.packet_loss_pct,
        );
    }
    println!("{:=<60}", "");

    Ok(())
}
