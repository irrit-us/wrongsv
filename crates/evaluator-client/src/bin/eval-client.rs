//! Evaluator client binary — connects to eval-server and runs all tests.
//!
//! Usage:
//!   eval-client --server 127.0.0.1:19999 [--token my-token] [--duration 3]
//!   eval-client --cluster core=tls,reality --cluster legacy=vmess

use clap::Parser;

/// Generate a random 32-char hex token.
fn random_token() -> String {
    (0..16)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect()
}

#[derive(Parser)]
#[command(name = "eval-client")]
struct Cli {
    /// Evaluator server address (control channel)
    #[arg(long, default_value = "127.0.0.1:19999")]
    server: String,

    /// Authentication token (must match server; auto-generated if not set)
    #[arg(long)]
    token: Option<String>,

    /// Test duration in seconds per protocol
    #[arg(long, default_value = "3")]
    duration: u64,

    /// Named protocol cluster, format `name=p1,p2,...`. Repeatable.
    /// Each cluster is reported as PASS/FAIL based on its members'
    /// per-protocol packet-loss. When any --cluster is given, only the
    /// union of cluster members is evaluated.
    #[arg(long = "cluster", value_name = "NAME=PROTOS")]
    clusters: Vec<String>,
}

struct Cluster {
    name: String,
    protocols: Vec<String>,
}

fn parse_clusters(raw: &[String]) -> Result<Vec<Cluster>, String> {
    raw.iter()
        .map(|spec| {
            let (name, list) = spec
                .split_once('=')
                .ok_or_else(|| format!("invalid --cluster (missing '='): {spec}"))?;
            let protocols: Vec<String> = list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if protocols.is_empty() {
                return Err(format!("cluster '{name}' has no protocols"));
            }
            Ok(Cluster {
                name: name.trim().to_string(),
                protocols,
            })
        })
        .collect()
}

/// Deduplicated union of all cluster protocols, preserving first-seen order.
fn union(clusters: &[Cluster]) -> Vec<String> {
    let mut out = Vec::new();
    for c in clusters {
        for p in &c.protocols {
            if !out.contains(p) {
                out.push(p.clone());
            }
        }
    }
    out
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let token = cli.token.unwrap_or_else(random_token);
    eprintln!("auth token: {token}");

    let clusters = parse_clusters(&cli.clusters)?;
    let selected = union(&clusters);

    println!("connecting to eval-server at {}...", cli.server);

    let results = wrongsv_evaluator_client::runner::run_evaluation(
        &cli.server,
        &token,
        cli.duration,
        &selected,
    )?;

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

    if !clusters.is_empty() {
        println!();
        println!("{:=<60}", "");
        println!("Cluster Results");
        println!("{:-<60}", "");
        for c in &clusters {
            let failing: Vec<&str> = c
                .protocols
                .iter()
                .filter(|p| {
                    results
                        .iter()
                        .find(|r| r.protocol == **p)
                        .is_none_or(|r| r.packet_loss_pct > 0.0)
                })
                .map(String::as_str)
                .collect();
            let status = if failing.is_empty() { "PASS" } else { "FAIL" };
            println!(
                "  {:<16} {}  protocols: {}",
                c.name,
                status,
                c.protocols.join(", ")
            );
            if !failing.is_empty() {
                println!("    failing: {}", failing.join(", "));
            }
        }
        println!("{:=<60}", "");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_clusters_basic() {
        let raw = vec!["core=tls,reality".to_string(), "legacy=vmess".to_string()];
        let cs = parse_clusters(&raw).unwrap();
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0].name, "core");
        assert_eq!(cs[0].protocols, vec!["tls", "reality"]);
        assert_eq!(cs[1].name, "legacy");
        assert_eq!(cs[1].protocols, vec!["vmess"]);
    }

    #[test]
    fn parse_clusters_trims_whitespace() {
        let raw = vec!["core =  tls , reality ".to_string()];
        let cs = parse_clusters(&raw).unwrap();
        assert_eq!(cs[0].name, "core");
        assert_eq!(cs[0].protocols, vec!["tls", "reality"]);
    }

    #[test]
    fn parse_clusters_rejects_missing_equals() {
        let raw = vec!["nocluster".to_string()];
        assert!(parse_clusters(&raw).is_err());
    }

    #[test]
    fn parse_clusters_rejects_empty_protocols() {
        let raw = vec!["empty=".to_string()];
        assert!(parse_clusters(&raw).is_err());
    }

    #[test]
    fn union_deduplicates() {
        let cs = vec![
            Cluster {
                name: "a".into(),
                protocols: vec!["tls".into(), "raw".into()],
            },
            Cluster {
                name: "b".into(),
                protocols: vec!["raw".into(), "vmess".into()],
            },
        ];
        assert_eq!(union(&cs), vec!["tls", "raw", "vmess"]);
    }

    #[test]
    fn union_empty_when_no_clusters() {
        assert!(union(&[]).is_empty());
    }
}
