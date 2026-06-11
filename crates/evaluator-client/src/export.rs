//! Export evaluation results to JSON and CSV.

use serde::Serialize;

/// Serializable result from a single protocol evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct ProtocolResult {
    pub protocol: String,
    pub latency_ms: LatencyStats,
    pub bandwidth_mbps: BandwidthStats,
    pub packet_loss_pct: f64,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct LatencyStats {
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct BandwidthStats {
    pub upload: f64,
    pub download: f64,
}

/// Export results to a JSON string.
pub fn export_json(results: &[ProtocolResult]) -> String {
    serde_json::to_string_pretty(results).expect("ProtocolResult should serialize")
}

/// Export results to a CSV string.
pub fn export_csv(results: &[ProtocolResult]) -> String {
    let mut csv = String::from(
        "protocol,lat_min_ms,lat_max_ms,lat_avg_ms,lat_p50_ms,lat_p95_ms,lat_p99_ms,\
         bw_upload_mbps,bw_download_mbps,packet_loss_pct\n",
    );
    for r in results {
        csv.push_str(&format!(
            "{},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2}\n",
            r.protocol,
            r.latency_ms.min,
            r.latency_ms.max,
            r.latency_ms.avg,
            r.latency_ms.p50,
            r.latency_ms.p95,
            r.latency_ms.p99,
            r.bandwidth_mbps.upload,
            r.bandwidth_mbps.download,
            r.packet_loss_pct,
        ));
    }
    csv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_results() -> Vec<ProtocolResult> {
        vec![
            ProtocolResult {
                protocol: "raw".into(),
                latency_ms: LatencyStats {
                    min: 0.1,
                    max: 1.2,
                    avg: 0.5,
                    p50: 0.45,
                    p95: 1.0,
                    p99: 1.1,
                },
                bandwidth_mbps: BandwidthStats {
                    upload: 1000.0,
                    download: 2000.0,
                },
                packet_loss_pct: 0.0,
            },
            ProtocolResult {
                protocol: "tls".into(),
                latency_ms: LatencyStats {
                    min: 5.0,
                    max: 50.0,
                    avg: 10.0,
                    p50: 8.0,
                    p95: 40.0,
                    p99: 48.0,
                },
                bandwidth_mbps: BandwidthStats {
                    upload: 500.0,
                    download: 600.0,
                },
                packet_loss_pct: 0.5,
            },
        ]
    }

    #[test]
    fn export_json_contains_all_protocols() {
        let json = export_json(&sample_results());
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["protocol"], "raw");
        assert_eq!(parsed[1]["protocol"], "tls");
    }

    #[test]
    fn export_json_contains_metrics() {
        let json = export_json(&sample_results());
        assert!(json.contains("latency_ms"));
        assert!(json.contains("bandwidth_mbps"));
        assert!(json.contains("packet_loss_pct"));
        assert!(json.contains("0.5")); // pkt loss for tls
    }

    #[test]
    fn export_csv_has_header() {
        let csv = export_csv(&sample_results());
        assert!(csv.starts_with("protocol,lat_min_ms"));
    }

    #[test]
    fn export_csv_row_count() {
        let csv = export_csv(&sample_results());
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 data rows
    }

    #[test]
    fn export_csv_contains_protocol_names() {
        let csv = export_csv(&sample_results());
        assert!(csv.contains("raw,0.10"));
        assert!(csv.contains("tls,5.00"));
    }

    #[test]
    fn export_empty_results() {
        let json = export_json(&[]);
        assert_eq!(json.trim(), "[]");

        let csv = export_csv(&[]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 1); // header only
    }
}
