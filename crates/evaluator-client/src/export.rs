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
