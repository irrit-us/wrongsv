//! Wire protocol types for the evaluation control channel.
//! JSON-line protocol over TCP between evaluator-server and evaluator-client.

use serde::{Deserialize, Serialize};

/// Messages from client to server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Authenticate with the shared token.
    #[serde(rename = "auth")]
    Auth { token: String },
    /// Client is ready to begin a test.
    #[serde(rename = "ready")]
    Ready { protocol: String },
    /// Test results for a protocol.
    #[serde(rename = "result")]
    Result {
        protocol: String,
        metrics: ProtocolMetrics,
    },
}

/// Messages from server to client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Authentication succeeded.
    #[serde(rename = "auth_ok")]
    AuthOk,
    /// Authentication failed.
    #[serde(rename = "auth_err")]
    AuthErr { reason: String },
    /// Test configuration for a protocol.
    #[serde(rename = "test")]
    TestConfig {
        protocol: String,
        proxy_port: u16,
        target_port: u16,
        uuid: String,
    },
    /// Start the test.
    #[serde(rename = "start")]
    Start {
        protocol: String,
        duration_secs: u64,
    },
    /// Next protocol or done.
    #[serde(rename = "next")]
    Next,
    /// All tests complete.
    #[serde(rename = "done")]
    Done,
}

/// Collected metrics for a single protocol evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMetrics {
    pub protocol: String,
    pub latency_ms: LatencyStats,
    pub bandwidth_mbps: BandwidthStats,
    pub packet_loss_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthStats {
    pub upload: f64,
    pub download: f64,
}

impl ProtocolMetrics {
    /// Export all results as a JSON string.
    pub fn export_json(results: &[Self]) -> String {
        serde_json::to_string_pretty(results).expect("ProtocolMetrics should serialize")
    }

    /// Export all results as CSV.
    pub fn export_csv(results: &[Self]) -> String {
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
}
