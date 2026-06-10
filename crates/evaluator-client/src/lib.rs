//! wrongsv-evaluator-client: Multi-protocol evaluation client.
//!
//! Connects to an evaluator-server, authenticates with a token, runs latency/
//! bandwidth/packet-loss tests through each protocol combination, and exports
//! results in JSON and CSV formats.

pub mod export;
pub mod runner;

pub use export::{BandwidthStats, LatencyStats, ProtocolResult, export_csv, export_json};
pub use runner::run_evaluation;
