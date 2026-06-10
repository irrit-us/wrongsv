//! wrongsv-evaluator-server: Multi-protocol evaluation orchestrator.
//!
//! Provides the server side of the evaluation system:
//! - Control channel (TCP, JSON-line) for authentication and coordination
//! - Echo, bandwidth, and packet-loss target servers
//! - Automatic wrongsv proxy spawning per protocol combination
//!
//! ## Usage
//!
//! ```ignore
//! use wrongsv_evaluator_server::run_orchestrator;
//! run_orchestrator("127.0.0.1:19999", "my-token", Some("reality,tls"), 10).await?;
//! ```

pub mod orchestrator;
pub mod protocol;
pub mod target;

pub use orchestrator::{DEFAULT_PROTOCOLS, resolve_protocols, run_orchestrator};
pub use protocol::{BandwidthStats, LatencyStats, ProtocolMetrics};
