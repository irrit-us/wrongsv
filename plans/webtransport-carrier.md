# WebTransport Carrier — Implementation Plan

## Overview

Add WebTransport (`wt`) as a VLESS carrier transport, per `docs/PROTOCOL-COVERAGE.md` priority #2. WebTransport runs over HTTP/3 (QUIC), providing a modern alternative to WebSocket for tunneling proxy traffic.

## Dependency Compatibility

The `wtransport` crate v0.7.1 is compatible with existing deps:
- Project: `quinn = "0.11"` ↔ wtransport: `quinn ^0.11.6`
- Project: `rustls = "0.23"` ↔ wtransport: `rustls ^0.23.23`

## Implementation Steps

### Step 1 — Add `wtransport` dependency
- **File**: `Cargo.toml` (workspace)
  - Add `wtransport = "0.7"` to `[workspace.dependencies]`
- **File**: `crates/server/Cargo.toml`
  - Add `wtransport.workspace = true`

### Step 2 — Add `WebTransportServerConfig` to config.rs
- **File**: `crates/server/src/config.rs`
  - Add `#[derive(Debug, Clone, Deserialize)] pub struct WebTransportTlsConfig { certificate, key, dest }`
  - Add `#[derive(Debug, Clone, Deserialize)] pub struct WebTransportServerConfig { path, host, tls, udp_relay }`
  - Add `webtransport: Option<WebTransportServerConfig>` field to `Config` struct
  - Add to all `Config` literal constructions in tests

### Step 3 — Add validation rules
- **File**: `crates/server/src/config.rs`
  - Add `ConfigError` variants: `WebTransportWithVlessTransport`, `WebTransportWithNonVless`, `WebTransportMissingUsers`
  - WebTransport is a **datagram transport** (QUIC-based, like QUIC/KCP) — cannot combine with non-VLESS inbounds, TLS layers, stream framing, or other datagram transports
  - Requires VLESS users
  - Add validation in `Config::validate()` using `check_datagram_transport()`
  - Add to `has_any_vless_transport()` helper
  - Update `check_datagram_transport()` to include webtransport as a conflicting peer

### Step 4 — Create WebTransport handler
- **File**: `crates/server/src/handler/webtransport.rs`
  - `WebTransportConfig` internal struct (parsed TLS config, path, host, udp_relay)
  - `parse_webtransport_config()` — parse server config, build TLS config, create wtransport server config
  - `run_webtransport_endpoint()` — async fn: create wtransport Endpoint, accept loop, spawn session handlers
  - `handle_webtransport_session()` — accept bidirectional streams, spawn VLESS handler per stream
  - `WebTransportStream` — async→sync bridge (same pattern as `QuicStream`): `std::sync::mpsc` for incoming, `tokio::sync::mpsc` for outgoing
  - `handle_vless_over_webtransport()` — decode VLESS header, dispatch TCP/UDP relay
  - Relay functions: `relay_wt_raw()`, `relay_wt_vision()`, `relay_wt_udp()`
  - Match existing 10ms target read timeout pattern from QUIC carrier

### Step 5 — Register in mod.rs
- **File**: `crates/server/src/handler/mod.rs`
  - Add `pub(crate) mod webtransport; pub(crate) use webtransport::*;`
  - Add `webtransport_config: Option<WebTransportConfig>` to `InboundServer`
  - Parse config in `InboundServer::new()`
  - Add dispatch in `run_until_shutdown()` — before QUIC/KCP, since it's similar (needs its own tokio runtime for wtransport endpoint)
  - Add to per-connection error hints in `run_with_listener()` (like Hysteria2/TUIC — WebTransport uses QUIC, not TCP)

### Step 6 — Write tests
- **File**: `crates/server/src/handler/webtransport.rs` (unit tests)
  - Config parsing tests (default path, custom path, TLS config, udp_relay toggle)
- **File**: `crates/server/src/config.rs` (validation tests)
  - WebTransport + non-VLESS rejects
  - WebTransport + other datagram transport rejects
  - WebTransport + stream framing rejects
  - WebTransport without users rejects

### Step 7 — Update protocol coverage doc
- **File**: `docs/PROTOCOL-COVERAGE.md`
  - Mark WebTransport as Implemented, add to the Implemented table

## Architecture Notes

- WebTransport is a **datagram transport** (like QUIC/KCP), not a stream framing transport
- Uses its own tokio runtime for the async wtransport endpoint
- Dispatch order in `run_until_shutdown()`: Hysteria2 → TUIC → **WebTransport** → QUIC → KCP → TCP fallback
- UDP relay is optional (configurable via `udp_relay` flag)
- Vision flow is supported (same pattern as QUIC carrier)
- TLS is required for WebTransport (HTTP/3 mandates TLS via QUIC)

## Config TOML Example

```toml
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
flow = "xtls-rprx-vision"

[webtransport]
path = "/wt"
udp_relay = true

[webtransport.tls]
certificate = "---BEGIN CERTIFICATE..."
key = "---BEGIN PRIVATE KEY..."
```

## Verification
- `cargo build` succeeds
- `cargo test` (config + handler unit tests) passes
- `cargo clippy` clean
- `cargo fmt` clean
