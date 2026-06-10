# Changelog

## [0.2.4] — 2026-06-05

### Added

- **Traffic benchmark suite** (`benches/traffic/`): 6 public tools for stress testing
  (Deathcore/xray-core for REALITY, Hellcat-v2 for multi-user TLS, wrk2, Vegeta, k6).
  One-shot `setup.sh` to build all tools, `run.sh` for unified test execution.
- **Xray-core 26.5.9** bundling support: local build from `xray-core/` or download.

### Fixed

- **AnyTLS Vision relay**: `relay_anytls_vision` no longer breaks immediately on
  client close_notify. Target write side is shut down and the loop continues
  for downlink flush, matching the two-threaded `relay_vision` behavior.
  Fixes `test_anytls_vision_small`, `test_anytls_vision_16kb`,
  `test_anytls_multi_user`.
- **Go client test**: `test_go_client_handshake_with_rust_server` now skips
  gracefully when the external Go REALITY client binary is not present.

### Changed

- **Project structure**: Traffic benchmark tools merged from `bench/` into
  `benches/traffic/`, alongside existing `benches/throughput.rs`.

## [0.2.5] — 2026-06-10

### Added

- **VLESS gRPC carrier** (`[grpc]` config section): HTTP/2 gRPC transport
  with configurable service name/path and Cookie-based auth. Compatible with
  sing-box, mihomo, and xray-core gRPC transport.
- **VLESS HTTPUpgrade transport** (`[httpupgrade]`): HTTP 101 upgrade
  semantics with configurable path and early data support.
- **VLESS WebSocket carrier** (`[websocket]`): Full WS frame handling with
  early data, masked frames, configurable path, and XUDP MUX relay over
  `v1.mux.cool`.
- **VLESS XHTTP (SplitHTTP) carrier** (`[xhttp]`): HTTP streaming transport
  with GET/POST long-polling, host validation, custom prefix paths, and
  Vision flow support.
- **VLESS QUIC carrier** (`[quic]`): QUIC/UDP transport with H3
  compatibility.
- **VLESS KCP (mKCP) carrier** (`[kcp]`): UDP-based mKCP with configurable
  seed, MTU (576–1460), TTI (10–100ms), and header size.
- **VLESS PacketAddr UDP relay**: `sp.packet-addr.v2fly.arpa` packet
  address encoding for destination-aware UDP tunneling.
- **Plain TLS transport** (`[tls]`): Standard TLS 1.3 + VLESS with
  auto-generated ECDSA P-256 self-signed certificates and uTLS Chrome
  fingerprint support.
- **Shadowsocks AEAD** (`[shadowsocks]`): TCP and UDP relay with
  `chacha20-ietf-poly1305` and `aes-256-gcm` methods, configurable salt
  prefixes (1–16 bytes).
- **Shadowsocks 2022** (`[shadowsocks]`): TCP and UDP relay with
  `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm` methods.
- **Trojan TLS inbound** (`[trojan]`): TLS 1.3 + SHA-224 password hash
  authentication, TCP forwarding and UDP associate.
- **Mixed proxy inbound** (`[mixed]`): SOCKS5 with optional
  username/password auth, plus HTTP CONNECT forwarding.
- **HTTP Forward proxy** (`[http]`): Standard HTTP CONNECT proxy support.
- **SOCKS4 proxy**: Native SOCKS4 protocol support in the mixed inbound.
- **TUIC server inbound** (`[tuic]`): QUIC-based TUIC protocol v5 with
  configurable congestion control (cubic/new_reno/bbr).
- **Hysteria2 server inbound** (`[hysteria2]`): QUIC-based Hysteria2
  protocol with password-based auth and bandwidth negotiation.
- **sing-box config format**: `--format sing-box` generates nested `tls`
  object with `utls`/`reality` sub-blocks.
- **Client config generation** for all transport types: REALITY, AnyTLS,
  TLS, and raw. Auto-detection from TOML + `--transport` override.
- **Graceful server shutdown**: SIGTERM/SIGINT handling with drain timeout.
- Config examples: `tls-vision.toml`, `tls-tcp.toml`, `ws-tcp.toml`,
  `ws-udp.toml`, `httpupgrade.toml`, `grpc.toml`, `kcp.toml`, `quic.toml`,
  `xhttp.toml`, `shadowsocks.toml`, `trojan.toml`, `mixed.toml`,
  `tuic.toml`, `hysteria2.toml`.
- Plain TLS deployment guide in `docs/simple-deploy.md`.

### Fixed

- **KCP security**: Credential leak via error timing, 16-bit session ID
  collision, and idle session GC reaper.
- **TLS+Vision deadlock**: Replaced `Arc<Mutex<AnyTlsStream>>` with
  sequential relay using `get_mut()`, eliminating mutex deadlock on HTTPS.
- **Vision user_uuid corruption**: UUID now consumed (`take()`) on first
  downlink write only.
- **ECDSA P-256 certificates**: Cert generation uses
  `PKCS_ECDSA_P256_SHA256` instead of Ed25519.
- **Relay timeout for high-RTT links**: TLS read timeout raised to 5s,
  target-drain-first ordering with 10ms retry. TCP_NODELAY on all target
  connections.
- **sing-anytls stream cleanup**: Closed streams now properly removed from
  session state.

### Changed

- **Handler refactored**: `handler.rs` (3.2K lines) split into 10 modules.
  TLS backend unified across all protocols.
- `VisionWriter.state` and `VisionWriter.user_uuid` fields are now `pub`.
- `config.example.toml` updated with all transport/protocol sections.
- README and SETUP docs updated with full feature matrix.
- Clippy clean on all crates; `rustfmt` applied workspace-wide.

## [0.2.3] — 2026-05-27

### Fixed

- **Panic prevention in REALITY TLS**: Removed `unreachable!()` in
  `RealityTlsStream::read()` (tls.rs:52) that could trigger if rustls returned
  unexpected I/O states. Replaced `.expect()` in `compute_cert_hmac` with proper
  `Result` propagation.
- **Worker thread panic isolation**: Connection handler threads are now wrapped in
  `std::panic::catch_unwind` with `AssertUnwindSafe`. Panics in worker threads
  are logged via `error!()` instead of silently terminating the thread or
  (on older Rust editions) aborting the process.
- **FlClash/mihomo config generation**: Fixed generated JSON format in
  `client_config_json` — keys now match mihomo Go struct tags:
  `"fingerprint"` → `"client-fingerprint"`, `"publicKey"` → `"public-key"`,
  `"shortId"` → `"short-id"`. Added missing `"tls": true` field.

### Changed

- Clippy clean on all library crates; `rustfmt` applied across workspace.

## [0.2.2] — 2026-05-27

### Fixed

- **Vision relay hang**: `RealityTlsStream::read` did not handle
  `Err(WouldBlock)` from rustls `reader().read()`, causing XTLS Vision relay
  to spin indefinitely without reading new TLS records from the socket.
- **Security**: TLS 1.3 session secrets logged at `INFO` level via
  `DebugKeyLog`. Secrets now only written to a file when
  `WRONGSV_KEYLOG_FILE` env var is explicitly set.
- **Log noise**: ClientHello cipher suite dump downgraded from `INFO` to
  `DEBUG` level. Removed hex dump debug logging from handler and tls acceptor.

### Docs

- Fixed `short_ids` size in README, SETUP, and config.example.toml: 4 bytes
  (8 hex chars), not 8 bytes (16 hex chars).

## [0.2.0] — 2026-05-26

### Added

- **AnyTLS protocol** (`crates/anytls`): TLS 1.3 disguise with SHA-256 password
  authentication, configurable padding, and fallback relay for active probe
  resistance. Wraps VLESS traffic in a standard TLS connection with a
  `SHA256(password) || padding_len || random_padding` auth frame.
- 14 integration tests for AnyTLS covering: basic echo, Vision relay, 4KB/16KB
  payloads, UDP relay, auth failure (with/without fallback), custom TLS certs,
  padding (217B and 8192B), multi-user, concurrent connections, auth failure
  with padding, and Kyber + AnyTLS combo.
- Config examples: `anytls-tcp.toml`, `anytls-udp.toml`, `anytls-vision.toml`,
  `anytls-fallback.toml`, `anytls-custom.toml`, `basic-tcp.toml`,
  `kyber-vision.toml`, `reality-vision.toml`, `reality-udp.toml`, `vision.toml`.
- `AnyTlsServerConfig` with fields: `password`, `dest` (fallback),
  `certificate`, `key`, `padding_scheme`.
- GitHub community docs: `SECURITY.md`, `CONTRIBUTING.md`, issue templates
  (bug report, feature request), PR template.

### Changed

- Banner redesigned: Cinzel Bold title, centered vertical layout (title /
  subtitle / keywords / flow diagram), two-color RGB scheme (#7c91db on
  white), flow diagram with Client → wrongsv → Target arrows.
- Subtitle updated to "Entrust Privacy to Protocol Security".
- README and SETUP expanded with AnyTLS documentation, config reference,
  and quick-start table.

## [0.1.0] — 2026-05-23

### Added

- Initial release: VLESS proxy server with XTLS Vision flow, UDP relay,
  ML-KEM-512 (Kyber) post-quantum key encapsulation, and REALITY TLS
  camouflage.
