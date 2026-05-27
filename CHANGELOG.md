# Changelog

## [Unreleased]

### Added

- **Plain TLS transport** (`[tls]` config section): Standard TLS 1.3 + VLESS,
  compatible with sing-box, mihomo, and xray-core `tls` transport. Auto-generated
  ECDSA P-256 self-signed certificates with uTLS Chrome fingerprint support.
- Config examples: `tls-vision.toml`, `tls-tcp.toml`.
- **Client config generation** now supports all transport types: REALITY, AnyTLS,
  TLS, and raw. Auto-detection from TOML config file + `--transport` override.
- **sing-box format** (`--format sing-box`): Generates nested `tls` object with
  `utls`, `reality` sub-blocks. Default is mihomo/FlClash flat-key format.
- Plain TLS deployment guide in `docs/simple-deploy.md`.

### Fixed

- **TLS+Vision deadlock**: Replaced `Arc<Mutex<AnyTlsStream>>` threaded relay
  with sequential relay using `get_mut()`. Uplink (TLS → Vision decode → target)
  and downlink (target → Vision encode → TLS) alternate in a single thread,
  eliminating the mutex deadlock that blocked HTTPS traffic.
- **Vision user_uuid corruption**: UUID is now consumed (`take()`) on first
  downlink write only. Previously, cloning `TrafficState` per iteration
  re-injected the UUID prefix, corrupting inner TLS data.
- **ECDSA P-256 certificates**: Cert generation uses `PKCS_ECDSA_P256_SHA256`
  instead of Ed25519, matching the signature algorithms advertised by Chrome
  uTLS fingerprint (ECDSA/RSA, not Ed25519).
- **ring crypto provider**: Switched from `aws-lc-rs` to `ring` for broader
  signature scheme support in rustls.
- **Relay timeout for high-RTT links**: Raised TLS stream read timeout from
  100ms to 5s and reordered relay loops to drain the target side first with
  aggressive 10ms retry. Eliminates WouldBlock spin cycles on links with
  600ms+ RTT. Added TCP_NODELAY on all target connections.

### Changed

- `VisionWriter.state` and `VisionWriter.user_uuid` fields are now `pub` for
  external state management in sequential relay.
- `config.example.toml` updated with all three transport sections (REALITY,
  AnyTLS, TLS) documented.
- README and SETUP docs updated with TLS transport, config reference, and
  client config generation for all formats.

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
