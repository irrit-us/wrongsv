# Changelog

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
