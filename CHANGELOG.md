# Changelog

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
