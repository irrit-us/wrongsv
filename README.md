<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/banner.png">
    <img src="assets/banner.png" alt="wrongsv banner" width="800">
  </picture>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License: MIT"></a>
  <a href="#"><img src="https://img.shields.io/badge/rust-stable-orange?style=for-the-badge&logo=rust" alt="Rust: stable"></a>
  <img src="https://img.shields.io/badge/protocol-VLESS-blue?style=for-the-badge" alt="Protocol: VLESS">
  <img src="https://img.shields.io/badge/flow-xtls--rprx--vision-purple?style=for-the-badge" alt="Flow: XTLS Vision">
  <img src="https://img.shields.io/badge/TLS-REALITY%201.3-brightgreen?style=for-the-badge" alt="TLS: REALITY 1.3">
  <img src="https://img.shields.io/badge/TLS-AnyTLS-7c91db?style=for-the-badge" alt="TLS: AnyTLS">
  <img src="https://img.shields.io/badge/KEM-ML--KEM--512-darkslateblue?style=for-the-badge" alt="KEM: ML-KEM-512">
</p>

---

A minimal, high-performance VLESS proxy server with XTLS Vision flow, REALITY and AnyTLS authentication, and NIST ML-KEM post-quantum key encapsulation. Built as a terminal-based runtime that accepts VLESS connections, validates users, decodes XTLS Vision traffic, and forwards to target destinations.

## Architecture

```
wrongsv (binary)
├── server          — inbound handler, config, connection relay
├── reality         — REALITY TLS 1.3 authentication with spider fallback
├── anytls          — AnyTLS TLS disguise with SHA-256 password auth + fallback
├── vless           — user validator, XTLS Vision padding/unpadding
├── vless-encoding  — VLESS header codec, addons protobuf, body framing
├── encryption      — TLS-1.3-disguised AEAD (AES-256-GCM / ChaCha20-Poly1305)
├── kyber           — NIST ML-KEM-512 post-quantum key encapsulation
├── protocol        — shared types (RequestHeader, MemoryUser, ID, AddressParser)
├── net-types       — Address, Port, AddressFamily
└── uuid            — UUID v4/v5, ProcessUUID masking
```

## Features

- **VLESS protocol** — stateless proxy wire format with version + UUID + addons + command + address
- **REALITY** — TLS 1.3 handshake hijacking with X25519 ECDH auth, dynamic Ed25519 cert generation, spider fallback. Compatible with xray-core clients.
- **AnyTLS** — TLS 1.3 disguise with SHA-256 password authentication and configurable padding. Simpler alternative to REALITY: uses a standard TLS handshake + password instead of ECDH key agreement.
- **XTLS Vision** (`xtls-rprx-vision`) — traffic analysis resistance via padding/unpadding
- **TLS 1.3 record disguise** — AEAD-encrypted transport that appears as TLS 1.3 application data
- **AEAD ciphers** — AES-256-GCM and ChaCha20-Poly1305 with BLAKE3 key derivation
- **NIST ML-KEM-512** — post-quantum session key establishment (FIPS 203)
- **Protobuf addons** — extensible handshake metadata (flow, Kyber ciphertext)
- **Probe resistance** — unauthenticated connections are transparently forwarded to fallback destinations
- **Config examples** — ready-to-use TOML files in [`configs/`](configs/) covering REALITY, AnyTLS, Vision, Kyber, UDP, and fallback

## Quick Start

[SETUP.md](SETUP.md) has the full build, configuration, and troubleshooting guide.

### Build

```bash
cargo build --release
```

### Configure

Pick an example from [`configs/`](configs/):

| Config | Transport | Flow | Notes |
|--------|-----------|------|-------|
| [`configs/basic-tcp.toml`](configs/basic-tcp.toml) | raw TCP | none | Simplest setup |
| [`configs/vision.toml`](configs/vision.toml) | raw TCP | Vision | Traffic analysis resistance |
| [`configs/reality-vision.toml`](configs/reality-vision.toml) | REALITY TLS | Vision | ECDH auth + spider fallback |
| [`configs/reality-udp.toml`](configs/reality-udp.toml) | REALITY TLS | none | With UDP relay |
| [`configs/anytls-vision.toml`](configs/anytls-vision.toml) | AnyTLS | Vision | Password auth |
| [`configs/anytls-tcp.toml`](configs/anytls-tcp.toml) | AnyTLS | none | Password auth + raw |
| [`configs/anytls-udp.toml`](configs/anytls-udp.toml) | AnyTLS | none | Password auth + UDP |
| [`configs/anytls-fallback.toml`](configs/anytls-fallback.toml) | AnyTLS | Vision | With fallback dest |
| [`configs/kyber-vision.toml`](configs/kyber-vision.toml) | raw TCP | Vision | Post-quantum KEM |
| [`configs/anytls-custom.toml`](configs/anytls-custom.toml) | AnyTLS | Vision | Custom cert + padding |

Or create your own:

```toml
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"
flow = "xtls-rprx-vision"
```

### Run

```bash
# With a config file
cargo run --release -- --config config.toml

# Zero-config mode (compile-time defaults from build.rs)
cargo run --release
```

### Client config generation

The server can generate a v2rayN/v2rayNG-compatible client config JSON:

```bash
cargo run --release -- --print-client-config --server-host YOUR_IP --servername YOUR_SNI

cargo run --release -- --write-client-config client.json --server-host YOUR_IP --servername YOUR_SNI
```

## Testing

```bash
cargo test                                    # all unit + integration + vision + anytls tests
cargo test --test integration                 # integration tests (REALITY, cross-compat, randomized)
cargo test --test vision_relay_tests          # Vision relay tests (HTTP, TLS-in-TLS, UDP, concurrency)
cargo test --test anytls_tests                # AnyTLS tests (echo, Vision, fallback, UDP)
cargo bench                                   # criterion benchmarks
```

### Stress test

```bash
cargo run --example stress
```

Runs 480 connections across 3 rounds and monitors RSS for memory leaks.

## Config Reference

| Field | Type | Description |
|-------|------|-------------|
| `listen` | string | Address to listen on (e.g. `"0.0.0.0:443"`) |
| `users` | array | List of VLESS user entries |
| `users[].id` | string | UUID in hex format |
| `users[].email` | string | Optional email label |
| `users[].flow` | string | `""` (raw) or `"xtls-rprx-vision"` |
| `users[].udp` | bool | Enable UDP relay (default: `true`) |
| `users[].encryption` | string | Per-user encryption key |
| `flow` | string | Default flow for all users |
| `kyber_secret_key` | string | ML-KEM-512 64-byte seed (hex-encoded) |
| **REALITY** | | |
| `reality.private_key` | string | X25519 32-byte private key (hex-encoded) |
| `reality.short_ids` | []string | Allowed short IDs (8-byte hex strings) |
| `reality.max_time_diff` | int | Max clock skew in seconds (default 300) |
| `reality.dest` | string | Spider fallback target (e.g. `"www.microsoft.com:443"`) |
| **AnyTLS** | | |
| `anytls.password` | string | Password for SHA-256 auth |
| `anytls.dest` | string | Fallback target for failed auth |
| `anytls.certificate` | string | Optional TLS cert PEM (auto-generated if omitted) |
| `anytls.key` | string | Optional TLS key PEM |
| `anytls.padding_scheme` | string | Optional padding scheme (anytls-go format) |

## Security

- **Encryption in transit**: AEAD with TLS 1.3 record disguise prevents DPI-based protocol identification
- **Post-quantum KEM**: ML-KEM-512 (NIST FIPS 203) for forward-secure session keys resistant to quantum attacks
- **Traffic analysis resistance**: XTLS Vision padding eliminates length-based fingerprinting
- **No pre-shared keys required**: Kyber key exchange establishes session keys without prior key distribution
- **Password authentication**: AnyTLS uses SHA-256 password verification in constant time

## Verified Interop

- **xray-core 26.5.9+** — REALITY handshake completes with `uConn.Verified: true`. Ed25519 certs work with Chrome fingerprint.
- **REALITY spider fallback** — unauthenticated probes forwarded to `dest` target. Confirmed with `curl` → `www.microsoft.com:443`.
- **AnyTLS echo relay** — TLS 1.3 handshake, password auth, VLESS header exchange, and bidirectional data relay verified end-to-end.
- **AnyTLS + Vision** — full XTLS Vision padding/unpadding over AnyTLS TLS connections. Small (14B) and large (16KB) payloads verified.
- **AnyTLS fallback** — wrong password → connection forwarded to fallback destination.
- **AnyTLS UDP** — length-prefixed UDP relay over AnyTLS TLS.
- **Concurrent connections** — 6+ simultaneous REALITY connections all authenticate and relay correctly.

## License

MIT
