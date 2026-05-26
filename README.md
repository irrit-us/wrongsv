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
  <img src="https://img.shields.io/badge/KEM-ML--KEM--512-darkslateblue?style=for-the-badge" alt="KEM: ML-KEM-512">
</p>

---

A minimal, high-performance VLESS proxy server with XTLS Vision flow and NIST ML-KEM post-quantum key encapsulation. Built as a terminal-based runtime that accepts VLESS connections, validates users, decodes XTLS Vision traffic, and forwards to target destinations.

## Architecture

```
wrongsv (binary)
├── server        — inbound handler, config, connection relay
├── reality       — REALITY TLS 1.3 authentication with spider fallback
├── vless         — user validator, XTLS Vision padding/unpadding
├── vless-encoding — VLESS header codec, addons protobuf, body framing
├── encryption    — TLS-1.3-disguised AEAD (AES-256-GCM / ChaCha20-Poly1305)
├── kyber         — NIST ML-KEM-512 post-quantum key encapsulation
├── protocol      — shared types (RequestHeader, MemoryUser, ID, AddressParser)
├── net-types     — Address, Port, AddressFamily
└── uuid          — UUID v4/v5, ProcessUUID masking
```

## Features

- **VLESS protocol** — stateless proxy wire format with version + UUID + addons + command + address
- **REALITY** — TLS 1.3 handshake hijacking with X25519 ECDH auth, dynamic cert generation, spider fallback. Compatible with xray-core clients (Chrome fingerprint + Ed25519 certs).
- **XTLS Vision** (`xtls-rprx-vision`) — traffic analysis resistance via padding/unpadding
- **TLS 1.3 record disguise** — AEAD-encrypted transport that appears as TLS 1.3 application data
- **AEAD ciphers** — AES-256-GCM and ChaCha20-Poly1305 with BLAKE3 key derivation
- **NIST ML-KEM-512** — post-quantum session key establishment (FIPS 203)
- **Protobuf addons** — extensible handshake metadata (flow, Kyber ciphertext)

## Quick Start

### Build

```bash
cargo build --release
```

### Configure

Create `config.toml`:

```toml
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"
flow = "xtls-rprx-vision"

# Optional: ML-KEM-512 secret key (64-byte hex) for post-quantum sessions
# kyber_secret_key = "a1b2c3d4..."
```

### Run

```bash
# With a config file
cargo run --release -- --config config.toml

# Zero-config mode (compile-time defaults from build.rs)
cargo run --release
```

The binary embeds compile-time defaults (random UUID, port, X25519 keypair, Kyber keypair)
via `build.rs`. Running without `--config` uses these defaults so no prior setup is needed.

### Client config generation

The server can generate a v2rayN/v2rayNG-compatible client config JSON:

```bash
# Print to stdout
cargo run --release -- --print-client-config --server-host YOUR_IP --servername YOUR_SNI

# Write to file
cargo run --release -- --write-client-config client.json --server-host YOUR_IP --servername YOUR_SNI
```

## Testing

```bash
cargo test                                  # all unit + integration + vision tests
cargo test --test integration               # integration tests (62 tests, incl. REALITY, cross-compat, randomized)
cargo test --test vision_relay_tests        # Vision relay tests (25 tests: HTTP, TLS-in-TLS, UDP, concurrency, stress)
cargo bench                                 # criterion benchmarks
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
| `users[].udp` | bool | Enable UDP-over-TCP relay (default: `true`) |
| `users[].encryption` | string | Per-user encryption key (not yet wired) |
| `decryption` | string | Server-wide decryption key (not yet wired) |
| `flow` | string | Default flow for all users |
| `kyber_secret_key` | string | ML-KEM-512 64-byte seed (hex-encoded) |
| `reality.private_key` | string | X25519 32-byte private key (hex-encoded) |
| `reality.short_ids` | []string | Allowed short IDs (8-byte hex strings) |
| `reality.max_time_diff` | int | Max clock skew in seconds (default 300) |
| `reality.dest` | string | Spider fallback target (e.g. `"www.microsoft.com:443"`) |

## Security

- **Encryption in transit**: AEAD with TLS 1.3 record disguise prevents DPI-based protocol identification
- **Post-quantum KEM**: ML-KEM-512 (NIST FIPS 203) for forward-secure session keys resistant to quantum attacks
- **Traffic analysis resistance**: XTLS Vision padding eliminates length-based fingerprinting
- **No pre-shared keys required**: Kyber key exchange establishes session keys without prior key distribution

## Verified Interop

- **xray-core 26.5.9+** — REALITY handshake completes with `uConn.Verified: true`. Ed25519 cert verification succeeds even with Chrome fingerprint (no Ed25519 in `signature_algorithms`).
- **Spider fallback** — unauthenticated probes are transparently forwarded to the configured `dest` target. Confirmed with `curl` -> `www.microsoft.com:443` (Microsoft's real TLS 1.3 cert returned).
- **Concurrent connections** — 6+ simultaneous REALITY connections all authenticate and relay correctly.
- **REALITY + Vision** — full XTLS Vision padding/unpadding now works over REALITY TLS connections. Large payloads (128KB), HTTP/1.0, HTTP/1.1 keep-alive, TLS-in-TLS passthrough, UDP, chunked writes, and sustained bidirectional traffic all verified via integration tests.

## Known Limitations

- **UDP + Vision**: XTLS Vision does not support UDP relay (same limitation as xray-core). UDP connections use raw length-prefixed framing.
- **REALITY UDP relay**: UDP over REALITY TLS uses a polling loop; throughput is lower than native UDP relay.

## License

MIT
