# wrongsv — VLESS proxy server in Rust

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
- **REALITY** — TLS 1.3 handshake hijacking with X25519 ECDH auth, dynamic cert generation, spider fallback
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
cargo test                          # all unit + integration tests
cargo test --test integration       # integration tests only (62 tests, incl. 114 randomized scenarios)
cargo bench                         # criterion benchmarks
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

## License

MIT
