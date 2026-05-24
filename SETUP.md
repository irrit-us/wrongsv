# SETUP.md — wrongsv build and configuration guide

## Prerequisites

- Rust toolchain (stable, edition 2024)
- `protoc` (protobuf compiler) — required by `prost` for addons proto generation

Install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install protoc:

```bash
# Fedora
sudo dnf install protobuf-compiler

# Ubuntu/Debian
sudo apt install protobuf-compiler

# macOS
brew install protobuf
```

## Build

```bash
# Debug build
cargo build

# Release build (LTO, single codegen unit, opt-level 3)
cargo build --release
```

The release profile enables LTO and maximum optimization. The binary will be at `target/release/wrongsv`.

## Configuration

The server reads a TOML config file. A minimal config:

```toml
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"
flow = "xtls-rprx-vision"
```

### User UUIDs

UUIDs can be provided as standard hex format (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) or as short names. Short names (< 32 hex chars) are hashed via SHA-1 to produce a v5-style UUID.

### Flow modes

| Flow | Description |
|------|-------------|
| `""` (empty) | Raw passthrough, no padding |
| `"xtls-rprx-vision"` | XTLS Vision padding for traffic analysis resistance |

### Post-quantum key exchange (ML-KEM-512)

To enable Kyber-encrypted sessions, generate a keypair and configure the secret key:

```bash
# Generate a keypair (you'd do this programmatically or via a helper)
# The secret key seed is 64 bytes, hex-encoded
```

Add to config:

```toml
kyber_secret_key = "a1b2c3d4e5f6..."  # 64-byte hex (128 hex chars)
```

The server will decapsulate Kyber ciphertexts sent by clients in the VLESS addons field and derive session keys from the shared secret.

### Full config reference

```toml
# Required: listen address
listen = "0.0.0.0:443"

# Optional: default flow for all users (overridden by per-user flow)
flow = "xtls-rprx-vision"

# Optional: server-wide decryption key (not yet wired into relay path)
decryption = "..."

# Optional: ML-KEM-512 secret key seed (64 bytes, hex-encoded)
kyber_secret_key = "..."

# User definitions
[[users]]
id = "uuid-here"
email = "user@example.com"     # optional
flow = ""                      # optional, inherits from global if empty
encryption = ""                # optional, per-user encryption key (not yet wired)
```

## Running the Server

```bash
# With config file
cargo run --release -- --config config.toml

# Zero-config mode (compile-time defaults from build.rs:
# random UUID, port, X25519 keypair, Kyber keypair)
cargo run --release

# The binary directly
./target/release/wrongsv --config config.toml
```

Log level is controlled via `RUST_LOG` environment variable:

```bash
RUST_LOG=debug ./target/release/wrongsv --config config.toml
```

### Client config generation

The server can generate a v2rayN/v2rayNG-compatible client config JSON:

```bash
# Print to stdout
./target/release/wrongsv --print-client-config --server-host YOUR_IP --servername YOUR_SNI

# Write to file, specifying a custom label
./target/release/wrongsv --write-client-config client.json \
    --server-host YOUR_IP --servername example.com --client-name "my-server"
```

This uses the same compile-time UUID, port, X25519 public key, short-id, and Kyber
public key that `build.rs` embeds into the binary.

## Testing

```bash
# All tests across workspace
cargo test

# Specific crate
cargo test -p wrongsv-kyber
cargo test -p wrongsv-vless
cargo test -p wrongsv-server

# Integration tests (spawn real server + echo target, 16 tests)
cargo test --test integration

# With output
cargo test --test integration -- --nocapture

# Memory stress test
cargo run --example stress
```

## Benchmarks

```bash
cargo bench
```

Benchmarks cover:
- Request header encoding/decoding throughput
- XTLS Vision padding/unpadding for 1460-byte MTU payloads

## Project Structure

```
wrongsv/
├── Cargo.toml              # workspace root
├── build.rs                # compile-time key generation (UUID, X25519, Kyber)
├── src/
│   └── main.rs             # CLI binary, client config generation
├── benches/
│   └── throughput.rs       # criterion benchmarks
├── examples/
│   └── stress.rs           # memory stress test (RSS monitoring)
├── tests/
│   └── integration.rs      # end-to-end integration tests (16 tests)
└── crates/
    ├── uuid/               # UUID v4/v5, ProcessUUID
    ├── net-types/          # Address, Port, AddressFamily
    ├── protocol/           # RequestHeader, MemoryUser, ID, AddressParser
    ├── vless-encoding/     # VLESS header codec, addons proto, body framing
    ├── vless/              # Validator trait, MemoryValidator, XTLS Vision
    ├── encryption/         # AEAD ciphers, TLS 1.3 record disguise
    ├── kyber/              # NIST ML-KEM-512 KEM
    └── server/             # InboundServer, config, connection handler
```

## Troubleshooting

**"protoc not found"**: Install protobuf-compiler (see Prerequisites above).

**"connection refused"**: Ensure the listen address is not already bound. Check `ss -tlnp`.

**"invalid UUID"**: UUID must be 36-character hex format (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) or a short name that can be SHA-1 hashed.

**"unknown flow"**: Flow must be either `""` or `"xtls-rprx-vision"`.

**Kyber decapsulation fails**: Ensure the server's `kyber_secret_key` matches the public key used by the client to encapsulate. The seed must be exactly 64 bytes (128 hex chars).
