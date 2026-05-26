# SETUP.md — wrongsv build and configuration guide

[README](README.md) has the project overview and feature list.

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

# Release build (LTO, single codegen unit, opt-level 3, panic=abort)
cargo build --release
```

The release binary is at `target/release/wrongsv`.

## Configuration

The server reads a TOML config file passed via `--config`. Pre-built examples are in the [`configs/`](configs/) directory.

### Quick config table

| File | Transport | Flow | Key features |
|------|-----------|------|-------------|
| `basic-tcp.toml` | raw TCP | none | Minimal setup |
| `vision.toml` | raw TCP | Vision | Traffic analysis resistance |
| `reality-vision.toml` | REALITY TLS 1.3 | Vision | ECDH auth, spider fallback |
| `reality-udp.toml` | REALITY TLS 1.3 | none | With UDP relay |
| `anytls-vision.toml` | AnyTLS | Vision | Password auth via TLS |
| `anytls-tcp.toml` | AnyTLS | none | Password auth, raw relay |
| `anytls-udp.toml` | AnyTLS | none | Password auth + UDP |
| `anytls-fallback.toml` | AnyTLS | Vision | With fallback destination |
| `kyber-vision.toml` | raw TCP | Vision | Post-quantum key exchange |
| `anytls-custom.toml` | AnyTLS | Vision | Custom TLS cert + padding |

### Minimal config

```toml
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"
flow = "xtls-rprx-vision"
```

### Users and UUIDs

UUIDs can be standard hex format (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) or short names. Short names (< 32 hex chars) are SHA-1 hashed to produce a v5-style UUID.

Each user supports:
| Field | Default | Description |
|-------|---------|-------------|
| `id` | required | UUID in hex or short-name format |
| `email` | `""` | Optional label for logging |
| `flow` | `""` | `""` (raw) or `"xtls-rprx-vision"` |
| `udp` | `true` | Enable UDP-over-TCP relay |
| `encryption` | `""` | Per-user encryption key |

### Flow modes

| Flow | Description |
|------|-------------|
| `""` (empty) | Raw TCP passthrough, no padding |
| `"xtls-rprx-vision"` | XTLS Vision padding/unpadding for traffic analysis resistance |

### REALITY configuration

REALITY provides TLS 1.3 authentication via X25519 ECDH without a pre-shared certificate chain. The server generates an Ed25519 certificate on-the-fly for each authenticated connection. Unauthenticated probes are forwarded to a fallback destination (spider mode).

Add a `[reality]` section:

```toml
[reality]
private_key = "d75c6e2f7e8a1b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4"
short_ids = ["aaaaaaaa"]
max_time_diff = 300                         # max clock skew, default 300s
dest = "www.microsoft.com:443"              # spider fallback target
```

**Fields:**

| Field | Default | Description |
|-------|---------|-------------|
| `private_key` | required | X25519 32-byte private key (hex-encoded, 64 chars) |
| `short_ids` | required | Allowed short IDs (4-byte hex, 8 chars each) |
| `max_time_diff` | `300` | Max allowed clock skew between client and server (seconds) |
| `dest` | none | Fallback target for unauthenticated probes (`"host:port"`) |

**Generating REALITY keys:**

```bash
# The build.rs generates an X25519 keypair at compile time.
# To generate your own:
openssl rand -hex 32  # private key (use this in config)
# The corresponding public key is embedded in the client config
# via --print-client-config / --write-client-config.
```

### AnyTLS configuration

AnyTLS provides TLS 1.3 disguise with SHA-256 password authentication. It uses a standard TLS handshake (no ClientHello interception) with an additional password verification step as the first application-data frame. This is simpler than REALITY and doesn't require key distribution — the client only needs the password.

Add an `[anytls]` section:

```toml
[anytls]
password = "your-secure-password"
dest = "127.0.0.1:8080"                     # optional fallback for failed auth
```

**Fields:**

| Field | Default | Description |
|-------|---------|-------------|
| `password` | required | Password for SHA-256 auth |
| `dest` | none | Fallback target for unauthenticated probes |
| `certificate` | auto-generated | TLS certificate PEM (self-signed if omitted) |
| `key` | auto-generated | TLS key PEM |
| `padding_scheme` | none | Padding pattern (anytls-go format: `stop=N`, stage rules) |

**Authentication protocol:**

After the TLS 1.3 handshake completes, the client sends:
```
SHA256(password)[32 bytes] || padding_len(u16 BE)[2 bytes] || random_padding[N bytes]
```

If the hash matches, the connection proceeds to VLESS relay. Otherwise it is forwarded to the fallback destination (if configured) or closed.

**Note:** REALITY and AnyTLS are mutually exclusive — configure one, not both.

### Post-quantum key exchange (ML-KEM-512)

Add a Kyber secret key to enable post-quantum session establishment:

```toml
kyber_secret_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
```

The 64-byte seed must be hex-encoded (128 hex chars). The server decapsulates Kyber ciphertexts from the VLESS addons field and derives session keys from the shared secret.

**Generating a Kyber keypair:**

```bash
# The build.rs generates a Kyber keypair at compile time.
# To generate your own, use the ml-kem crate or:
openssl rand -hex 64  # 64-byte seed (128 hex chars)
```

### Full config reference

```toml
# ── Required ──────────────────────────────────────────────────────────────────
listen = "0.0.0.0:443"

# ── Users ─────────────────────────────────────────────────────────────────────
[[users]]
id = "uuid-here"
email = "user@example.com"     # optional
flow = "xtls-rprx-vision"      # optional, inherits from global flow
encryption = ""                # optional
udp = true                     # optional, enable UDP relay (default: true)

# ── Optional globals ──────────────────────────────────────────────────────────
flow = "xtls-rprx-vision"      # default flow for users who don't specify one
kyber_secret_key = "..."       # ML-KEM-512 64-byte seed, hex-encoded (128 chars)

# ── REALITY (mutually exclusive with AnyTLS) ──────────────────────────────────
[reality]
private_key = "..."            # X25519 32-byte hex (64 chars)
short_ids = ["..."]            # allowed short IDs, 4-byte hex each (8 chars)
max_time_diff = 300            # max clock skew in seconds
dest = "host:port"             # spider fallback target

# ── AnyTLS (mutually exclusive with REALITY) ──────────────────────────────────
[anytls]
password = "..."               # SHA-256 auth password
dest = "host:port"             # fallback for failed auth
# certificate = """-----BEGIN CERTIFICATE-----..."""   # optional custom cert
# key = """-----BEGIN PRIVATE KEY-----..."""           # optional custom key
# padding_scheme = """stop=8                           # optional padding
# 0=30-30
# 1=100-400"""
```

## Running the Server

```bash
# With a config file
cargo run --release -- --config config.toml

# Zero-config mode (compile-time defaults: random UUID, port, keypairs)
cargo run --release

# Using the binary directly
./target/release/wrongsv --config config.toml
```

Log level via `RUST_LOG`:

```bash
RUST_LOG=debug ./target/release/wrongsv --config config.toml
RUST_LOG=trace ./target/release/wrongsv --config config.toml   # very verbose
```

### Client config generation

Generate v2rayN/v2rayNG-compatible client JSON:

```bash
# Print to stdout
./target/release/wrongsv --print-client-config \
    --server-host YOUR_SERVER_IP \
    --servername YOUR_SNI

# Write to file with custom label
./target/release/wrongsv --write-client-config client.json \
    --server-host YOUR_IP --servername example.com --client-name "my-server"
```

The generated JSON includes REALITY options (publicKey, shortId) when REALITY is configured, derived from the config or compile-time build.rs defaults.

## Testing

```bash
# All tests across workspace
cargo test

# Specific crates
cargo test -p wrongsv-reality
cargo test -p wrongsv-anytls
cargo test -p wrongsv-kyber
cargo test -p wrongsv-vless

# Integration tests
cargo test --test integration          # REALITY, cross-compat, randomized
cargo test --test vision_relay_tests   # Vision relay (HTTP, TLS-in-TLS, UDP, concurrency)
cargo test --test anytls_tests         # AnyTLS (echo, Vision, fallback, UDP)

# With output
cargo test --test integration -- --nocapture

# Memory stress test (480 connections × 3 rounds)
cargo run --example stress
```

## Benchmarks

```bash
cargo bench
```

Covers request header encoding/decoding and XTLS Vision padding/unpadding throughput.

## Project Structure

```
wrongsv/
├── Cargo.toml                  # workspace root
├── build.rs                    # compile-time key generation (UUID, X25519, Kyber)
├── README.md                   # project overview, features, interop
├── SETUP.md                    # this file — build and config guide
├── configs/                    # ready-to-use TOML config examples
│   ├── basic-tcp.toml
│   ├── vision.toml
│   ├── kyber-vision.toml
│   ├── reality-vision.toml
│   ├── reality-udp.toml
│   ├── anytls-vision.toml
│   ├── anytls-tcp.toml
│   ├── anytls-udp.toml
│   ├── anytls-fallback.toml
│   └── anytls-custom.toml
├── src/
│   └── main.rs                 # CLI binary, client config generation
├── benches/
│   └── throughput.rs           # criterion benchmarks
├── examples/
│   └── stress.rs               # memory stress test (RSS monitoring)
├── tests/
│   ├── integration.rs          # end-to-end REALITY integration tests
│   ├── vision_relay_tests.rs   # XTLS Vision relay tests
│   └── anytls_tests.rs         # AnyTLS protocol tests
└── crates/
    ├── uuid/                   # UUID v4/v5, ProcessUUID
    ├── net-types/              # Address, Port, AddressFamily
    ├── protocol/               # RequestHeader, MemoryUser, ID, AddressParser
    ├── vless-encoding/         # VLESS header codec, addons proto, body framing
    ├── vless/                  # Validator trait, MemoryValidator, XTLS Vision
    ├── encryption/             # AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305)
    ├── kyber/                  # NIST ML-KEM-512 KEM
    ├── reality/                # REALITY TLS auth, dynamic cert, spider fallback
    ├── anytls/                 # AnyTLS TLS disguise, password auth, fallback
    └── server/                 # InboundServer, config, connection handler
```

## Troubleshooting

**"protoc not found"** — Install protobuf-compiler (see Prerequisites).

**"connection refused"** — Port already bound. Check `ss -tlnp`.

**"invalid UUID"** — UUID must be 36-char hex (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) or a short name that can be SHA-1 hashed.

**"unknown flow"** — Flow must be `""` or `"xtls-rprx-vision"`.

**Kyber decapsulation fails** — The `kyber_secret_key` seed must be exactly 64 bytes (128 hex chars) and must match the public key the client used for encapsulation.

**AnyTLS auth failure (client side)** — The password hash sent by the client must match the server's `anytls.password`. Check that the client is sending `SHA256(password)` as the first 32 bytes of application data.

**"TLS handshake failed"** — For REALITY, ensure the `private_key` is 32 bytes hex-encoded (64 chars). For AnyTLS, check that the TLS certificate is valid PEM if a custom one is provided.

**"auth failed" (AnyTLS)** — Wrong password. Probes are forwarded to `anytls.dest` if configured.
