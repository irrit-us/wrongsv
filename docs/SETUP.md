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
| `tls-tcp.toml` | Plain TLS | none | TLS 1.3 encryption |
| `tls-vision.toml` | Plain TLS | Vision | TLS + Vision, DPI resistant |
| `reality-vision.toml` | REALITY TLS 1.3 | Vision | ECDH auth, spider fallback |
| `reality-udp.toml` | REALITY TLS 1.3 | none | With UDP relay |
| `anytls-vision.toml` | AnyTLS | Vision | Password auth via TLS |
| `anytls-tcp.toml` | AnyTLS | none | Password auth, raw relay |
| `anytls-udp.toml` | AnyTLS | none | Password auth + UDP |
| `anytls-fallback.toml` | AnyTLS | Vision | With fallback destination |
| `kyber-vision.toml` | raw TCP | Vision | Post-quantum key exchange |
| `anytls-custom.toml` | AnyTLS | Vision | Custom TLS cert + padding |
| `shadowsocks-aead.toml` | Shadowsocks AEAD | n/a | TCP/UDP relay |
| `shadowsocks-2022.toml` | Shadowsocks AEAD-2022 | n/a | TCP/UDP relay |
| `mixed-proxy.toml` | SOCKS4/4A, SOCKS5, HTTP | n/a | Local/LAN mixed proxy |
| `trojan-tls.toml` | Trojan over TLS | n/a | TCP/UDP relay with fallback |

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

**Note:** REALITY, AnyTLS, plain TLS, Shadowsocks, mixed proxy, and Trojan are mutually exclusive listener modes — configure one inbound mode per server process.

### Plain TLS configuration

Plain TLS provides standard TLS 1.3 encryption without password auth or ECDH key agreement. This is the simplest TLS option — compatible with sing-box, mihomo, and xray-core clients using `tls` transport (not REALITY).

Add a `[tls]` section:

```toml
[tls]
# All fields optional — auto-generated ECDSA P-256 cert if omitted
# certificate = """-----BEGIN CERTIFICATE-----..."""
# key = """-----BEGIN PRIVATE KEY-----..."""
# dest = "127.0.0.1:8080"
```

**Fields:**

| Field | Default | Description |
|-------|---------|-------------|
| `certificate` | auto-generated | TLS certificate PEM (ECDSA P-256, self-signed) |
| `key` | auto-generated | TLS key PEM |
| `dest` | none | Fallback target for probes |

**Client compatibility:** sing-box uses nested `tls.enabled`, `tls.server_name`, `tls.utls.fingerprint`. Mihomo/FlClash uses flat `tls: true`, `servername`, `client-fingerprint`. The `--print-client-config` command with `--format sing-box` or `--format mihomo` generates the appropriate format.

Use `--servername` to set the SNI (e.g., `cloudfront.net`) for DPI resistance. Enable uTLS Chrome fingerprint to mimic browser TLS behavior.

### Shadowsocks configuration

Shadowsocks provides a standalone AEAD inbound for clients compatible with Shadowsocks, Outline, GOST, sing-box, xray-core, and mihomo. Classic AEAD and AEAD-2022 methods support TCP/UDP.

```toml
[shadowsocks]
method = "chacha20-ietf-poly1305"           # aes-128-gcm, aes-256-gcm, or chacha20-ietf-poly1305
password = "your-secure-password"
udp = true                                  # default true
# tcp_prefix = "HTTP/1.1 "                  # optional Outline-style salt prefix
# udp_prefix = "k{\u0001 "                  # optional Outline-style salt prefix
```

AEAD-2022 uses fixed-length base64 pre-shared keys instead of password-derived keys:

```toml
[shadowsocks]
method = "2022-blake3-aes-128-gcm"          # or 2022-blake3-aes-256-gcm
password = "AAAAAAAAAAAAAAAAAAAAAA=="        # replace with openssl rand -base64 16
udp = true                                  # default true
```

### Mixed proxy configuration

Mixed proxy provides a plain local/LAN listener with SOCKS4/4A CONNECT, SOCKS5 CONNECT, HTTP absolute-form forwarding, and HTTP CONNECT.

```toml
[mixed]
# Optional shared credentials for SOCKS5 username/password and HTTP Basic.
# SOCKS4/4A has no password auth and is rejected when credentials are set.
# username = "admin"
# password = "your-secure-password"
```

### Trojan configuration

Trojan provides a standalone TLS listener with SHA224 password authentication, SOCKS5-style TCP CONNECT destination headers, and UDP ASSOCIATE packet relay.

```toml
[trojan]
password = "your-secure-password"
dest = "127.0.0.1:8080"                     # optional fallback for invalid post-TLS probes
# certificate = """-----BEGIN CERTIFICATE-----..."""
# key = """-----BEGIN PRIVATE KEY-----..."""

# Multi-user form:
# [[trojan.users]]
# password = "another-secure-password"
# email = "user@example.com"
```

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

# ── REALITY (mutually exclusive with other listener modes) ────────────────────
[reality]
private_key = "..."            # X25519 32-byte hex (64 chars)
short_ids = ["..."]            # allowed short IDs, 4-byte hex each (8 chars)
max_time_diff = 300            # max clock skew in seconds
dest = "host:port"             # spider fallback target

# ── AnyTLS (mutually exclusive with other listener modes) ─────────────────────
[anytls]
password = "..."               # SHA-256 auth password
dest = "host:port"             # fallback for failed auth
# certificate = """-----BEGIN CERTIFICATE-----..."""   # optional custom cert
# key = """-----BEGIN PRIVATE KEY-----..."""           # optional custom key
# padding_scheme = """stop=8                           # optional padding
# 0=30-30
# 1=100-400"""

# ── Plain TLS (mutually exclusive with other listener modes) ──────────────────
[tls]
# certificate = """-----BEGIN CERTIFICATE-----..."""   # optional custom cert
# key = """-----BEGIN PRIVATE KEY-----..."""           # optional custom key
# dest = "host:port"                                   # optional fallback

# ── Shadowsocks (instead of users/VLESS transports) ───────────────────────────
[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "..."
udp = true
# tcp_prefix = "HTTP/1.1 "
# udp_prefix = "k{\u0001 "

# ── Mixed proxy (instead of users/VLESS transports) ───────────────────────────
[mixed]
# username = "admin"
# password = "..."

# ── Trojan over TLS (instead of users/VLESS transports) ───────────────────────
[trojan]
password = "..."
dest = "host:port"
# certificate = """-----BEGIN CERTIFICATE-----..."""
# key = """-----BEGIN PRIVATE KEY-----..."""
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

Generate client config JSON in mihomo/FlClash format (default) or sing-box format:

```bash
# mihomo/FlClash format (flat keys: tls, client-fingerprint, servername)
./target/release/wrongsv --print-client-config \
    --server-host YOUR_SERVER_IP \
    --servername cloudfront.net

# sing-box format (nested tls object with utls/reality)
./target/release/wrongsv --print-client-config \
    --server-host YOUR_IP --servername cloudfront.net --format sing-box

# Write to file with custom label
./target/release/wrongsv --write-client-config client.json \
    --server-host YOUR_IP --servername cloudfront.net --client-name "my-server"

# Auto-detect transport type from TOML config
./target/release/wrongsv --config configs/tls-vision.toml \
    --print-client-config --server-host YOUR_IP --servername cloudfront.net

# Explicit transport override (reality, anytls, tls, raw)
./target/release/wrongsv --transport tls \
    --print-client-config --server-host YOUR_IP --servername cloudfront.net
```

Transport type is auto-detected from the TOML config file (reality → `reality-opts`, tls/anytls → `tls`, none → raw). Use `--transport` to override.

The generated JSON keys match Go struct tags in mihomo/sing-box (`client-fingerprint`, `public-key`, `short-id` in kebab-case). For REALITY transport, `reality-opts` block is included.

## Testing

See [docs/TESTING.md](TESTING.md) for the complete test suite — unit tests,
integration tests, lifecycle tests (sing-box, mihomo, xray-core), stress tests,
benchmarks, and manual proxy testing.

## Project Structure

```
wrongsv/
├── Cargo.toml                  # workspace root
├── build.rs                    # compile-time key generation (UUID, X25519, Kyber)
├── README.md                   # project overview, features, interop
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── docs/
│   ├── SETUP.md                # this file — build and config guide
│   ├── TESTING.md              # complete test suite reference
│   └── simple-deploy.md        # TLS/REALITY deployment walkthrough
├── configs/                    # ready-to-use TOML config examples
│   ├── basic-tcp.toml
│   ├── vision.toml
│   ├── tls-tcp.toml
│   ├── tls-vision.toml
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
│   ├── common/
│   │   └── mod.rs               # shared test helpers
│   ├── integration.rs           # end-to-end REALITY integration tests
│   ├── vision_relay_tests.rs    # XTLS Vision relay tests
│   ├── anytls_tests.rs          # AnyTLS protocol tests
│   ├── shadowsocks_tests.rs     # Shadowsocks AEAD/AEAD-2022 TCP/UDP tests
│   ├── mixed_proxy_tests.rs     # SOCKS4/4A, SOCKS5, HTTP proxy tests
│   ├── trojan_tests.rs          # Trojan TLS TCP tests
│   ├── singbox_lifecycle.rs     # sing-box REALITY+VLESS and Shadowsocks 2022 lifecycle
│   ├── mihomo_lifecycle.rs      # mihomo REALITY+VLESS and Shadowsocks 2022 lifecycle
│   └── xray_lifecycle.rs        # xray-core REALITY+VLESS and Shadowsocks 2022 lifecycle
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
    ├── shadowsocks/            # Shadowsocks AEAD/2022 codec and relay helpers
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

**"Trojan authentication failed"** — Wrong Trojan password. Invalid probes are forwarded to `trojan.dest` if configured.
