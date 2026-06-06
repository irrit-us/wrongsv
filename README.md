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
  <img src="https://img.shields.io/badge/TLS-Plain%201.3-8787af?style=for-the-badge" alt="TLS: Plain 1.3">
  <img src="https://img.shields.io/badge/protocol-Shadowsocks%20AEAD-2b8a3e?style=for-the-badge" alt="Protocol: Shadowsocks AEAD">
  <img src="https://img.shields.io/badge/protocol-SOCKS5%20%2B%20HTTP%20CONNECT-4f6f9f?style=for-the-badge" alt="Protocol: SOCKS5 and HTTP CONNECT">
  <img src="https://img.shields.io/badge/KEM-ML--KEM--512-darkslateblue?style=for-the-badge" alt="KEM: ML-KEM-512">
</p>

---

A minimal, high-performance proxy server with VLESS, XTLS Vision flow, REALITY / AnyTLS / plain TLS transport layers, Shadowsocks AEAD TCP inbound, mixed SOCKS5/HTTP CONNECT inbound, and NIST ML-KEM post-quantum key encapsulation.

## Architecture

```
wrongsv (binary)
├── server          — inbound handler, config, connection relay
├── reality         — REALITY TLS 1.3 authentication with spider fallback
├── anytls          — AnyTLS TLS disguise with SHA-256 password auth + fallback
├── shadowsocks     — Shadowsocks AEAD TCP codec and relay
├── mixed proxy     — SOCKS5 CONNECT and HTTP CONNECT inbound relay
├── vless           — user validator, XTLS Vision padding/unpadding
├── vless-encoding  — VLESS header codec, addons protobuf, body framing
├── encryption      — AEAD (AES-256-GCM / ChaCha20-Poly1305)
├── kyber           — NIST ML-KEM-512 post-quantum key encapsulation
├── protocol        — shared types (RequestHeader, MemoryUser, ID, AddressParser)
├── net-types       — Address, Port, AddressFamily
└── uuid            — UUID v4/v5, ProcessUUID masking
```

## Features

- **VLESS** — stateless proxy with UUID authentication and extensible addons
- **Shadowsocks AEAD TCP** — `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`
- **Mixed proxy inbound** — SOCKS5 CONNECT and HTTP CONNECT, optional shared credentials
- **REALITY** — TLS 1.3 handshake hijacking, X25519 ECDH auth, dynamic certs, spider fallback
- **AnyTLS** — TLS 1.3 + SHA-256 password auth with configurable padding
- **Plain TLS** — Standard TLS 1.3, compatible with sing-box/mihomo/xray-core `tls` transport
- **XTLS Vision** — traffic analysis resistance via padding/unpadding
- **ML-KEM-512** — NIST FIPS 203 post-quantum key encapsulation
- **Probe resistance** — unauthenticated connections forwarded to fallback destinations
- **Client config generation** — auto-generate config JSON for sing-box and mihomo/FlClash

## Quick Start

[docs/SETUP.md](docs/SETUP.md) has the full build and configuration guide.
[docs/simple-deploy.md](docs/simple-deploy.md) has step-by-step TLS and REALITY deployment walkthroughs.

### Build

```bash
cargo build --release
```

### Configure

Pick an example from [`configs/`](configs/):

| Config | Transport | Flow | Notes |
|--------|-----------|------|-------|
| [`tls-vision.toml`](configs/tls-vision.toml) | Plain TLS | Vision | Recommended — TLS + DPI resistant |
| [`reality-vision.toml`](configs/reality-vision.toml) | REALITY TLS | Vision | ECDH auth + spider fallback |
| [`anytls-vision.toml`](configs/anytls-vision.toml) | AnyTLS | Vision | Password auth |
| [`tls-tcp.toml`](configs/tls-tcp.toml) | Plain TLS | none | TLS encryption, no Vision |
| [`basic-tcp.toml`](configs/basic-tcp.toml) | raw TCP | none | Simplest setup |
| [`kyber-vision.toml`](configs/kyber-vision.toml) | raw TCP | Vision | Post-quantum KEM |
| [`shadowsocks-aead.toml`](configs/shadowsocks-aead.toml) | Shadowsocks AEAD | n/a | TCP relay for Shadowsocks-compatible clients |
| [`mixed-proxy.toml`](configs/mixed-proxy.toml) | SOCKS5 / HTTP CONNECT | n/a | Local/LAN mixed proxy inbound |

Or create a minimal config:

```toml
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"
flow = "xtls-rprx-vision"
```

### Run

```bash
./target/release/wrongsv --config config.toml
```

### Generate client config

```bash
# sing-box format
./target/release/wrongsv --config config.toml --print-client-config \
  --server-host YOUR_IP --servername cloudfront.net --format sing-box

# mihomo/FlClash format
./target/release/wrongsv --config config.toml --print-client-config \
  --server-host YOUR_IP --servername cloudfront.net
```

See [docs/SETUP.md](docs/SETUP.md) for all transport options, REALITY keypair
generation, AnyTLS padding configuration, and Kyber setup.

## Testing

```bash
cargo test                      # all unit + integration tests
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

See [docs/TESTING.md](docs/TESTING.md) for the complete test suite including
lifecycle tests (sing-box, mihomo, xray-core), stress tests, benchmarks, and
manual proxy testing procedures.

## Interop

- **xray-core 26.5.9+** — REALITY handshake, Ed25519 certs, Chrome fingerprint
- **sing-box** — REALITY+Vision and TLS+uTLS lifecycle tests passing
- **mihomo / FlClash** — REALITY+Vision and TLS+uTLS full proxy cycle verified
- **REALITY spider fallback** — unauthenticated probes forwarded to `dest`
- **AnyTLS echo, Vision, UDP, fallback** — all verified end-to-end
- **Shadowsocks AEAD TCP** — local echo relay coverage for `chacha20-ietf-poly1305`; codec unit coverage for AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305
- **Mixed SOCKS5/HTTP CONNECT** — no-auth and authenticated end-to-end echo coverage
- **Concurrent connections** — 6+ simultaneous REALITY connections, 30 rapid-fire requests, 5×1MB concurrent downloads

## License

MIT
