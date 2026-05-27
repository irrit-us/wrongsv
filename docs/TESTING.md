# TESTING.md — wrongsv test procedures

## Quick suite

```bash
cargo test                                    # all unit + integration + vision + anytls
cargo clippy --workspace --all-targets        # lint all targets
cargo fmt --all -- --check                    # verify formatting
```

## Unit tests (per crate)

```bash
cargo test -p wrongsv-reality
cargo test -p wrongsv-anytls
cargo test -p wrongsv-kyber
cargo test -p wrongsv-vless
cargo test -p wrongsv-vless-encoding
cargo test -p wrongsv-encryption
cargo test -p wrongsv-protocol
cargo test -p wrongsv-uuid
cargo test -p wrongsv-net-types
cargo test -p wrongsv-server
```

## Integration tests

```bash
# REALITY handshake + spider fallback + cross-compatibility + randomized payloads
cargo test --test integration

# With output
cargo test --test integration -- --nocapture

# Run a specific test
cargo test --test integration test_reality_echo -- --nocapture
```

## Vision relay tests

```bash
cargo test --test vision_relay_tests

# Covers: HTTP relay, TLS-in-TLS, UDP relay, concurrent connections,
# padding/unpadding correctness, payload sizes (14B / 4KB / 16KB)
```

## AnyTLS tests

```bash
cargo test --test anytls_tests

# Covers: basic echo, Vision relay, 4KB/16KB payloads, UDP relay,
# auth failure (with/without fallback), custom TLS certs, padding
# schemes, multi-user, concurrent connections, Kyber + AnyTLS combo
```

## Lifecycle tests (external clients)

These tests spawn the wrongsv server and connect through real client binaries
(sing-box, mihomo/Meta, xray-core), performing full REALITY+VLESS proxy cycles.

### Prerequisites

Set environment variables pointing to client binaries:

```bash
export SINGBOX_BIN=/path/to/sing-box
export MIHOMO_BIN=/path/to/mihomo
export XRAY_BIN=/path/to/xray
```

### Running

Lifecycle tests must be run with `--test-threads=1` to avoid port conflicts:

```bash
# sing-box (6 tests)
cargo test --test singbox_lifecycle -- --test-threads=1

# mihomo/ClashMeta (6 tests)
cargo test --test mihomo_lifecycle -- --test-threads=1

# xray-core (6 tests)
cargo test --test xray_lifecycle -- --test-threads=1
```

### What each suite covers

| Test | Description |
|------|-------------|
| vision HTTP relay | REALITY handshake → VLESS → Vision → HTTP response |
| raw/no-flow relay | REALITY handshake → VLESS raw → HTTP response |
| multi-request | 5 sequential HTTP requests on single connection |
| multi-user | Two users, two connections, both authenticate correctly |
| restart | Server restart, client reconnects successfully |
| wrong credential rejection | Invalid UUID → connection rejected, no data leak |

## Stress test

```bash
cargo run --example stress
```

Runs 480 connections across 3 rounds and monitors RSS for memory leaks.

## Benchmarks

```bash
cargo bench
```

Criterion benchmarks covering request header encoding/decoding and XTLS Vision
padding/unpadding throughput.

## Manual proxy testing

When the server is deployed with a local sing-box (or mihomo/xray) SOCKS5
proxy at `127.0.0.1:10809`:

```bash
# Basic HTTP
curl -x socks5h://127.0.0.1:10809 -s -o /dev/null \
  -w "HTTP %{http_code} %{size_download}B %{time_total}s\n" \
  --connect-timeout 10 -m 30 "https://httpbin.org/get"

# Large download (throughput test)
curl -x socks5h://127.0.0.1:10809 -s -o /dev/null \
  -w "HTTP %{http_code} %{size_download}B %{time_total}s\n" \
  --connect-timeout 10 -m 120 \
  "http://ipv4.download.thinkbroadband.com/10MB.zip"

# Google search (complex page)
curl -x socks5h://127.0.0.1:10809 -s -o /dev/null \
  -w "HTTP %{http_code} %{size_download}B %{time_total}s\n" \
  --connect-timeout 10 -m 30 "https://www.google.com/search?q=test"

# GitHub API (JSON)
curl -x socks5h://127.0.0.1:10809 -s -o /dev/null \
  -w "HTTP %{http_code} %{size_download}B %{time_total}s\n" \
  --connect-timeout 10 -m 30 "https://api.github.com/repos/rust-lang/rust"

# Wikipedia (text-heavy)
curl -x socks5h://127.0.0.1:10809 -s -o /dev/null \
  -w "HTTP %{http_code} %{size_download}B %{time_total}s\n" \
  --connect-timeout 10 -m 30 "https://en.wikipedia.org/wiki/Network_proxy"
```

### Server log monitoring

```bash
ssh YOUR_SERVER journalctl -u wrongsv -f

# Expected: "TLS enabled", "TLS handshake complete",
# "TCP <email> -> <target>:<port>"
```

## Pre-commit checklist

Before submitting a PR, run the full verification pipeline:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test
cargo test --test integration
cargo test --test vision_relay_tests
cargo test --test anytls_tests
```

If lifecycle test binaries are available:

```bash
cargo test --test singbox_lifecycle -- --test-threads=1
cargo test --test mihomo_lifecycle -- --test-threads=1
cargo test --test xray_lifecycle -- --test-threads=1
```
