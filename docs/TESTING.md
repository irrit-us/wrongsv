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
cargo test -p wrongsv-shadowsocks
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

# Shadowsocks AEAD TCP relay
cargo test --test shadowsocks_tests
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

Lifecycle tests serialize real-client process startup internally and can be run
with the default Rust test runner:

```bash
# sing-box (6 tests)
cargo test --test singbox_lifecycle

# mihomo/ClashMeta (6 tests)
cargo test --test mihomo_lifecycle

# xray-core (6 tests)
cargo test --test xray_lifecycle
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

### Headless browser test

```bash
# Requires: google-chrome, websocket-client (pip install websocket-client)
# Default proxy: socks5://127.0.0.1:10809
./scripts/headless-gmail-test.py [proxy_host:port] [timeout_seconds]

# Custom proxy
./scripts/headless-gmail-test.py 127.0.0.1:7891 120
```

Screenshots saved to `$SCREENSHOT_DIR` (default `/tmp/wrongsv-headless-test`).

**Two-phase test:**

1. **Phase 1 (dump-dom)** — Launches headless Chrome through the SOCKS5 proxy.
   Loads httpbin.org/get (warm-up, proxy chain verification) then
   mail.google.com. Verifies:
   - httpbin: JSON markers (`"headers"`, `"url"`) in response
   - Gmail: `<title>Gmail</title>`, form `input` elements, page size >50KB
   - Screenshots captured at each stage (`.png`)

2. **Phase 2 (CDP)** — Connects via Chrome DevTools Protocol WebSocket for
   interaction: scroll, find clickable elements, text input, CDP screenshot.
   Falls back gracefully when CDP `Page.navigate` is unavailable (known
   Chrome+SOCKS5 limitation in headless mode — Phase 1 already validates
   the critical path).

**Expected output (all checks passing):**
```
[1/5] Phase 1: Loading pages via socks5://127.0.0.1:10809 ...
  OK httpbin warm-up: JSON response
  OK httpbin warm-up: url field
  OK httpbin warm-up: 1108B (9.7s)
  OK httpbin warm-up: screenshot (63KB)
  OK Gmail: page title
  OK Gmail: form elements
  OK Gmail: 840294B (56.1s)
  OK Gmail: screenshot (37KB)
[2/5] Phase 2: ...
  OK CDP connected
  OK Page load verified in Phase 1

Results: 10 ok, 0 failed
OVERALL: PASS
```

### AnyTLS client test

```bash
# Direct AnyTLS + VLESS test (no proxy needed)
# Default server: <YOUR_SERVER_IP>:443
./scripts/anytls-test.py [server_host] [port]
```

End-to-end verification of the AnyTLS protocol:
1. TCP connect → TLS 1.3 handshake (self-signed cert)
2. Send AnyTLS auth frame: `SHA256(password)[32B] || padding_len(0)[2B]`
3. Server verifies auth → connection stays alive
4. Send VLESS TCP header (httpbin.org:80) + HTTP request
5. Read VLESS response header + HTTP response from httpbin

**Expected output (all checks passing):**
```
=== AnyTLS client test ===
[1/5] TCP connect ... OK Connected (358ms)
[2/5] TLS handshake ... OK TLS handshake complete (411ms)
[3/5] Sending AnyTLS auth frame ... OK AnyTLS auth accepted
[4/5] Sending VLESS header + HTTP request ... OK
[5/5] Reading response ...
  OK VLESS response: version=0, addons_len=0
  OK Response: 423B (1.7s)
  OK Got valid HTTP response through AnyTLS + VLESS
OVERALL: PASS — AnyTLS auth + VLESS relay works
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
