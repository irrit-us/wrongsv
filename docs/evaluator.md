# Evaluator

Automated proxy evaluation across all 17 wrongsv protocols. One server, one
client — spawns proxy instances and echo/bandwidth/packet-loss targets, measures
latency, throughput, and loss per protocol.

## Quick Start

```bash
# Terminal 1 — start the server (defaults to 0.0.0.0:19999)
eval-server

# Terminal 2 — run all protocols
eval-client --server 127.0.0.1:19999
```

That's it. The client connects, authenticates, and iterates through every
protocol. Output:

```
testing protocol: reality (proxy=40000, echo=38849, bw=39437, pl=44100)
  lat=435.26ms avg, bw=0.79/0.00 Mbps up/dn, loss=0.00%
testing protocol: tls (proxy=40000, echo=45253, bw=39159, pl=41424)
  lat=675.19ms avg, bw=2.53/1.66 Mbps up/dn, loss=0.00%
...
```

## CLI Reference

### eval-server

```
eval-server [OPTIONS]
```

| Flag | Default | Purpose |
|------|---------|---------|
| `--listen` | `0.0.0.0:19999` | Control channel bind address |
| `--token` | `eval-token` | Shared auth token |
| `--duration` | `3` | Test duration per protocol (seconds) |
| `--protocols` | all 17 | Comma-separated subset (e.g. `kcp,raw,tls`) |
| `--stack` | — | Comma-separated stacks (e.g. `tier1,tier2`) or `all` |
| `--fixed-proxy-port` | random | Pin proxy to a specific port |
| `--proxy-bind` | `127.0.0.1` | Proxy bind address |

### eval-client

```
eval-client [OPTIONS]
```

| Flag | Default | Purpose |
|------|---------|---------|
| `--server` | `127.0.0.1:19999` | Control channel address |
| `--token` | `eval-token` | Shared auth token |
| `--duration` | `3` | Test duration per protocol (seconds) |

## What Gets Measured

Each protocol runs three tests through the proxy:

| Test | Method | Metric |
|------|--------|--------|
| Latency | 21 timestamped pings → echo target | min, max, avg, p50, p95, p99 |
| Bandwidth | Upload (5s) + Download (5s) → bw target | Mbps both directions |
| Packet Loss | 100 numbered packets → pl target → count gaps | % loss |

## Remote Testing

To test through real network paths, run the server on a remote host and connect
directly (no SSH tunnel for data — TCP-over-TCP collapse at high RTT causes
100% loss on TLS protocols).

### Server (remote host)

```bash
eval-server --listen 0.0.0.0:19999 --proxy-bind 0.0.0.0
```

### Client (local machine)

```bash
eval-client --server <remote-ip>:19999
```

### High-RTT Tuning

For paths over 200ms RTT, the client uses WouldBlock-tolerant reads
(600 retries × 5ms = ~3s budget). These timeouts are tuned for such paths:

| Transport | Setting | Default | Remote Value |
|-----------|---------|---------|-------------|
| kcp | UDP read timeout | 10ms | 200ms |
| kcp | poll iterations | 50 | 200 |
| shadowtls | TLS reader timeout | 50ms | 500ms |

## Protocol Matrix

All 17 protocols at 0% loss locally. 14/17 tested remotely via direct connection
(13 at 0% loss, 3 UDP blocked by firewall).

| Protocol | Local | Remote | Loss | Notes |
|----------|-------|--------|------|-------|
| reality | 0% | 600ms | 0% | GFW bypass OK |
| anytls | 0% | 683ms | 0% | |
| tls | 0% | 512ms | 0% | |
| raw | 0% | 901ms | 0% | baseline |
| ws | 0% | 1600ms | 0% | WS overhead visible at high RTT |
| ws+tls | 0% | 1315ms | 0% | |
| httpupgrade | 0% | 609ms | 0% | |
| httpupgrade+tls | 0% | 799ms | 0% | |
| grpc | 0% | 558ms | 0% | upload inflated*, download ~0* |
| grpc+tls | 0% | 542ms | 0% | |
| xhttp | 0% | 583ms | 0% | upload inflated*, download ~0* |
| xhttp+tls | 0% | 520ms | 0% | |
| shadowtls | 0% | 957ms | 0% | |
| vmess | 0% | 1389ms | 12.5% | ⚠️ suspected GFW interference |
| quic | 0% | — | 100% | ❌ UDP port blocked by firewall |
| kcp | 0% | — | 100% | ❌ UDP port blocked by firewall |
| webtransport | 0% | — | hung | ❌ TCP handshake OK, UDP data blocked |

\* Known artifact: h2 internal buffering. Not a protocol bug.

## Protocol Stacks

The evaluator supports named protocol stacks — groupings that represent
real-world deployment recommendations. Use `--stack all` to test every stack,
or `--stack tier1,tier2` for specific tiers.

A stack **passes** only if every protocol in it achieves 0% packet loss.

```
$ eval-server --stack all
$ eval-client
...
======================================================================
Stack Results
----------------------------------------------------------------------
  tier1            PASS  VLESS + REALITY + XTLS-Vision (TCP/443)
  tier2            PASS  REALITY + Hysteria2 dual-stack (TCP+UDP/443)
  tier3            PASS  VLESS + WebSocket + TLS (TCP/443 via CDN)
  tier4            PASS  VLESS + ShadowTLS v3 (TCP/443)
  post-quantum     PASS  VLESS + REALITY + Vision + ML-KEM-512
  legacy           PASS  VMess AEAD — legacy client compatibility
======================================================================
```

### Stack Definitions

| Stack | Protocols | Description |
|-------|-----------|-------------|
| `tier1` | reality | VLESS + REALITY + XTLS-Vision (TCP/443) — maximum stealth |
| `tier2` | reality | REALITY + Hysteria2 dual-stack (TCP+UDP/443). Hysteria2 runs as a separate server instance and is not tested via the VLESS evaluator path. |
| `tier3` | ws+tls | VLESS + WebSocket + TLS (TCP/443 via CDN) — CDN-friendly |
| `tier4` | shadowtls | VLESS + ShadowTLS v3 (TCP/443) — TLS mimicry, no pre-shared keys |
| `post-quantum` | reality | VLESS + REALITY + Vision + ML-KEM-512 |
| `legacy` | vmess | VMess AEAD — legacy client compatibility |

### Local Stack Results (2026-06-11)

All 6 stacks pass locally at 0% loss (3-second tests):

| Stack | Protocols Tested | Loss | Latency (avg) |
|-------|-----------------|------|---------------|
| tier1 | reality | 0% | 16.05ms |
| tier2 | reality | 0% | 16.05ms |
| tier3 | ws+tls | 0% | 41.20ms |
| tier4 | shadowtls | 0% | 511.72ms |
| post-quantum | reality | 0% | 16.05ms |
| legacy | vmess | 0% | 82.25ms |

### Remote Stack Results (2026-06-11, ~600ms RTT path)

5/6 stacks pass. VMess shows suspected GFW interference (consistent with
prior 12.5% remote loss pattern):

| Stack | Protocols Tested | Loss | Latency (avg) | Notes |
|-------|-----------------|------|---------------|-------|
| tier1 | reality | 0% | 787ms | |
| tier2 | reality | 0% | 787ms | |
| tier3 | ws+tls | 0% | 1035ms | WS framing overhead at high RTT |
| tier4 | shadowtls | 0% | 1080ms | |
| post-quantum | reality | 0% | 787ms | |
| legacy | vmess | 20% | 2055ms | ⚠️ suspected GFW DPI |

For the full protocol-level matrix, see [Protocol Matrix](#protocol-matrix) above.

## Known Artifacts

Not bugs — measurement artifacts inherent to the test method:

- **gRPC upload inflated** (13000-22000 Mbps): h2 internal buffering.
- **gRPC download ~0** (0.05-0.17 Mbps): h2 flow-control interaction with
  unidirectional download pattern.
- **WebSocket +41ms latency**: per-message framing/deframing overhead.
- **KCP +72ms**: protocol-level queue delay even in nodelay mode.
- **ShadowTLS +56ms**: handshake + TLS record crypto.
- **VMess +82ms**: AEAD body encryption + relay polling loop.

## Architecture

The evaluator imports protocol implementations from actual crates rather than
reimplementing them:

| Protocol logic | Imported from |
|----------------|---------------|
| VLESS header | `wrongsv_vless_encoding::encode_request_header` |
| WebSocket framing | `wrongsv_websocket::write_frame` |
| gRPC hunk framing | `wrongsv_grpc::encode_hunk_frame` / `decode_hunk_frame` |
| VMess crypto + body AEAD | `wrongsv_server::vmess` |
| TLS config | `tls_common::make_no_verify_config` (shared) |

REALITY client handshake and ShadowTLS HMAC auth remain evaluator-local — the
`wrongsv-reality` and server crates only expose server-side APIs.

## Building

```bash
# Server (static musl for remote deployment)
cargo build -p wrongsv-evaluator-server \
  --target x86_64-unknown-linux-musl --release

# Client
cargo build -p wrongsv-evaluator-client \
  --target x86_64-unknown-linux-musl --release
```

## GFW DPI Considerations

For protocols that exhibit GFW DPI blocking patterns (connection reset after
handshake, periodic RST during data transfer, TLS fingerprint rejection),
failures are treated as environmental rather than code defects. The evaluator
does not attempt to distinguish GFW interference from transport bugs — if a
protocol passes locally at 0% loss but fails remotely, suspect DPI.
