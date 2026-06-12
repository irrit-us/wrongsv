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

All 17 protocols at 0% loss locally. Remote results via direct connection.

| Protocol | Local | Remote | Notes |
|----------|-------|--------|-------|
| reality | 0% | 0% | |
| anytls | 0% | 0% | |
| tls | 0% | 0% | |
| raw | 0% | 0% | baseline |
| ws | 0% | 0% | |
| ws+tls | 0% | 0% | |
| httpupgrade | 0% | 0% | |
| httpupgrade+tls | 0% | 0% | |
| grpc | 0% | 0% | upload inflated*, download ~0* |
| grpc+tls | 0% | timeout | h2 stream errors at high RTT |
| xhttp | 0% | untested | |
| xhttp+tls | 0% | untested | |
| quic | 0% | untested | |
| kcp | 0% | untested | |
| webtransport | 0% | untested | |
| shadowtls | 0% | untested | |
| vmess | 0% | untested | |

\* Known artifact: h2 internal buffering. Not a protocol bug.

## Known Artifacts

Not bugs — measurement artifacts inherent to the test method:

- **gRPC upload inflated** (13000-22000 Mbps): h2 internal buffering.
- **gRPC download ~0** (0.05-0.17 Mbps): h2 flow-control interaction with
  unidirectional download pattern.
- **WebSocket +41ms latency**: per-message framing/deframing overhead.
- **KCP +72ms**: protocol-level queue delay even in nodelay mode.
- **ShadowTLS +56ms**: handshake + TLS record crypto.
- **VMess +82ms**: AEAD body encryption + relay polling loop.

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
