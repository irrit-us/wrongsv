# bench — wrongsv stability & performance test suite

Traffic generation and stability testing for wrongsv using publicly available tools.

## Quick Start

```bash
# One-time setup (clone + build all tools)
./bench/setup.sh

# Run all scenarios
./bench/run.sh all

# Run single scenario
./bench/run.sh reality-stress
```

## Tools

| Tool | Binary | Purpose |
|------|--------|---------|
| **Deathcore** | `tools/bin/deathcore` | REALITY-native VLESS protocol stress |
| **Hellcat-v2** | `tools/bin/hellcat` | Multi-user realistic VLESS traffic |
| **wrk2** | `tools/bin/wrk2` | Constant-throughput HTTP benchmark |
| **Vegeta** | `tools/bin/vegeta` | HTTP load testing & reporting |
| **k6** | `tools/bin/k6` | Scriptable user behavior simulation |

## Scenarios

| Scenario | Tools | What it tests |
|----------|-------|---------------|
| `reality-stress` | Deathcore | REALITY handshake rate, connection flood, HTTP relay |
| `multi-user-sim` | Hellcat-v2 | Random UUID/SNI users, mixed load, SYN flood |
| `throughput-ladder` | wrk2, Vegeta, curl | Throughput-vs-latency curve, large downloads |
| `tls-handshake` | wrk2, curl | TLS 1.3 handshake concurrency, connect rate |

## Scripts

| Script | Usage |
|--------|-------|
| `scripts/k6-real-browse.js` | Realistic multi-user browsing via k6 through SOCKS5 |
| `scripts/headless-gmail-test.py` | Headless Chrome Gmail test through SOCKS5 (from docs) |

## Configuration

```bash
# Customize via environment variables
SERVER_HOST=my.server.com \
SERVER_PORT=443 \
DURATION=120s \
CONCURRENT=500 \
./bench/run.sh reality-stress
```

## Results

All results are saved to `bench/results/<timestamp>/<scenario>/`.

### Initial Benchmarks (localhost, TLS+Vision mode, 100 clients)

| Metric | Value |
|--------|-------|
| TLS handshakes | 32,577 (over all test phases) |
| Successful VLESS relays | 7,681 |
| Relay success rate | **100%** |
| Sustained RPS (100 clients) | 153 req/s |
| Peak RPS (200 clients) | 304 req/s |
| TLS handshake P50 latency | 105ms @ 200 conn/s |
| Memory (idle) | 9 MB RSS |
| Memory (200 clients) | 17 MB RSS |
| Memory leak | **None detected** |

> Note: "connection errors" in logs are expected — Hellcat's `mixed`/`handshake` modes send SYN/ACK probes that aren't valid VLESS headers. The server correctly rejects these. All valid VLESS requests succeed.
