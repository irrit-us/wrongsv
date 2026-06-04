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
