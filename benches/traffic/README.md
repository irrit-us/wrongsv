# bench — wrongsv stability & performance test suite

Traffic generation and stability testing for wrongsv using publicly available tools.

## Quick Start

```bash
# One-time setup (clone + build all tools)
./benches/traffic/setup.sh

# Run all scenarios
./benches/traffic/run.sh all

# Run single scenario
./benches/traffic/run.sh reality-stress
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
./benches/traffic/run.sh reality-stress
```

## Results

All results are saved to `benches/traffic/results/<timestamp>/<scenario>/`.

### TLS+Vision Mode (Hellcat-v2)

| Metric | Value |
|--------|-------|
| Successful VLESS relays | 18,088 (100 clients, 60s) |
| Relay success rate | **100%** |
| Sustained RPS (100 clients) | 153 req/s |
| Peak RPS (200 clients) | 304 req/s |
| Memory (idle/loaded) | 9 MB / 17 MB |
| Memory leak | **None** |

### REALITY+Vision Mode (Deathcore + xray-core)

#### Local (localhost)

| Metric | Value |
|--------|-------|
| Connections (30s burst) | 5,812 |
| Connections (120s soak) | 9,466 |
| Data sent (120s) | 65.8 GB |
| REALITY handshakes | 19,930 |
| Memory (120s soak) | 37-39 MB |
| Memory leak | **None** |
| Errors / Crashes | **0** |

#### Remote (<SERVER_IP>:443, 1 vCPU / 512MB)

| Metric | Value |
|--------|-------|
| Connections (50 workers) | 844 |
| Data sent | 2.1 GB |
| REALITY handshakes | 930 |
| TCP relays | 930 (100%) |
| RSS memory | 4.3 MB |
| Threads | 2 |
| Errors | **0** |

### HTTP through SOCKS5 → REALITY (Vegeta)

| Rate | Success | P50 Latency |
|------|---------|-------------|
| 10 req/s | 86.7% | 1.175s |
| 50 req/s | 98.7% | 1.153s |
| 100 req/s | 72.5% | 1.206s |

> Bottleneck at 100 req/s is sing-box SOCKS5 connection management, not wrongsv.
