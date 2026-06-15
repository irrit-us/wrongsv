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

| Metric | Value |
|--------|-------|
| Connections (30s burst) | 5,812 |
| Connections (120s soak) | 9,466 |
| Data sent (120s) | 65.8 GB |
| REALITY handshakes | 19,930 |
| Memory (120s soak) | 37-39 MB |
| Memory leak | **None** |
| Errors / Crashes | **0** |

### HTTP through SOCKS5 → REALITY (Vegeta)

| Rate | Success | P50 Latency |
|------|---------|-------------|
| 10 req/s | 86.7% | 1.175s |
| 50 req/s | 98.7% | 1.153s |
| 100 req/s | 72.5% | 1.206s |

> Bottleneck at 100 req/s is sing-box SOCKS5 connection management, not wrongsv.

## Comprehensive multi-server comparison

For head-to-head comparison of wrongsv vs xray / sing-box / mihomo across all
protocol configs — including memory leak detection over a 30-min soak under
realistic network conditions — see `comprehensive/`.

```bash
# Run the full matrix (4 servers × ~30 configs × 30-min soak — long)
./benches/traffic/run.sh comprehensive

# Subset: one config, one server, short soak (for smoke-testing)
SERVERS=wrongsv CONFIGS=vmess SOAK_DURATION=60 SHAPE_NETEM=0 \
    ./benches/traffic/run.sh comprehensive

# Without tc-netem shaping (no root needed)
SHAPE_NETEM=0 ./benches/traffic/run.sh comprehensive
```

### What it measures per cell

- **Throughput** — sustained req/s and bytes/s via vegeta through a SOCKS5
  client (xray, held constant across cells; only the server-under-test varies).
- **Latency** — p50/p95/p99 from vegeta's HDR histogram.
- **Memory** — `/proc/PID/status` VmRSS sampled every 5 s; leak verdict is the
  slope of a linear regression in KB/min over the soak.
- **Compatibility** — cells where a server lacks a canonical config for that
  protocol are recorded as `unsupported`.

### Network shaping

When `SHAPE_NETEM=1` (default), the matrix runs `tc qdisc replace dev lo root
netem delay 50ms 5ms distribution normal loss 0.1%` on `lo` to simulate a
realistic WAN. Requires `CAP_NET_ADMIN` (sudo); degrades to unshaped loopback
if sudo is unavailable.

### Env vars

| Var | Default | Purpose |
|-----|---------|---------|
| `SERVERS` | `wrongsv xray sing-box mihomo` | Servers to bench |
| `CONFIGS` | (auto-discovered) | Protocol configs to bench |
| `SOAK_DURATION` | `1800` (30 min) | Seconds per cell |
| `LOAD_RATE` | `200` | Requests/second |
| `LOAD_PAYLOAD` | `8192` | Bytes per response |
| `SHAPE_NETEM` | `1` | Apply tc-netem on `lo` |
| `LEAK_THRESHOLD_KB_PER_MIN` | `50` | Slope above this flags leak |

### Output

`results/<timestamp>/<config>/<server>.json` per cell, plus an auto-generated
`REPORT.md` aggregating per-config tables, per-server summaries, and a flagged
leak list. See `comprehensive/report.py` for the format.

## Microbenchmarks

Computational efficiency of encode/decode hot paths is covered by criterion
benches at the workspace root:

```bash
cargo bench --bench throughput   # VLESS encode/decode, XTLS Vision padding
cargo bench --bench protocols    # VMess, Shadowsocks-2022, AnyTLS, WebSocket
```
