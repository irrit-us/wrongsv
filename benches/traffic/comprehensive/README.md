# comprehensive — multi-server comparison matrix

Head-to-head comparison of **wrongsv** vs **xray**, **sing-box**, **mihomo**
across all wrongsv protocol configs, with **memory leak detection** and
**realistic network shaping** (tc-netem).

## What runs

```
For each config in configs/*.toml:
  For each server in {wrongsv, xray, sing-box, mihomo}:
    1. apply tc-netem on lo (50ms delay, 5ms jitter, 0.1% loss)
    2. start the server-under-test (SUT) with the canonical config for that protocol
    3. start an xray client (CONSTANT — exposes SOCKS5:18080)
    4. start a local HTTP target (CONSTANT — listens on 18081)
    5. sample SUT's VmRSS every 5s in background
    6. drive vegeta at LOAD_RATE through SOCKS5 for SOAK_DURATION,
       using LOAD_WORKERS / LOAD_CONNECTIONS / LOAD_MAX_CONNECTIONS
    7. stop everything; record memory slope + throughput + latency
```

Only the SUT varies between cells — the load generator, SOCKS5 translator,
and HTTP target are constant, so any differences observed are attributable
to the server.

## Run

```bash
# Full matrix (long — ~hours)
./matrix.sh

# Or via the parent run.sh dispatcher
../run.sh comprehensive

# Smoke test (1 config × 1 server × 60s)
SERVERS=wrongsv CONFIGS=vmess SOAK_DURATION=60 SHAPE_NETEM=0 ./matrix.sh
```

## Tunables (env vars)

| Var | Default | Notes |
|-----|---------|-------|
| `SERVERS` | `wrongsv xray sing-box mihomo` | Space-separated subset |
| `CONFIGS` | auto-discovered | Intersection of `configs/*.toml` and a canonical server config |
| `SOAK_DURATION` | `1800` (30 min) | Per cell, seconds |
| `LOAD_RATE` | `200` | Requests/second (vegeta rate) |
| `LOAD_PAYLOAD` | `8192` | Response body size, bytes |
| `LOAD_WORKERS` | `10` | Initial vegeta workers |
| `LOAD_CONNECTIONS` | `10000` | Max idle connections per target host |
| `LOAD_MAX_CONNECTIONS` | `0` | Max active connections per target host; `0` keeps vegeta unlimited |
| `SHAPE_NETEM` | `1` | Apply tc-netem on `lo` (needs `CAP_NET_ADMIN`) |
| `LEAK_THRESHOLD_KB_PER_MIN` | `50` | Slope above this flags as leak |
| `SAMPLE_INTERVAL` | `5` | Memory sampler period, seconds |
| `RESULTS_DIR` | `results/<timestamp>` | Output root |

## Files

```
matrix.sh                Orchestrator
report.py                Aggregates JSON cells → REPORT.md
lib/netem.sh             Apply / restore tc-netem on lo
lib/memory.sh            VmRSS sampler + linear-regression leak detection
lib/certs.sh             Self-signed TLS cert at /tmp/wrongsv-bench-cert.pem
lib/server.sh            start_server / stop_server for all 4 binaries
lib/load.sh              vegeta-via-SOCKS5h driver + xray client + HTTP target
server-configs/{xray,sing-box,mihomo}/  Canonical server configs per protocol
client-configs/                          xray client configs (constant translator)
```

## Output

Each cell writes `results/<timestamp>/<config>/<server>.json`:

```json
{
  "server": "wrongsv",
  "config": "vmess",
  "status": "ok",
  "duration_sec": 1800,
  "load_rate": 200,
  "load_payload_bytes": 8192,
  "load_workers": 10,
  "load_connections": 10000,
  "load_max_connections": 0,
  "memory": {
    "slope_kb_per_min": 0.4,
    "leak": false,
    "rss_initial_kb": 12384,
    "rss_final_kb": 12400,
    "rss_peak_kb": 12592,
    "n_samples": 360
  },
  "load": {
    "requests": 360000,
    "success_ratio": 0.999,
    "throughput_req_s": 199.4,
    "latency_p50_ns": 50100000,
    "latency_p95_ns": 53000000,
    "latency_p99_ns": 61000000
  }
}
```

After the run, `REPORT.md` is auto-generated with per-config tables, per-server
summaries, and a leak list. See `report.py` for the layout.

## Prerequisites

- `xray`, `sing-box`, `mihomo` binaries (path-overridable via `XRAY_BIN`,
  `SINGBOX_BIN`, `MIHOMO_BIN`)
- `vegeta` (in `tools/bin/`)
- `python3` (memory sampler, report generation)
- `openssl` (TLS cert)
- `tc` + sudo (only if `SHAPE_NETEM=1`)

## Caveats

- **mihomo limitations**: mihomo is primarily a client; it supports vmess,
  trojan, and shadowsocks as server inbound but not VLESS/REALITY/AnyTLS.
  Unsupported cells are recorded as `unsupported`, not failures.
- **VMess interop**: wrongsv's VMess dialect diverges from v2fly/xray in key
  derivation. The xray client used as translator may not interop with
  wrongsv's VMess server in cells where wrongsv is the SUT. Treat VMess
  comparison results with care.
- **CAP_NET_ADMIN**: without sudo, the matrix runs unshaped (warning emitted).
- **Single port per protocol family**: TLS-class protocols share 18443;
  Shadowsocks uses 18388. The matrix is sequential, so no port contention.
