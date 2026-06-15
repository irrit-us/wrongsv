# Comprehensive Bench Report

- Combined report across runs:
  - `20260615-142339` → `benches/traffic/comprehensive/results/20260615-142339`
  - `20260615-162915` → `benches/traffic/comprehensive/results/20260615-162915`

## Methodology

- Each cell = (wrongsv-config, server impl). One server at a time, sequential.
- Traffic flow: vegeta → SOCKS5 (xray client, constant) → SUT → local HTTP target.
- The xray client and HTTP target are CONSTANT across cells; only the SUT varies.
- Network: `lo` shaped via `tc-netem` (50ms delay, 5ms jitter, 0.1% loss) when SHAPE_NETEM=1.
- Memory: SUT's `VmRSS` sampled every 5s. Leak slope = linear regression over samples.
- Throughput: req/s sustained over soak duration.

## Per-config comparison

### hysteria2

| Run | Server | Status | Req/s | Success % | p50 (ms) | p95 (ms) | p99 (ms) | RSS peak (MB) | RSS slope (KB/min) | Leak? |
|-----|--------|--------|------:|----------:|---------:|---------:|---------:|--------------:|-------------------:|:-----:|
| 20260615-162915 | wrongsv | ok | 200.0 | 100.00 | 0.5 | 0.7 | 0.8 | 9.0 | +0.0 | ok |
| 20260615-162915 | sing-box | ok | 200.0 | 100.00 | 0.5 | 0.7 | 0.8 | 34.7 | +16.3 | ok |
| 20260615-162915 | mihomo | ok | 200.0 | 100.00 | 0.5 | 0.7 | 0.8 | 43.3 | -338.5 | ok |

### reality-vision

| Run | Server | Status | Req/s | Success % | p50 (ms) | p95 (ms) | p99 (ms) | RSS peak (MB) | RSS slope (KB/min) | Leak? |
|-----|--------|--------|------:|----------:|---------:|---------:|---------:|--------------:|-------------------:|:-----:|
| 20260615-142339 | wrongsv | ok | 200.0 | 100.00 | 0.5 | 0.8 | 0.9 | 8.1 | +0.0 | ok |
| 20260615-142339 | xray | ok | 200.0 | 100.00 | 0.5 | 0.7 | 0.8 | 37.3 | -279.9 | ok |
| 20260615-142339 | sing-box | ok | 200.0 | 100.00 | 0.5 | 0.7 | 0.8 | 35.2 | +20.4 | ok |
| 20260615-142339 | mihomo | `unsupported` | — | — | — | — | — | — | — | — |

### shadowsocks-2022

| Run | Server | Status | Req/s | Success % | p50 (ms) | p95 (ms) | p99 (ms) | RSS peak (MB) | RSS slope (KB/min) | Leak? |
|-----|--------|--------|------:|----------:|---------:|---------:|---------:|--------------:|-------------------:|:-----:|
| 20260615-142339 | wrongsv | ok | 200.0 | 100.00 | 0.5 | 0.7 | 0.9 | 6.9 | +0.0 | ok |
| 20260615-142339 | xray | ok | 200.0 | 100.00 | 0.5 | 0.7 | 0.9 | 30.9 | +2.4 | ok |
| 20260615-142339 | sing-box | ok | 200.0 | 100.00 | 0.5 | 0.7 | 0.9 | 34.0 | +37.3 | ok |
| 20260615-142339 | mihomo | ok | 200.0 | 100.00 | 0.6 | 0.8 | 0.9 | 41.5 | -336.3 | ok |

### shadowtls

| Run | Server | Status | Req/s | Success % | p50 (ms) | p95 (ms) | p99 (ms) | RSS peak (MB) | RSS slope (KB/min) | Leak? |
|-----|--------|--------|------:|----------:|---------:|---------:|---------:|--------------:|-------------------:|:-----:|
| 20260615-162915 | wrongsv | ok | 200.0 | 100.00 | 0.5 | 0.7 | 0.9 | 8.8 | +0.0 | ok |
| 20260615-162915 | sing-box | ok | 200.0 | 100.00 | 0.5 | 0.7 | 0.9 | 34.3 | +14.1 | ok |
| 20260615-162915 | mihomo | `unsupported` | — | — | — | — | — | — | — | — |

### tls-vision

| Run | Server | Status | Req/s | Success % | p50 (ms) | p95 (ms) | p99 (ms) | RSS peak (MB) | RSS slope (KB/min) | Leak? |
|-----|--------|--------|------:|----------:|---------:|---------:|---------:|--------------:|-------------------:|:-----:|
| 20260615-142339 | wrongsv | `client_start_failed` | — | — | — | — | — | — | — | — |
| 20260615-142339 | xray | `client_start_failed` | — | — | — | — | — | — | — | — |
| 20260615-142339 | sing-box | `client_start_failed` | — | — | — | — | — | — | — | — |
| 20260615-142339 | mihomo | `unsupported` | — | — | — | — | — | — | — | — |

### trojan-tls

| Run | Server | Status | Req/s | Success % | p50 (ms) | p95 (ms) | p99 (ms) | RSS peak (MB) | RSS slope (KB/min) | Leak? |
|-----|--------|--------|------:|----------:|---------:|---------:|---------:|--------------:|-------------------:|:-----:|
| 20260615-142339 | wrongsv | `client_start_failed` | — | — | — | — | — | — | — | — |
| 20260615-142339 | xray | `client_start_failed` | — | — | — | — | — | — | — | — |
| 20260615-142339 | sing-box | `client_start_failed` | — | — | — | — | — | — | — | — |
| 20260615-142339 | mihomo | `server_start_failed` | — | — | — | — | — | — | — | — |

### vmess

| Run | Server | Status | Req/s | Success % | p50 (ms) | p95 (ms) | p99 (ms) | RSS peak (MB) | RSS slope (KB/min) | Leak? |
|-----|--------|--------|------:|----------:|---------:|---------:|---------:|--------------:|-------------------:|:-----:|
| 20260615-142339 | wrongsv | ok | 200.0 | 100.00 | 0.6 | 0.8 | 0.9 | 6.7 | +0.0 | ok |
| 20260615-142339 | xray | ok | 200.0 | 100.00 | 0.5 | 0.7 | 0.8 | 30.7 | -14.8 | ok |
| 20260615-142339 | sing-box | ok | 200.0 | 100.00 | 0.5 | 0.7 | 0.8 | 34.2 | +18.5 | ok |
| 20260615-142339 | mihomo | ok | 200.0 | 100.00 | 0.5 | 0.7 | 0.8 | 41.6 | -334.1 | ok |

## Per-server summary (across all configs and runs)

| Server | Cells run | OK | Failed | Unsupported | Mean req/s | Mean RSS peak (MB) | Leaks |
|--------|----------:|---:|-------:|------------:|-----------:|-------------------:|------:|
| wrongsv | 7 | 5 | 2 | 0 | 200.0 | 7.9 | 0 |
| xray | 5 | 3 | 2 | 0 | 200.0 | 32.9 | 0 |
| sing-box | 7 | 5 | 2 | 0 | 200.0 | 34.5 | 0 |
| mihomo | 7 | 3 | 1 | 3 | 200.0 | 42.1 | 0 |

## ✓ No memory leaks detected

All cells had RSS slope below the configured threshold (see `LEAK_THRESHOLD_KB_PER_MIN`, default 50).
