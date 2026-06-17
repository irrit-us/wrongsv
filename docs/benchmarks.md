# Benchmarks

This page is the canonical entrypoint for performance work in `wrongsv`.

Use it together with:

- `benches/traffic/README.md` for the full traffic-harness details
- [bench-comprehensive.md](bench-comprehensive.md) for the latest published
  cross-server summary
- [testing.md](testing.md) for the rest of the test suite
- `.github/workflows/bench-smoke.yml` for the dedicated manual benchmark
  workflow outside main CI

## Benchmark Surfaces

There are two benchmark layers:

- Criterion microbenchmarks for encode/decode and protocol hot paths
- traffic and soak harnesses under `benches/traffic/`

## Quick Start

Criterion:

```bash
cargo bench --bench throughput
cargo bench --bench protocols
```

Traffic harness:

```bash
./benches/traffic/setup.sh
./benches/traffic/run.sh all
./benches/traffic/run.sh reality-stress
```

Comprehensive multi-server matrix:

```bash
./benches/traffic/run.sh comprehensive

SERVERS=wrongsv CONFIGS=vmess SOAK_DURATION=60 SHAPE_NETEM=0 \
  ./benches/traffic/run.sh comprehensive
```

## What Each Layer Measures

Criterion benches currently cover:

- request header encode / decode
- XTLS Vision padding / unpadding
- VMess header helpers
- AnyTLS verification
- Shadowsocks-2022 UDP request encryption
- WebSocket frame read / write roundtrips

The traffic harness covers:

- handshake rate and connection flood behavior
- throughput and latency curves
- multi-user and browser-like workloads
- long-running soak tests with RSS sampling
- comprehensive multi-server comparisons against xray, sing-box, and mihomo

## Key Parameters

The comprehensive matrix already exposes runtime knobs through environment
variables. Common ones are:

| Variable | Default | Meaning |
|----------|---------|---------|
| `SERVERS` | `wrongsv xray sing-box mihomo` | Servers to benchmark |
| `CONFIGS` | auto-discovered | Protocol configs to benchmark |
| `SOAK_DURATION` | `1800` | Seconds per matrix cell |
| `LOAD_RATE` | `200` | Requests per second |
| `LOAD_PAYLOAD` | `8192` | Response payload bytes |
| `SHAPE_NETEM` | `1` | Apply loopback `tc-netem` shaping |
| `LEAK_THRESHOLD_KB_PER_MIN` | `50` | RSS slope threshold for leak verdict |

See `benches/traffic/README.md` for the full list.

## Outputs

Microbench output uses Criterion's normal report layout.

The traffic harness writes timestamped directories under
`benches/traffic/results/`.

The comprehensive matrix writes one JSON file per `(config, server)` cell plus
an aggregated report. Published snapshots currently live in:

- [bench-comprehensive.md](bench-comprehensive.md)
- [bench-comprehensive.csv](bench-comprehensive.csv)

Each comprehensive cell records:

- protocol config and server implementation
- req/s throughput
- latency percentiles
- RSS peak and RSS slope
- compatibility verdict
- commit, OS, CPU, build profile, and load metadata

## Regression Policy

The repo CI does not currently execute the performance presets below, but these
are the intended parameters and thresholds for manual pre-merge checks and any
future benchmark automation.

Only compare runs when the environment and parameters match:

- same OS and CPU class
- same `wrongsv` build profile
- same `SERVERS` and `CONFIGS`
- same `SOAK_DURATION`, `LOAD_RATE`, `LOAD_PAYLOAD`, and connection settings
- same `SHAPE_NETEM` setting

For the published 8-config comparison set
(`anytls-tcp`, `hysteria2`, `reality-vision`, `shadowsocks-2022`,
`shadowtls`, `tls-vision`, `trojan-tls`, `vmess`), treat these as the working
guardrails for `wrongsv`:

- Hard failure:
  - a previously-supported `wrongsv` cell stops reporting `status: "ok"`
  - `success_ratio < 0.995`
  - `memory.leak = true`
- Regression requiring investigation before merge or release:
  - throughput drop greater than 10%
  - p95 latency increase greater than 20%
  - RSS peak increase greater than 25%

Unsupported competitor cells are acceptable only when they remain consistent
with the documented capability limits in [bench-comprehensive.md](bench-comprehensive.md).
A newly unsupported `wrongsv` cell is always a regression.

## Parameter Sets

### PR Smoke Preset

Use this for a fast wrongsv-only sanity check that still covers the major
protocol families in the published comparison set:

```bash
SERVERS=wrongsv \
CONFIGS="anytls-tcp reality-vision hysteria2 shadowsocks-2022 trojan-tls vmess" \
SOAK_DURATION=60 \
LOAD_RATE=50 \
LOAD_PAYLOAD=2048 \
LOAD_WORKERS=4 \
LOAD_CONNECTIONS=256 \
LOAD_MAX_CONNECTIONS=256 \
SHAPE_NETEM=0 \
./benches/traffic/run.sh comprehensive
```

Intent:

- keep runtime to minutes instead of hours
- avoid root-dependent network shaping
- verify that the harness, wrongsv server, SOCKS5 translator, and load path
  still work across the main protocol families

### Nightly Comparison Preset

Use this for the regular comparative benchmark pass behind the published
8-protocol report:

```bash
SERVERS="wrongsv xray sing-box mihomo" \
CONFIGS="anytls-tcp hysteria2 reality-vision shadowsocks-2022 shadowtls tls-vision trojan-tls vmess" \
SOAK_DURATION=600 \
LOAD_RATE=200 \
LOAD_PAYLOAD=8192 \
LOAD_WORKERS=10 \
LOAD_CONNECTIONS=10000 \
LOAD_MAX_CONNECTIONS=0 \
SHAPE_NETEM=1 \
./benches/traffic/run.sh comprehensive
```

Intent:

- match the current 10-minute published comparison style
- preserve realistic WAN-like loopback shaping
- compare wrongsv against xray, sing-box, and mihomo where canonical configs
  exist

### Extended Soak Preset

Use this for release qualification or periodic long-run checks:

```bash
SOAK_DURATION=1800 \
SHAPE_NETEM=1 \
./benches/traffic/run.sh comprehensive
```

Intent:

- run the full discovered intersection with the long 30-minute soak default
- increase confidence in leak detection and longer-duration stability

## Dedicated Workflow

The repo now includes `.github/workflows/bench-smoke.yml` as a dedicated manual
benchmark workflow outside the main CI path.

- `pr-smoke` runs the documented wrongsv-only smoke preset.
- `nightly-comparison` runs the documented 8-config comparison set.
- `extended-soak` runs the long soak preset.

The workflow currently uses `SHAPE_NETEM=0` for GitHub-hosted runners, because
the hosted environment is not treated as a stable place for root-dependent
loopback shaping. Treat those runs as comparable only to other unshaped runs.

The workflow intentionally remains `workflow_dispatch`-only for now.

Reasons:

- the GitHub-hosted runner path is unshaped (`SHAPE_NETEM=0`), so unattended
  scheduled numbers would mix poorly with the shaped comparison baseline
- `benches/traffic/setup.sh` downloads and builds several external tools, which
  makes every run comparatively heavy
- the results are more useful as operator-invoked spot checks than as noisy
  scheduled gates until a more stable benchmark environment exists
