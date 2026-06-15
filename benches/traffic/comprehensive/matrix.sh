#!/usr/bin/env bash
# matrix.sh — comprehensive comparison matrix for wrongsv vs xray/sing-box/mihomo.
#
# For each (config × server) cell:
#   1. Apply tc-netem shaping on lo (50ms delay, 5ms jitter, 0.1% loss)
#   2. Start the server-under-test (SUT)
#   3. Start an xray client (constant) exposing SOCKS5 on 127.0.0.1:18080
#   4. Start a local HTTP target on 127.0.0.1:18081 (constant)
#   5. Sample SUT's RSS every 5s in background while vegeta drives load through SOCKS5
#   6. After SOAK_DURATION, stop everything, restore netem
#   7. Write {cell}.json containing throughput + memory + leak verdict
#
# Cells where the server doesn't support that protocol (no canonical config)
# are recorded as `unsupported`.
#
# Env vars:
#   SERVERS         space-separated list of {wrongsv,xray,sing-box,mihomo}
#                   (default: all four)
#   CONFIGS         space-separated list of config names (e.g. "reality-vision vmess")
#                   (default: discovered from server-configs/*/<name>.* intersection)
#   SOAK_DURATION   seconds per cell (default 1800 = 30 min)
#   LOAD_RATE       requests per second (default 200)
#   LOAD_PAYLOAD    bytes per response (default 8192)
#   SHAPE_NETEM     1|0 — apply tc-netem shaping (default 1)
#   RESULTS_DIR     output directory (default $COMP_DIR/results/TIMESTAMP)
set -uo pipefail

COMP_DIR="$(realpath "$(dirname "$0")")"
LIB="$COMP_DIR/lib"
RESULTS_BASE="${RESULTS_DIR:-$COMP_DIR/results/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$RESULTS_BASE"

# shellcheck disable=SC1091
source "$LIB/netem.sh"
# shellcheck disable=SC1091
source "$LIB/memory.sh"
# shellcheck disable=SC1091
source "$LIB/server.sh"
# shellcheck disable=SC1091
source "$LIB/load.sh"
# shellcheck disable=SC1091
source "$LIB/certs.sh"

# ── Config ──────────────────────────────────────────────────────────────────
SERVERS="${SERVERS:-wrongsv xray sing-box mihomo}"
SOAK_DURATION="${SOAK_DURATION:-1800}"
LOAD_RATE="${LOAD_RATE:-200}"
LOAD_PAYLOAD="${LOAD_PAYLOAD:-8192}"
SHAPE_NETEM="${SHAPE_NETEM:-1}"
LEAK_THRESHOLD_KB_PER_MIN="${LEAK_THRESHOLD_KB_PER_MIN:-50}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-5}"

export SOAK_DURATION SAMPLE_INTERVAL LEAK_THRESHOLD_KB_PER_MIN

# Discover configs: intersection of wrongsv configs (configs/*.toml) and at least
# one competitor with a canonical config. If CONFIGS env var is set, use that.
discover_configs() {
    local wrongsv_dir comp_dir
    wrongsv_dir="$(realpath "$COMP_DIR/../../../configs")"
    comp_dir="$COMP_DIR/server-configs"
    local out=()
    for f in "$wrongsv_dir"/*.toml; do
        local name
        name="$(basename "$f" .toml)"
        # include if ANY competitor has a canonical config (so we can compare ≥2 servers)
        if [ -f "$comp_dir/xray/$name.json" ] || \
           [ -f "$comp_dir/sing-box/$name.json" ] || \
           [ -f "$comp_dir/mihomo/$name.yaml" ]; then
            out+=("$name")
        fi
    done
    echo "${out[@]}"
}

CONFIGS="${CONFIGS:-$(discover_configs)}"

log()  { echo "[$(date +%H:%M:%S)] $*"; }
warn() { echo "[$(date +%H:%M:%S)] WARN $*" >&2; }

# Cleanup state — populated as we start things
ACTIVE_SUT_PID=""
ACTIVE_CLIENT_PID=""
ACTIVE_TARGET_PID=""
ACTIVE_MEM_PID=""

cleanup_cell() {
    [ -n "$ACTIVE_MEM_PID" ]    && kill "$ACTIVE_MEM_PID" 2>/dev/null
    [ -n "$ACTIVE_SUT_PID" ]    && stop_server "$ACTIVE_SUT_PID"
    [ -n "$ACTIVE_CLIENT_PID" ] && stop_server "$ACTIVE_CLIENT_PID"
    [ -n "$ACTIVE_TARGET_PID" ] && stop_server "$ACTIVE_TARGET_PID"
    ACTIVE_SUT_PID=""
    ACTIVE_CLIENT_PID=""
    ACTIVE_TARGET_PID=""
    ACTIVE_MEM_PID=""
}

trap 'cleanup_cell; [ "$SHAPE_NETEM" = "1" ] && netem_restore' EXIT INT TERM

# ── Cell runner ────────────────────────────────────────────────────────────
# run_cell SERVER CONFIG_NAME -> writes $RESULTS_BASE/$CONFIG/$SERVER.json
run_cell() {
    local server="$1"
    local cfg_name="$2"
    local cell_dir="$RESULTS_BASE/$cfg_name"
    mkdir -p "$cell_dir"
    local out_json="$cell_dir/$server.json"
    local sut_log="$cell_dir/$server.server.log"
    local cli_log="$cell_dir/$server.client.log"
    local tgt_log="$cell_dir/$server.target.log"
    local mem_json="$cell_dir/$server.memory.json"
    local vegeta_json="$cell_dir/$server.vegeta.json"
    local vegeta_log="$cell_dir/$server.vegeta.log"

    log "▶ $server × $cfg_name"

    # 1. Start SUT
    ACTIVE_SUT_PID="$(start_server "$server" "$cfg_name" "$sut_log" 2>>"$sut_log")"
    local rc=$?
    if [ "$rc" -eq 2 ]; then
        log "  $server unsupported for $cfg_name — skipping"
        cat > "$out_json" <<JSON
{"server":"$server","config":"$cfg_name","status":"unsupported"}
JSON
        return 0
    elif [ "$rc" -ne 0 ] || [ -z "$ACTIVE_SUT_PID" ]; then
        warn "  $server failed to start for $cfg_name"
        cat > "$out_json" <<JSON
{"server":"$server","config":"$cfg_name","status":"server_start_failed","log":"$sut_log"}
JSON
        cleanup_cell
        return 0
    fi

    # 2. Start protocol-appropriate client (xray for most; sing-box for shadowtls/hysteria2)
    ACTIVE_CLIENT_PID="$(start_client_for "$cfg_name" "$cli_log" 2>>"$cli_log")" || ACTIVE_CLIENT_PID=""
    if [ -z "$ACTIVE_CLIENT_PID" ]; then
        warn "  client failed to start for $cfg_name"
        cat > "$out_json" <<JSON
{"server":"$server","config":"$cfg_name","status":"client_start_failed","log":"$cli_log"}
JSON
        cleanup_cell
        return 0
    fi

    # 3. Start target HTTP server
    ACTIVE_TARGET_PID="$(start_target_server "$tgt_log")" || ACTIVE_TARGET_PID=""
    if [ -z "$ACTIVE_TARGET_PID" ]; then
        warn "  target HTTP server failed to start"
        cat > "$out_json" <<JSON
{"server":"$server","config":"$cfg_name","status":"target_start_failed"}
JSON
        cleanup_cell
        return 0
    fi

    # 4. Memory sampler in background, attached to SUT PID
    ( sample_memory "$ACTIVE_SUT_PID" "$mem_json" ) &
    ACTIVE_MEM_PID=$!

    # 5. Drive load. vegeta runs for SOAK_DURATION seconds.
    if ! run_vegeta "$SOAK_DURATION" "$LOAD_RATE" "$LOAD_PAYLOAD" "$vegeta_json" "$vegeta_log"; then
        warn "  vegeta failed; partial data may be in $vegeta_log"
    fi

    # 6. Wait for memory sampler to finish (it should be near-done since soak just ended)
    wait "$ACTIVE_MEM_PID" 2>/dev/null || true
    ACTIVE_MEM_PID=""

    # 7. Combine memory + load results into the cell's JSON
    python3 - <<PYEOF > "$out_json"
import json, os
result = {
    "server": "$server",
    "config": "$cfg_name",
    "status": "ok",
    "duration_sec": $SOAK_DURATION,
    "load_rate": $LOAD_RATE,
    "load_payload_bytes": $LOAD_PAYLOAD,
    "netem": {"shaped": $( [ "$SHAPE_NETEM" = "1" ] && echo True || echo False )},
}
try:
    with open("$mem_json") as f:
        result["memory"] = json.load(f)
        del result["memory"]["samples"]    # too long; raw samples kept in $mem_json
except Exception as e:
    result["memory_error"] = str(e)
try:
    with open("$vegeta_json") as f:
        v = json.load(f)
    # Pull the fields we want from vegeta's report
    result["load"] = {
        "requests": v.get("requests"),
        "success_ratio": v.get("success"),
        "throughput_req_s": v.get("throughput"),
        "throughput_bytes_in": v.get("bytes_in", {}).get("total"),
        "latency_p50_ns": v.get("latencies", {}).get("50th"),
        "latency_p95_ns": v.get("latencies", {}).get("95th"),
        "latency_p99_ns": v.get("latencies", {}).get("99th"),
        "latency_max_ns": v.get("latencies", {}).get("max"),
        "errors": v.get("errors", []),
    }
except Exception as e:
    result["load_error"] = str(e)
print(json.dumps(result, indent=2))
PYEOF

    cleanup_cell
    log "  ✓ $server × $cfg_name done"
}

# ── Main loop ──────────────────────────────────────────────────────────────
log "Comprehensive matrix — $(date)"
log "Results dir: $RESULTS_BASE"
log "Servers: $SERVERS"
log "Configs: $CONFIGS"
log "Soak duration: ${SOAK_DURATION}s, load rate: ${LOAD_RATE}/s, payload: ${LOAD_PAYLOAD}B"

if [ "$SHAPE_NETEM" = "1" ]; then
    netem_apply
fi

# Build (xray cert) for TLS-needing protocols
ensure_bench_cert || true

# Build wrongsv if missing
if [ ! -x "$WRONGSV_BIN" ]; then
    log "Building wrongsv..."
    (cd "$(realpath "$COMP_DIR/../../..")" && cargo build --release) >/dev/null
fi

for cfg in $CONFIGS; do
    for server in $SERVERS; do
        run_cell "$server" "$cfg"
    done
done

if [ "$SHAPE_NETEM" = "1" ]; then
    netem_restore
fi

log "✓ all cells done — $RESULTS_BASE"
log "  Run report: python3 $COMP_DIR/report.py $RESULTS_BASE"

# Auto-generate report if python is available
if command -v python3 >/dev/null && [ -f "$COMP_DIR/report.py" ]; then
    python3 "$COMP_DIR/report.py" "$RESULTS_BASE" > "$RESULTS_BASE/REPORT.md"
    log "  Wrote $RESULTS_BASE/REPORT.md"
fi
