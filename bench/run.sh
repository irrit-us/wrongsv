#!/usr/bin/env bash
# run.sh — wrongsv stability test runner
# Usage: ./bench/run.sh [scenario] [--debug]
# Scenarios: reality-stress, multi-user, throughput-ladder, tls-handshake, all
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$BENCH_DIR/tools/bin"
RESULTS_DIR="$BENCH_DIR/results/$(date +%Y%m%d-%H%M%S)"
SCENARIOS_DIR="$BENCH_DIR/scenarios"
WRONGSV_DIR="$(dirname "$BENCH_DIR")"

# Defaults
SERVER_HOST="${SERVER_HOST:-127.0.0.1}"
SERVER_PORT="${SERVER_PORT:-8443}"
SOCKS_PORT="${SOCKS_PORT:-10809}"
DURATION="${DURATION:-30s}"
CONCURRENT="${CONCURRENT:-100}"
WRONGSV_BIN="${WRONGSV_BIN:-$WRONGSV_DIR/target/release/wrongsv}"
TEST_CONFIG="${TEST_CONFIG:-$BENCH_DIR/configs/test-reality.toml}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; }

check_tools() {
    local missing=""
    for tool in deathcore hellcat wrk2 vegeta k6; do
        if [ ! -x "$BIN_DIR/$tool" ] && [ ! -L "$BIN_DIR/$tool" ]; then
            missing="$missing $tool"
        fi
    done
    if [ -n "$missing" ]; then
        err "Missing tools:$missing"
        err "Run: ./bench/setup.sh"
        exit 1
    fi
}

start_server() {
    local config="${1:-$TEST_CONFIG}"
    if [ ! -f "$config" ]; then
        err "Config not found: $config"
        exit 1
    fi
    log "Building wrongsv..."
    cd "$WRONGSV_DIR" && cargo build --release 2>&1 | tail -1
    log "Starting wrongsv with $config..."
    "$WRONGSV_BIN" --config "$config" &
    WRONGSV_PID=$!
    sleep 2
    if ! kill -0 "$WRONGSV_PID" 2>/dev/null; then
        err "wrongsv failed to start"
        exit 1
    fi
    log "wrongsv running (PID: $WRONGSV_PID)"
}

stop_server() {
    if [ -n "${WRONGSV_PID:-}" ] && kill -0 "$WRONGSV_PID" 2>/dev/null; then
        log "Stopping wrongsv (PID: $WRONGSV_PID)..."
        kill "$WRONGSV_PID" 2>/dev/null || true
        wait "$WRONGSV_PID" 2>/dev/null || true
    fi
}

cleanup() {
    stop_server
    log "Results saved to: $RESULTS_DIR"
}
trap cleanup EXIT

run_scenario() {
    local scenario="$1"
    local script="$SCENARIOS_DIR/$scenario.sh"
    if [ ! -f "$script" ]; then
        err "Scenario not found: $scenario (looked for $script)"
        err "Available: $(ls "$SCENARIOS_DIR"/*.sh 2>/dev/null | xargs -I{} basename {} .sh)"
        exit 1
    fi
    log "Running scenario: $scenario"
    mkdir -p "$RESULTS_DIR/$scenario"
    # Source the scenario script — it has access to run_tool, SERVER_HOST, etc.
    source "$script"
}

run_tool() {
    # Helper: run a tool with args, log output to results dir
    local name="$1"
    shift
    local out="$RESULTS_DIR/${scenario:-unknown}/$name-$(date +%H%M%S).log"
    log "  -> $name $*"
    "$@" 2>&1 | tee "$out"
    echo ""
}

# ── Main ────────────────────────────────────────────────────────────────────
mkdir -p "$RESULTS_DIR"
check_tools

case "${1:-all}" in
    all)
        for s in "$SCENARIOS_DIR"/*.sh; do
            scenario_name="$(basename "$s" .sh)"
            start_server "$TEST_CONFIG"
            run_scenario "$scenario_name"
            stop_server
        done
        ;;
    reality-stress|multi-user|throughput-ladder|tls-handshake)
        start_server "$TEST_CONFIG"
        run_scenario "$1"
        stop_server
        ;;
    *)
        echo "Usage: $0 [scenario]"
        echo "Scenarios: reality-stress, multi-user, throughput-ladder, tls-handshake, all"
        echo ""
        echo "Env vars:"
        echo "  SERVER_HOST=$SERVER_HOST"
        echo "  SERVER_PORT=$SERVER_PORT"
        echo "  DURATION=$DURATION"
        echo "  CONCURRENT=$CONCURRENT"
        echo "  WRONGSV_BIN=$WRONGSV_BIN"
        echo "  TEST_CONFIG=$TEST_CONFIG"
        exit 1
        ;;
esac
