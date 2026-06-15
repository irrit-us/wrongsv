#!/usr/bin/env bash
# load.sh — drives load against a server-under-test via:
#
#   [vegeta-via-curl] --HTTP--> [xray client SOCKS5:18080] --proxy--> [SUT:18443] --HTTP--> [target:18081]
#
# The xray client and target HTTP server are a CONSTANT across cells, so only
# the SUT (the server we are benchmarking) varies between cells. This isolates
# server-side CPU/memory/throughput differences.
#
# Output: a JSON line summary of {requests, error_count, p50_ms, p95_ms, p99_ms, throughput_req_s, throughput_mb_s}
#
# Args:
#   start_xray_client CONFIG_NAME LOG_PATH -> echo xray client PID
#   start_target_server LOG_PATH -> echo target PID (listens on 18081)
#   run_vegeta DURATION RATE OUT_JSON -> blocks until done, writes summary
set -uo pipefail

# Resolve paths
LOAD_LIB_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
COMP_DIR="$(realpath "$LOAD_LIB_DIR/..")"
TOOLS_BIN="${TOOLS_BIN:-$(realpath "$COMP_DIR/../tools/bin")}"
XRAY_BIN="${XRAY_BIN:-$TOOLS_BIN/xray}"
SINGBOX_BIN="${SINGBOX_BIN:-/usr/sbin/sing-box}"
VEGETA_BIN="${VEGETA_BIN:-$TOOLS_BIN/vegeta}"
CLIENT_CONFIGS_DIR="$COMP_DIR/client-configs"

# Constants for the load topology
CLIENT_SOCKS_PORT="${CLIENT_SOCKS_PORT:-18080}"
TARGET_HTTP_PORT="${TARGET_HTTP_PORT:-18081}"

# _wait_for_port comes from server.sh (TCP/UDP aware); both files are sourced
# by matrix.sh. If load.sh is sourced standalone, source server.sh first.

start_xray_client() {
    local config_name="$1"
    local log_path="$2"
    local cfg="$CLIENT_CONFIGS_DIR/$config_name.json"
    if [ ! -f "$cfg" ]; then
        echo "[load] no xray client config for $config_name" >&2
        return 2
    fi
    [ -x "$XRAY_BIN" ] || { echo "[load] xray binary missing: $XRAY_BIN" >&2; return 1; }
    cfg="$(_prepare_xray_client_config "$cfg")" || return 1
    "$XRAY_BIN" run -c "$cfg" >"$log_path" 2>&1 &
    local pid=$!
    if ! _wait_for_port "$CLIENT_SOCKS_PORT"; then
        kill "$pid" 2>/dev/null || true
        echo "[load] xray client did not bind SOCKS5 $CLIENT_SOCKS_PORT (see $log_path)" >&2
        return 1
    fi
    echo "$pid"
}

# xray 26.5.9 removed `allowInsecure`; clients must instead pin the server cert
# via `pinnedPeerCertSha256`. Compute the pin from the shared bench cert (set up
# by lib/certs.sh) and rewrite the user-checked-in client config into a tmp copy.
# Falls back to passthrough if there is no `tlsSettings.allowInsecure` to rewrite.
_prepare_xray_client_config() {
    local src="$1"
    local out
    out="$(mktemp -t "xray-client-XXXXXX.json")"
    local pin=""
    if command -v bench_cert_pin_sha256 >/dev/null 2>&1; then
        pin="$(bench_cert_pin_sha256 2>/dev/null || true)"
    fi
    if [ -n "$pin" ]; then
        # Drop allowInsecure (legacy), pin the cert SHA256 instead. xray 26.5.9
        # accepts pinnedPeerCertSha256 as a string (not array).
        jq --arg pin "$pin" '
          (.. | objects | select(has("allowInsecure"))) |= (
            del(.allowInsecure)
            | .pinnedPeerCertSha256 = $pin
          )
        ' "$src" > "$out" || { cp "$src" "$out"; }
    else
        cp "$src" "$out"
    fi
    echo "$out"
}

start_singbox_client() {
    local config_name="$1"
    local log_path="$2"
    local cfg="$CLIENT_CONFIGS_DIR/$config_name.json"
    if [ ! -f "$cfg" ]; then
        echo "[load] no sing-box client config for $config_name" >&2
        return 2
    fi
    [ -x "$SINGBOX_BIN" ] || { echo "[load] sing-box binary missing: $SINGBOX_BIN" >&2; return 1; }
    "$SINGBOX_BIN" run -c "$cfg" >"$log_path" 2>&1 &
    local pid=$!
    if ! _wait_for_port "$CLIENT_SOCKS_PORT"; then
        kill "$pid" 2>/dev/null || true
        echo "[load] sing-box client did not bind SOCKS5 $CLIENT_SOCKS_PORT (see $log_path)" >&2
        return 1
    fi
    echo "$pid"
}

# Dispatcher: pick the right client binary for a given protocol.
# xray-core lacks shadowtls, hysteria2, and anytls client outbounds, so those
# use sing-box. All other protocols default to xray (consistent with the
# original constant-client design).
start_client_for() {
    local config_name="$1"
    local log_path="$2"
    case "$config_name" in
        shadowtls|hysteria2|anytls-tcp|anytls)
            start_singbox_client "$config_name" "$log_path"
            ;;
        *)
            start_xray_client "$config_name" "$log_path"
            ;;
    esac
}

# Local HTTP target: serves deterministic byte payloads at /bytes/N
# and a small /api/echo. Constant payload keeps measurement stable.
#
# Python script written to a tmp file (not heredoc to background process)
# so the backgrounded child fully detaches from this function's stdout —
# otherwise command substitution `$(start_target_server)` hangs waiting
# for the python's stdout fd to close.
start_target_server() {
    local log_path="$1"
    local script
    script="$(mktemp -t "wrongsv-bench-target-XXXXXX.py")"
    cat > "$script" <<'PYEOF'
import http.server, os, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/bytes/"):
            try:
                n = int(self.path.rsplit("/", 1)[1])
            except ValueError:
                n = 1024
            n = max(0, min(n, 16 * 1024 * 1024))
            body = b"x" * n
        elif self.path == "/api/echo":
            body = b'{"ok":true}'
        else:
            body = b"OK"
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a, **kw):
        pass
class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True
port = int(os.environ["PORT"])
with TS(("127.0.0.1", port), H) as s:
    s.serve_forever()
PYEOF
    PORT="$TARGET_HTTP_PORT" python3 "$script" >"$log_path" 2>&1 </dev/null &
    local pid=$!
    if ! _wait_for_port "$TARGET_HTTP_PORT"; then
        kill "$pid" 2>/dev/null || true
        rm -f "$script"
        echo "[load] target HTTP server did not bind $TARGET_HTTP_PORT" >&2
        return 1
    fi
    echo "$pid"
}

# run_vegeta DURATION_SEC RATE_RPS PAYLOAD_BYTES OUT_JSON LOG_PATH
# Drives `rate` requests per second of GET /bytes/PAYLOAD_BYTES, through
# the SOCKS5 client. Uses vegeta in HTTP_PROXY mode pointed at the xray client.
# Returns a JSON line with summary stats.
run_vegeta() {
    local duration_sec="$1"
    local rate="$2"
    local payload="$3"
    local out_json="$4"
    local log_path="$5"

    [ -x "$VEGETA_BIN" ] || { echo "[load] vegeta missing: $VEGETA_BIN" >&2; return 1; }

    # Vegeta target: hit the local HTTP target *via the SOCKS5 client*.
    # vegeta supports HTTPS_PROXY/HTTP_PROXY env, but only HTTP and SOCKS5 are common.
    # Use socks5h scheme so DNS is resolved on the proxy side. Vegeta uses Go's net/http
    # which respects {ALL_,HTTPS_,HTTP_}PROXY; socks5 is supported by Go natively.
    local report_bin
    report_bin="$VEGETA_BIN"

    # Build targets file inline.
    local targets
    targets="$(mktemp)"
    echo "GET http://127.0.0.1:${TARGET_HTTP_PORT}/bytes/${payload}" > "$targets"

    # vegeta attack -> binary results -> vegeta report (json)
    local bin
    bin="$(mktemp)"
    HTTPS_PROXY="socks5h://127.0.0.1:${CLIENT_SOCKS_PORT}" \
    HTTP_PROXY="socks5h://127.0.0.1:${CLIENT_SOCKS_PORT}" \
    ALL_PROXY="socks5h://127.0.0.1:${CLIENT_SOCKS_PORT}" \
        "$VEGETA_BIN" attack \
            -targets="$targets" \
            -rate="${rate}/1s" \
            -duration="${duration_sec}s" \
            -timeout=10s \
            -insecure \
            -output="$bin" \
            > "$log_path" 2>&1 || true

    # Generate JSON report
    "$VEGETA_BIN" report -type=json "$bin" > "$out_json" 2>>"$log_path" || {
        echo "[load] vegeta report failed (see $log_path)" >&2
        rm -f "$targets" "$bin"
        return 1
    }
    rm -f "$targets" "$bin"
}

# Direct invocation for ad-hoc use.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        start_xray_client) shift; start_xray_client "$@" ;;
        start_target)      shift; start_target_server "$@" ;;
        run_vegeta)        shift; run_vegeta "$@" ;;
        *) echo "Usage: $0 {start_xray_client|start_target|run_vegeta} ARGS..." >&2; exit 1 ;;
    esac
fi
