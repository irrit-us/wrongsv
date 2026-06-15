#!/usr/bin/env bash
# server.sh — start/stop a proxy server of a given kind on a given config.
#
# Supported kinds: wrongsv, xray, sing-box, mihomo
#
# For wrongsv: uses the wrongsv TOML config directly. The bench runner injects
# a localhost listen address into a tmp copy so it doesn't try to bind 0.0.0.0:443.
#
# For xray/sing-box/mihomo: uses configs from server-configs/{kind}/{name}.{json|yaml}.
# Returns exit code 2 if the kind doesn't have a config for that protocol.
set -uo pipefail

# Resolve binary paths
WRONGSV_BIN="${WRONGSV_BIN:-$(realpath "$(dirname "${BASH_SOURCE[0]}")/../../../..")/target/release/wrongsv}"
XRAY_BIN="${XRAY_BIN:-/home/johnsilver/focus/wrongsv/wrongsv/benches/traffic/tools/bin/xray}"
SINGBOX_BIN="${SINGBOX_BIN:-/usr/sbin/sing-box}"
MIHOMO_BIN="${MIHOMO_BIN:-/home/johnsilver/focus/wrongsv/test-deploy/mihomo}"

SERVER_CONFIGS_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")/..")/server-configs"
WRONGSV_CONFIGS_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")/../../../..")/configs"

# Verify a 127.0.0.1:$port listener is up. Default is TCP via /dev/tcp; pass
# "udp" as $2 for UDP protocols (KCP, Hysteria2) which never bind TCP.
_wait_for_port() {
    local port="$1"
    local proto="${2:-tcp}"
    local deadline=$(( $(date +%s) + 15 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ "$proto" = "udp" ]; then
            ss -uln 2>/dev/null | awk -v p=":$port\$" '$4 ~ p {found=1} END {exit !found}' && return 0
        else
            if (echo > "/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
                return 0
            fi
        fi
        sleep 0.2
    done
    return 1
}

# Pick TCP vs UDP based on config name. KCP and Hysteria2 are UDP-only.
_proto_for_config() {
    case "$1" in
        kcp|hysteria2) echo udp ;;
        *) echo tcp ;;
    esac
}

# Rewrite wrongsv config to listen on 127.0.0.1 instead of 0.0.0.0,
# and — for TLS-bearing configs — inject the shared bench cert+key as
# inline PEM strings under the appropriate section. Without this, wrongsv
# self-generates a different cert per run, breaking the xray client's
# pinnedPeerCertSha256 (which is computed from the shared cert).
# Writes to a tmp file and echoes its path.
_prepare_wrongsv_config() {
    local src="$1"
    local port="$2"
    local config_name="$3"
    local out
    out="$(mktemp -t "wrongsv-bench-XXXXXX.toml")"
    # Section header that takes `certificate`/`key` fields, by config family.
    local section=""
    case "$config_name" in
        tls-vision)        section="[tls]" ;;
        trojan-tls)        section="[trojan]" ;;
        anytls-*|anytls)   section="[anytls]" ;;
    esac
    BENCH_CERT_PATH_VAL="${BENCH_CERT_PATH:-/tmp/wrongsv-bench-cert.pem}" \
    BENCH_KEY_PATH_VAL="${BENCH_KEY_PATH:-/tmp/wrongsv-bench-key.pem}" \
    SRC="$src" OUT="$out" PORT="$port" SECTION="$section" \
    python3 - <<'PYEOF'
import os, pathlib
src     = os.environ["SRC"]
out     = os.environ["OUT"]
port    = os.environ["PORT"]
section = os.environ["SECTION"]
cert_p  = os.environ["BENCH_CERT_PATH_VAL"]
key_p   = os.environ["BENCH_KEY_PATH_VAL"]

lines = pathlib.Path(src).read_text().splitlines()
out_lines = []
for line in lines:
    if line.startswith("listen = "):
        out_lines.append(f'listen = "127.0.0.1:{port}"')
        continue
    out_lines.append(line)
    if section and line.strip() == section:
        cert = pathlib.Path(cert_p).read_text().rstrip("\n")
        key  = pathlib.Path(key_p).read_text().rstrip("\n")
        out_lines.append(f'certificate = """\n{cert}\n"""')
        out_lines.append(f'key = """\n{key}\n"""')

pathlib.Path(out).write_text("\n".join(out_lines) + "\n")
PYEOF
    echo "$out"
}

# Resolve listen port from a competitor config file by reading the canonical fields.
_competitor_port() {
    local kind="$1"
    local cfg="$2"
    case "$kind" in
        xray|sing-box)
            python3 -c "import json,sys; d=json.load(open('$cfg')); print(d['inbounds'][0].get('port') or d['inbounds'][0].get('listen_port'))"
            ;;
        mihomo)
            python3 -c "import yaml,sys; d=yaml.safe_load(open('$cfg')); print(d['listeners'][0]['port'])"
            ;;
    esac
}

# start_server KIND CONFIG_NAME LOG_PATH -> echoes PID on success, exits 2 if unsupported.
start_server() {
    local kind="$1"
    local config_name="$2"   # e.g. "reality-vision"
    local log_path="$3"

    case "$kind" in
        wrongsv)
            local src="$WRONGSV_CONFIGS_DIR/$config_name.toml"
            if [ ! -f "$src" ]; then
                echo "[server] wrongsv config missing: $src" >&2
                return 2
            fi
            if [ ! -x "$WRONGSV_BIN" ]; then
                echo "[server] wrongsv binary missing: $WRONGSV_BIN — run cargo build --release" >&2
                return 1
            fi
            # Resolve port: use protocol-family default (matches competitor configs).
            local port
            case "$config_name" in
                shadowsocks-2022|shadowsocks-aead) port=18388 ;;
                *)                                 port=18443 ;;
            esac
            local cfg
            cfg="$(_prepare_wrongsv_config "$src" "$port" "$config_name")"
            "$WRONGSV_BIN" --config "$cfg" >"$log_path" 2>&1 &
            local pid=$!
            if ! _wait_for_port "$port" "$(_proto_for_config "$config_name")"; then
                kill "$pid" 2>/dev/null || true
                echo "[server] wrongsv did not bind 127.0.0.1:$port (see $log_path)" >&2
                return 1
            fi
            echo "$pid"
            ;;
        xray)
            local cfg="$SERVER_CONFIGS_DIR/xray/$config_name.json"
            [ -f "$cfg" ] || { echo "[server] no xray config for $config_name" >&2; return 2; }
            [ -x "$XRAY_BIN" ] || { echo "[server] xray binary missing: $XRAY_BIN" >&2; return 1; }
            local port
            port="$(_competitor_port xray "$cfg")"
            "$XRAY_BIN" run -c "$cfg" >"$log_path" 2>&1 &
            local pid=$!
            if ! _wait_for_port "$port" "$(_proto_for_config "$config_name")"; then
                kill "$pid" 2>/dev/null || true
                echo "[server] xray did not bind 127.0.0.1:$port (see $log_path)" >&2
                return 1
            fi
            echo "$pid"
            ;;
        sing-box)
            local cfg="$SERVER_CONFIGS_DIR/sing-box/$config_name.json"
            [ -f "$cfg" ] || { echo "[server] no sing-box config for $config_name" >&2; return 2; }
            [ -x "$SINGBOX_BIN" ] || { echo "[server] sing-box binary missing: $SINGBOX_BIN" >&2; return 1; }
            local port
            port="$(_competitor_port sing-box "$cfg")"
            "$SINGBOX_BIN" run -c "$cfg" >"$log_path" 2>&1 &
            local pid=$!
            if ! _wait_for_port "$port" "$(_proto_for_config "$config_name")"; then
                kill "$pid" 2>/dev/null || true
                echo "[server] sing-box did not bind 127.0.0.1:$port (see $log_path)" >&2
                return 1
            fi
            echo "$pid"
            ;;
        mihomo)
            local cfg="$SERVER_CONFIGS_DIR/mihomo/$config_name.yaml"
            [ -f "$cfg" ] || { echo "[server] no mihomo config for $config_name" >&2; return 2; }
            [ -x "$MIHOMO_BIN" ] || { echo "[server] mihomo binary missing: $MIHOMO_BIN" >&2; return 1; }
            local port
            port="$(_competitor_port mihomo "$cfg")"
            # mihomo wants config in a directory; create one.
            # mihomo 1.19.x restricts file paths read by config to under HOME
            # or the config dir (SAFE_PATHS is ignored in this build), so we
            # copy the shared bench cert+key into the cfg dir and the YAMLs
            # reference them via relative paths (./cert.pem, ./key.pem).
            local cfg_dir
            cfg_dir="$(mktemp -d -t "mihomo-bench-XXXXXX")"
            cp "$cfg" "$cfg_dir/config.yaml"
            local bench_cert="${BENCH_CERT_PATH:-/tmp/wrongsv-bench-cert.pem}"
            local bench_key="${BENCH_KEY_PATH:-/tmp/wrongsv-bench-key.pem}"
            [ -f "$bench_cert" ] && cp "$bench_cert" "$cfg_dir/cert.pem"
            [ -f "$bench_key" ]  && cp "$bench_key"  "$cfg_dir/key.pem"
            "$MIHOMO_BIN" -d "$cfg_dir" >"$log_path" 2>&1 &
            local pid=$!
            if ! _wait_for_port "$port" "$(_proto_for_config "$config_name")"; then
                kill "$pid" 2>/dev/null || true
                echo "[server] mihomo did not bind 127.0.0.1:$port (see $log_path)" >&2
                return 1
            fi
            echo "$pid"
            ;;
        *)
            echo "[server] unknown kind: $kind" >&2
            return 1
            ;;
    esac
}

stop_server() {
    local pid="$1"
    [ -z "$pid" ] && return 0
    kill "$pid" 2>/dev/null || true
    local deadline=$(( $(date +%s) + 5 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.1
    done
    kill -9 "$pid" 2>/dev/null || true
}

# Direct invocation: ./server.sh start KIND CONFIG_NAME LOG | ./server.sh stop PID
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        start) shift; start_server "$@" ;;
        stop)  shift; stop_server "$@" ;;
        *)     echo "Usage: $0 start KIND CONFIG_NAME LOG | $0 stop PID" >&2; exit 1 ;;
    esac
fi
