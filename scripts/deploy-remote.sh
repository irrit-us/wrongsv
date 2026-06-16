#!/usr/bin/env bash
# Deploy wrongsv to an SSH host using a selected main TOML config, then generate
# client files validated against wrongsv-external-tests capability metadata.

set -euo pipefail

CONFIG="configs/tls-vision.toml"
REMOTE_DIR="/opt/wrongsv"
SERVICE="wrongsv"
TARGET="x86_64-unknown-linux-musl"
PROFILE="release"
CLIENTS="all"
CLIENT_NAME="wrongsv"
SERVER_HOST=""
SERVERNAME=""
OUTPUT_DIR=""
EXTERNAL_TESTS_ROOT=""
GENERATE_CLIENTS=1

usage() {
  cat >&2 <<'EOF'
usage: scripts/deploy-remote.sh <ssh-host> [options]

Options:
  --config <path>              main wrongsv TOML config to deploy
  --remote-dir <path>          remote install dir (default: /opt/wrongsv)
  --service <name>             systemd service name (default: wrongsv)
  --target <triple>            cargo target (default: x86_64-unknown-linux-musl)
  --profile <profile>          cargo profile (default: release)
  --server-host <host>         server address written to client configs
  --servername <name>          TLS SNI/servername written to client configs
  --client-name <name>         generated node name prefix (default: wrongsv)
  --clients <csv|all>          clients to generate (default: all)
  --output-dir <path>          local generated client config dir
  --external-tests-root <path> wrongsv-external-tests dir
  --no-client-configs          deploy only
  -h, --help                   show this help

The generated client set is filtered by wrongsv-external-tests/e2e-harness
capabilities. FlClash AnyTLS generation is enabled when anytls_tcp is declared
runnable in that matrix.
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

HOST=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --config)
      CONFIG="$2"
      shift 2
      ;;
    --remote-dir)
      REMOTE_DIR="$2"
      shift 2
      ;;
    --service)
      SERVICE="$2"
      shift 2
      ;;
    --target)
      TARGET="$2"
      shift 2
      ;;
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --server-host)
      SERVER_HOST="$2"
      shift 2
      ;;
    --servername)
      SERVERNAME="$2"
      shift 2
      ;;
    --client-name)
      CLIENT_NAME="$2"
      shift 2
      ;;
    --clients)
      CLIENTS="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --external-tests-root)
      EXTERNAL_TESTS_ROOT="$2"
      shift 2
      ;;
    --no-client-configs)
      GENERATE_CLIENTS=0
      shift
      ;;
    --*)
      echo "unknown option: $1" >&2
      usage
      exit 1
      ;;
    *)
      if [[ -z "$HOST" ]]; then
        HOST="$1"
      elif [[ "$CONFIG" == "configs/tls-vision.toml" ]]; then
        CONFIG="$1"
      else
        echo "unexpected argument: $1" >&2
        usage
        exit 1
      fi
      shift
      ;;
  esac
done

if [[ -z "$HOST" ]]; then
  echo "missing ssh host" >&2
  usage
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f "$CONFIG" ]]; then
  echo "missing config: $CONFIG" >&2
  exit 1
fi

if [[ -z "$EXTERNAL_TESTS_ROOT" ]]; then
  EXTERNAL_TESTS_ROOT="$(cd "$ROOT/.." && pwd)/wrongsv-external-tests"
fi
if [[ "$GENERATE_CLIENTS" -eq 1 && ! -d "$EXTERNAL_TESTS_ROOT/e2e-harness" ]]; then
  echo "missing wrongsv-external-tests e2e harness: $EXTERNAL_TESTS_ROOT" >&2
  exit 1
fi

REMOTE_HOSTNAME="$(ssh -G "$HOST" | awk '$1=="hostname"{print $2; exit}')"
if [[ -z "$REMOTE_HOSTNAME" ]]; then
  echo "could not resolve $HOST via ssh -G" >&2
  exit 1
fi
if [[ -z "$SERVER_HOST" ]]; then
  SERVER_HOST="$REMOTE_HOSTNAME"
fi
if [[ -z "$SERVERNAME" ]]; then
  SERVERNAME="$(python3 - "$CONFIG" "$SERVER_HOST" <<'PY'
import sys
import tomllib

config_path, server_host = sys.argv[1], sys.argv[2]
with open(config_path, "rb") as fh:
    cfg = tomllib.load(fh)
dest = (cfg.get("reality") or {}).get("dest")
if dest:
    print(dest.rsplit(":", 1)[0])
else:
    print("localhost" if server_host.replace(".", "").isdigit() else server_host)
PY
)"
fi
if [[ -z "$OUTPUT_DIR" ]]; then
  safe_host="${HOST//[^A-Za-z0-9_.-]/_}"
  OUTPUT_DIR="$ROOT/deploy-output/${safe_host}-$(date -u +%Y%m%dT%H%M%SZ)"
fi

echo "==> building wrongsv for $TARGET ($PROFILE)"
BUILD_ARGS=(build --target "$TARGET" -p wrongsv --bin wrongsv)
ARTIFACT_PROFILE="$PROFILE"
case "$PROFILE" in
  release)
    BUILD_ARGS+=(--release)
    ;;
  debug|dev)
    ARTIFACT_PROFILE="debug"
    ;;
  *)
    BUILD_ARGS+=(--profile "$PROFILE")
    ;;
esac
cargo "${BUILD_ARGS[@]}"

BIN="$ROOT/target/$TARGET/$ARTIFACT_PROFILE/wrongsv"
if [[ ! -x "$BIN" ]]; then
  echo "missing build artifact: $BIN" >&2
  exit 1
fi

LISTEN_PORT="$(python3 - "$CONFIG" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as fh:
    listen = tomllib.load(fh).get("listen", "")
if ":" not in listen:
    raise SystemExit("config listen is missing a port")
print(listen.rsplit(":", 1)[1].strip("]"))
PY
)"

DIAGNOSTICS="$("$BIN" \
  --config "$CONFIG" \
  --print-endpoint-diagnostics \
  --server-host "$SERVER_HOST" \
  --servername "$SERVERNAME")"
BASE_CARRIERS="$(python3 -c 'import json,sys; print(",".join(json.load(sys.stdin)["resolved"]["base_carriers"]))' <<<"$DIAGNOSTICS")"

LOCAL_SUM="$(sha256sum "$BIN" | awk '{print $1}')"

echo "==> stopping remote $SERVICE (or stray wrongsv processes)"
ssh "$HOST" "mkdir -p '$REMOTE_DIR'; \
  if systemctl list-unit-files '$SERVICE.service' >/dev/null 2>&1 \
     && systemctl cat '$SERVICE' >/dev/null 2>&1; then \
    systemctl stop '$SERVICE' || true; \
  fi; \
  pkill -x wrongsv || true; \
  for _ in 1 2 3 4 5; do pgrep -x wrongsv >/dev/null || break; sleep 0.5; done; \
  rm -f '$REMOTE_DIR/wrongsv'"

echo "==> shipping wrongsv + $(basename "$CONFIG") as config.toml"
scp -q "$BIN" "$HOST:$REMOTE_DIR/wrongsv"
scp -q "$CONFIG" "$HOST:$REMOTE_DIR/config.toml"
ssh "$HOST" "chmod +x '$REMOTE_DIR/wrongsv'; chmod 600 '$REMOTE_DIR/config.toml'"

REMOTE_SUM="$(ssh "$HOST" "sha256sum '$REMOTE_DIR/wrongsv'" | awk '{print $1}')"
if [[ "$LOCAL_SUM" != "$REMOTE_SUM" ]]; then
  echo "==> FAIL: sha256 mismatch after upload" >&2
  echo "    local:  $LOCAL_SUM" >&2
  echo "    remote: $REMOTE_SUM" >&2
  exit 1
fi
echo "    binary sha256 verified: ${LOCAL_SUM:0:12}..."

echo "==> starting remote service"
ssh "$HOST" "if systemctl list-unit-files '$SERVICE.service' >/dev/null 2>&1 \
                && systemctl cat '$SERVICE' >/dev/null 2>&1; then \
    systemctl start '$SERVICE'; \
  else \
    cd '$REMOTE_DIR' && setsid -f nohup ./wrongsv --config ./config.toml \
      >wrongsv.log 2>&1 </dev/null; \
  fi"

if [[ ",$BASE_CARRIERS," == *",tcp,"* ]]; then
  echo "==> connectivity check: TCP connect $SERVER_HOST:$LISTEN_PORT"
  up=0
  for _ in $(seq 1 30); do
    if (echo > /dev/tcp/"$SERVER_HOST"/"$LISTEN_PORT") 2>/dev/null; then
      up=1
      break
    fi
    sleep 0.5
  done
  if [[ "$up" -ne 1 ]]; then
    echo "==> FAIL: $SERVER_HOST:$LISTEN_PORT not reachable; recent log tail:" >&2
    ssh "$HOST" "journalctl -u '$SERVICE' -n 40 --no-pager 2>/dev/null \
      || tail -n 40 '$REMOTE_DIR/wrongsv.log'" >&2 || true
    exit 1
  fi
  echo "==> OK: $SERVER_HOST:$LISTEN_PORT accepting TCP connections"
else
  echo "==> UDP-only listener; checking remote wrongsv process"
  ssh "$HOST" "pgrep -x wrongsv >/dev/null || systemctl is-active --quiet '$SERVICE'"
  echo "==> OK: remote wrongsv process is active"
fi

if [[ "$GENERATE_CLIENTS" -eq 1 ]]; then
  echo "==> generating capability-validated client configs"
  node "$ROOT/scripts/generate-client-configs.js" \
    --wrongsv-bin "$BIN" \
    --config "$CONFIG" \
    --external-tests-root "$EXTERNAL_TESTS_ROOT" \
    --output-dir "$OUTPUT_DIR" \
    --server-host "$SERVER_HOST" \
    --servername "$SERVERNAME" \
    --client-name "$CLIENT_NAME" \
    --clients "$CLIENTS"
  echo "==> client configs written to $OUTPUT_DIR"
fi

echo "==> done"
