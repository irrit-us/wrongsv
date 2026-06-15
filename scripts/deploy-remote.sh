#!/usr/bin/env bash
# Deploy wrongsv to an SSH host using a local TOML config, then run a TCP
# connectivity check against the listener port.
#
# Workflow:
#   1. cross-compile wrongsv (musl)
#   2. stop the remote service (systemd unit if present, else pkill)
#   3. scp the binary and the local CONFIG onto the host as the canonical
#      $REMOTE_DIR/wrongsv and $REMOTE_DIR/config.toml
#   4. verify with sha256 that the binary the remote will run is the one we
#      just built — a TCP-port check alone is not enough, since a stale daemon
#      could still answer on the same port
#   5. start the service back up (systemd if available, else nohup+setsid)
#   6. TCP-connect to $LISTEN_PORT to confirm the new instance is accepting
#
# Only argument: the SSH host (alias or hostname). Everything else is
# hardcoded below — edit the script to change which config gets deployed.
#
# Usage:  ./scripts/deploy-remote.sh <ssh-host>

set -euo pipefail

# --- hardcoded params ---------------------------------------------------
CONFIG="configs/tls-vision.toml"
LISTEN_PORT=443                   # must match the `listen` line in CONFIG
REMOTE_DIR=/opt/wrongsv
SERVICE=wrongsv                   # systemd unit name, used only if present
TARGET="x86_64-unknown-linux-musl"
PROFILE=release
# ------------------------------------------------------------------------

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <ssh-host>" >&2
  exit 1
fi
HOST="$1"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ -f "$CONFIG" ]] || { echo "missing config: $CONFIG" >&2; exit 1; }

echo "==> building wrongsv for $TARGET"
cargo build --"$PROFILE" --target "$TARGET" -p wrongsv --bin wrongsv

BIN="$ROOT/target/$TARGET/$PROFILE/wrongsv"
[[ -x "$BIN" ]] || { echo "missing build artifact: $BIN" >&2; exit 1; }

REMOTE_IP="$(ssh -G "$HOST" | awk '$1=="hostname"{print $2; exit}')"
[[ -n "$REMOTE_IP" ]] || { echo "could not resolve $HOST via ssh -G" >&2; exit 1; }

LOCAL_SUM="$(sha256sum "$BIN" | awk '{print $1}')"

echo "==> stopping remote $SERVICE (or any stray wrongsv processes)"
ssh "$HOST" "mkdir -p $REMOTE_DIR; \
  if systemctl list-unit-files $SERVICE.service >/dev/null 2>&1 \
     && systemctl cat $SERVICE >/dev/null 2>&1; then \
    systemctl stop $SERVICE || true; \
  fi; \
  pkill -x wrongsv || true; \
  for _ in 1 2 3 4 5; do pgrep -x wrongsv >/dev/null || break; sleep 0.5; done; \
  rm -f $REMOTE_DIR/wrongsv"

echo "==> shipping wrongsv + $(basename "$CONFIG") as config.toml"
scp -q "$BIN" "$HOST:$REMOTE_DIR/wrongsv"
scp -q "$CONFIG" "$HOST:$REMOTE_DIR/config.toml"
ssh "$HOST" "chmod +x $REMOTE_DIR/wrongsv"

REMOTE_SUM="$(ssh "$HOST" "sha256sum $REMOTE_DIR/wrongsv" | awk '{print $1}')"
if [[ "$LOCAL_SUM" != "$REMOTE_SUM" ]]; then
  echo "==> FAIL: sha256 mismatch after upload" >&2
  echo "    local:  $LOCAL_SUM" >&2
  echo "    remote: $REMOTE_SUM" >&2
  exit 1
fi
echo "    binary sha256 verified: ${LOCAL_SUM:0:12}…"

echo "==> starting remote service"
ssh "$HOST" "if systemctl list-unit-files $SERVICE.service >/dev/null 2>&1 \
                && systemctl cat $SERVICE >/dev/null 2>&1; then \
    systemctl start $SERVICE; \
  else \
    cd $REMOTE_DIR && setsid -f nohup ./wrongsv --config ./config.toml \
      >wrongsv.log 2>&1 </dev/null; \
  fi"

echo "==> connectivity check: TCP connect $HOST:$LISTEN_PORT"
up=0
for _ in $(seq 1 30); do
  if (echo > /dev/tcp/"$REMOTE_IP"/"$LISTEN_PORT") 2>/dev/null; then
    up=1; break
  fi
  sleep 0.5
done

if [[ "$up" -eq 1 ]]; then
  echo "==> OK: $HOST:$LISTEN_PORT accepting TCP connections"
else
  echo "==> FAIL: $HOST:$LISTEN_PORT not reachable — recent log tail:" >&2
  ssh "$HOST" "journalctl -u $SERVICE -n 40 --no-pager 2>/dev/null \
    || tail -n 40 $REMOTE_DIR/wrongsv.log" >&2 || true
  exit 1
fi
