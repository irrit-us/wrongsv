#!/usr/bin/env bash
# Run the full-protocol evaluator against an SSH host.
#
# Builds eval-server for musl, ships it to the remote, starts it bound to
# 0.0.0.0:19999 with the proxy pinned to 0.0.0.0:40000, then runs the local
# eval-client against it. The remote eval-server is stopped on exit.
#
# Only argument: the SSH host (alias or hostname). Everything else is
# hardcoded below — edit the script to change it.
#
# Usage:  ./scripts/eval-remote.sh <ssh-host>

set -euo pipefail

# --- hardcoded params ---------------------------------------------------
TOKEN="wrongsv-eval-fixed-token"
DURATION=5                 # seconds per protocol
LISTEN_PORT=19999
PROXY_PORT=40000
REMOTE_DIR=/opt/wrongsv-eval
PROTOCOLS=""               # empty = all 17, or e.g. "reality,tls,raw"
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

echo "==> building eval-server for $TARGET"
cargo build --"$PROFILE" --target "$TARGET" \
  -p wrongsv-evaluator-server --bin eval-server

SERVER_BIN="$ROOT/target/$TARGET/$PROFILE/eval-server"
[[ -x "$SERVER_BIN" ]] || { echo "missing build artifact: $SERVER_BIN" >&2; exit 1; }

REMOTE_IP="$(ssh -G "$HOST" | awk '$1=="hostname"{print $2; exit}')"
[[ -n "$REMOTE_IP" ]] || { echo "could not resolve $HOST via ssh -G" >&2; exit 1; }

echo "==> shipping eval-server to $HOST:$REMOTE_DIR/"
ssh "$HOST" "mkdir -p $REMOTE_DIR && pkill -x eval-server || true; \
  for _ in 1 2 3 4 5; do pgrep -x eval-server >/dev/null || break; sleep 0.5; done; \
  rm -f $REMOTE_DIR/eval-server"
scp -q "$SERVER_BIN" "$HOST:$REMOTE_DIR/eval-server"
ssh "$HOST" "chmod +x $REMOTE_DIR/eval-server"

cleanup() {
  echo "==> stopping remote eval-server"
  ssh "$HOST" "pkill -x eval-server || true" || true
}
trap cleanup EXIT

PROTO_ARG=""
[[ -n "$PROTOCOLS" ]] && PROTO_ARG="--protocols $PROTOCOLS"

echo "==> starting eval-server on $HOST (control :$LISTEN_PORT, proxy :$PROXY_PORT)"
# setsid -f puts the process in its own session and exits the parent shell
# immediately, so the SSH channel doesn't get held open by an inherited fd.
ssh "$HOST" "cd $REMOTE_DIR && setsid -f nohup ./eval-server \
  --listen 0.0.0.0:$LISTEN_PORT \
  --proxy-bind 0.0.0.0 \
  --fixed-proxy-port $PROXY_PORT \
  --duration $DURATION \
  --token $TOKEN \
  $PROTO_ARG \
  >eval-server.log 2>&1 </dev/null"

echo "==> waiting for eval-server to become ready"
# The orchestrator is one-shot: it accepts a single control-channel session,
# runs the protocol matrix, then exits. A TCP probe on $LISTEN_PORT would
# burn that session, so check via process state instead.
up=0
for _ in $(seq 1 20); do
  if ssh "$HOST" "pgrep -x eval-server >/dev/null"; then
    up=1; break
  fi
  sleep 0.5
done
if [[ "$up" -ne 1 ]]; then
  echo "eval-server did not start — recent server log:" >&2
  ssh "$HOST" "tail -n 40 $REMOTE_DIR/eval-server.log" >&2 || true
  exit 1
fi

echo "==> building eval-client locally"
cargo build --"$PROFILE" -p wrongsv-evaluator-client --bin eval-client

CLIENT_BIN="$ROOT/target/$PROFILE/eval-client"
echo "==> running eval-client against $HOST"
"$CLIENT_BIN" \
  --server "$REMOTE_IP:$LISTEN_PORT" \
  --token "$TOKEN" \
  --duration "$DURATION"

echo "==> done"
