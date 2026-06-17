#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"
FAKEBIN="$TMPDIR/fakebin"
SSH_HOME="$TMPDIR/home"
REMOTE_ROOT="$TMPDIR/remote-root"
OUTPUT_FILE="$TMPDIR/deploy-output.log"
SSHD_LOG="$TMPDIR/sshd.log"
REMOTE_DIR="$REMOTE_ROOT/wrongsv"
CONFIG_FILE="$TMPDIR/config.toml"
SECRET_VALUE="deploy-real-sshd-secret"
REAL_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
REAL_RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
REAL_SSH_BIN="$(command -v ssh)"
REAL_SCP_BIN="$(command -v scp)"
REAL_SSHD_BIN="$(command -v sshd)"

cleanup() {
  if [[ -n "${REMOTE_WRONGSV_PID:-}" ]]; then
    kill "$REMOTE_WRONGSV_PID" 2>/dev/null || true
    wait "$REMOTE_WRONGSV_PID" 2>/dev/null || true
  fi
  if [[ -n "${SSHD_PID:-}" ]]; then
    kill "$SSHD_PID" 2>/dev/null || true
    wait "$SSHD_PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

mkdir -p "$SSH_HOME/.ssh" "$REMOTE_ROOT" "$FAKEBIN"

ssh-keygen -q -t ed25519 -N '' -f "$SSH_HOME/.ssh/id_ed25519" >/dev/null
cp "$SSH_HOME/.ssh/id_ed25519.pub" "$SSH_HOME/.ssh/authorized_keys"
chmod 700 "$SSH_HOME/.ssh"
chmod 600 "$SSH_HOME/.ssh/authorized_keys"

ssh-keygen -q -t ed25519 -N '' -f "$TMPDIR/ssh_host_ed25519_key" >/dev/null

SSH_PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

LISTEN_PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

cat >"$TMPDIR/sshd_config" <<EOF
Port ${SSH_PORT}
ListenAddress 127.0.0.1
HostKey ${TMPDIR}/ssh_host_ed25519_key
AuthorizedKeysFile ${SSH_HOME}/.ssh/authorized_keys
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
PermitRootLogin no
AllowUsers $(whoami)
PubkeyAuthentication yes
StrictModes no
LogLevel VERBOSE
PidFile ${TMPDIR}/sshd.pid
Subsystem sftp internal-sftp
EOF

cat >"$TMPDIR/ssh_client_config" <<EOF
Host mockdeploy
  HostName 127.0.0.1
  Port ${SSH_PORT}
  User $(whoami)
  IdentityFile ${SSH_HOME}/.ssh/id_ed25519
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
EOF
chmod 600 "$TMPDIR/ssh_client_config"

cat >"$FAKEBIN/ssh" <<EOF
#!/usr/bin/env bash
exec "$REAL_SSH_BIN" -F "$TMPDIR/ssh_client_config" "\$@"
EOF
chmod +x "$FAKEBIN/ssh"

cat >"$FAKEBIN/scp" <<EOF
#!/usr/bin/env bash
exec "$REAL_SCP_BIN" -F "$TMPDIR/ssh_client_config" "\$@"
EOF
chmod +x "$FAKEBIN/scp"

cat >"$CONFIG_FILE" <<EOF
listen = "127.0.0.1:${LISTEN_PORT}"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"
flow = "xtls-rprx-vision"

[anytls]
password = "${SECRET_VALUE}"
dest = "127.0.0.1:8080"
EOF

"$REAL_SSHD_BIN" -D -f "$TMPDIR/sshd_config" -E "$SSHD_LOG" &
SSHD_PID=$!

for _ in $(seq 1 50); do
  if "$REAL_SSH_BIN" -F "$TMPDIR/ssh_client_config" mockdeploy 'echo READY' >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

set +e
PATH="$FAKEBIN:$PATH" \
CARGO_HOME="$REAL_CARGO_HOME" \
RUSTUP_HOME="$REAL_RUSTUP_HOME" \
"$ROOT/scripts/deploy-remote.sh" mockdeploy \
  --config "$CONFIG_FILE" \
  --remote-dir "$REMOTE_DIR" \
  --service wrongsv-mock \
  --target x86_64-unknown-linux-gnu \
  --profile debug \
  --server-host 127.0.0.1 \
  --servername localhost \
  --no-client-configs >"$OUTPUT_FILE" 2>&1
status=$?
set -e

if [[ "$status" -ne 0 ]]; then
  cat "$OUTPUT_FILE" >&2 || true
  cat "$SSHD_LOG" >&2 || true
  exit "$status"
fi

[[ -f "$REMOTE_DIR/config.toml" ]]
[[ -f "$REMOTE_DIR/wrongsv.log" ]]
grep -F "$SECRET_VALUE" "$REMOTE_DIR/config.toml" >/dev/null

if grep -F "$SECRET_VALUE" "$OUTPUT_FILE" "$REMOTE_DIR/wrongsv.log" "$SSHD_LOG"; then
  echo "secret leaked into deploy output or remote logs" >&2
  exit 1
fi

REMOTE_WRONGSV_PID="$("$REAL_SSH_BIN" -F "$TMPDIR/ssh_client_config" mockdeploy "pgrep -f '$REMOTE_DIR/wrongsv --config $REMOTE_DIR/config.toml' | head -n 1")"
[[ -n "$REMOTE_WRONGSV_PID" ]]
