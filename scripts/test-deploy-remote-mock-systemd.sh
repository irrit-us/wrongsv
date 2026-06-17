#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"
FAKEBIN="$TMPDIR/fakebin"
REMOTE_FS="$TMPDIR/remote-fs"
LOG_FILE="$TMPDIR/commands.log"
OUTPUT_FILE="$TMPDIR/deploy-output.log"
CONFIG_FILE="$TMPDIR/deploy-config.toml"
REMOTE_DIR="/opt/mock-wrongsv-systemd"
SERVICE="mock-wrongsv"
SECRET_VALUE="deploy-mock-systemd-secret"
UNREACHABLE_PORT=65433
REMOTE_JOURNAL_LINE="mock journalctl tail: service failed to bind listener"

cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

mkdir -p "$FAKEBIN" "$REMOTE_FS$REMOTE_DIR"

cat >"$FAKEBIN/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "cargo $*" >>"$MOCK_LOG_FILE"
target=""
profile="debug"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      target="$2"
      shift 2
      ;;
    --release)
      profile="release"
      shift
      ;;
    --profile)
      profile="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "target/$target/$profile"
cat >"target/$target/$profile/wrongsv" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"--print-endpoint-diagnostics"* ]]; then
  cat <<'JSON'
{"resolved":{"base_carriers":["tcp"]}}
JSON
  exit 0
fi
echo "unexpected fake wrongsv args: $*" >&2
exit 1
SCRIPT
chmod +x "target/$target/$profile/wrongsv"
EOF
chmod +x "$FAKEBIN/cargo"

cat >"$FAKEBIN/scp" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "scp $*" >>"$MOCK_LOG_FILE"
if [[ "${1:-}" == "-q" ]]; then
  shift
fi
src="$1"
dest="$2"
remote_path="${dest#*:}"
local_path="$MOCK_REMOTE_FS$remote_path"
mkdir -p "$(dirname "$local_path")"
cp "$src" "$local_path"
EOF
chmod +x "$FAKEBIN/scp"

cat >"$FAKEBIN/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "ssh $*" >>"$MOCK_LOG_FILE"
if [[ "${1:-}" == "-G" ]]; then
  shift
  echo "hostname 127.0.0.1"
  exit 0
fi
host="$1"
shift
cmd="$1"
if [[ "$cmd" =~ sha256sum\ \'([^\']+)\' ]]; then
  path="${BASH_REMATCH[1]}"
  sha256sum "$MOCK_REMOTE_FS$path"
  exit 0
fi
if [[ "$cmd" =~ chmod\ \+x\ \'([^\']+)\'\;\ chmod\ 600\ \'([^\']+)\' ]]; then
  chmod +x "$MOCK_REMOTE_FS${BASH_REMATCH[1]}"
  chmod 600 "$MOCK_REMOTE_FS${BASH_REMATCH[2]}"
  exit 0
fi
if [[ "$cmd" == *"journalctl -u"* ]]; then
  printf '%s\n' "$MOCK_REMOTE_JOURNAL_LINE"
  exit 0
fi
if [[ "$cmd" == *"systemctl list-unit-files"* ]] || [[ "$cmd" == *"systemctl cat"* ]] || [[ "$cmd" == *"systemctl stop"* ]] || [[ "$cmd" == *"systemctl start"* ]]; then
  exit 0
fi
exit 0
EOF
chmod +x "$FAKEBIN/ssh"

cat >"$CONFIG_FILE" <<EOF
listen = "127.0.0.1:${UNREACHABLE_PORT}"

[anytls]
password = "${SECRET_VALUE}"
EOF

set +e
PATH="$FAKEBIN:$PATH" \
MOCK_LOG_FILE="$LOG_FILE" \
MOCK_REMOTE_FS="$REMOTE_FS" \
MOCK_REMOTE_JOURNAL_LINE="$REMOTE_JOURNAL_LINE" \
"$ROOT/scripts/deploy-remote.sh" mock-host \
  --config "$CONFIG_FILE" \
  --remote-dir "$REMOTE_DIR" \
  --service "$SERVICE" \
  --target mock-target \
  --profile debug \
  --server-host 127.0.0.1 \
  --servername example.com \
  --no-client-configs >"$OUTPUT_FILE" 2>&1
status=$?
set -e

if [[ "$status" -eq 0 ]]; then
  echo "expected deploy script to fail connectivity check" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
fi

grep -F "FAIL: 127.0.0.1:${UNREACHABLE_PORT} not reachable" "$OUTPUT_FILE" >/dev/null
grep -F "$REMOTE_JOURNAL_LINE" "$OUTPUT_FILE" >/dev/null
grep -F "systemctl start '$SERVICE'" "$LOG_FILE" >/dev/null
grep -F "journalctl -u '$SERVICE'" "$LOG_FILE" >/dev/null
grep -F "$SECRET_VALUE" "$REMOTE_FS$REMOTE_DIR/config.toml" >/dev/null

if grep -F "$SECRET_VALUE" "$OUTPUT_FILE" >/dev/null; then
  echo "secret leaked to systemd failure stdout/stderr" >&2
  exit 1
fi

if grep -F "$SECRET_VALUE" "$LOG_FILE" >/dev/null; then
  echo "secret leaked to mocked transport command log" >&2
  exit 1
fi
