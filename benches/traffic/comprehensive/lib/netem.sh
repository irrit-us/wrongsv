#!/usr/bin/env bash
# netem.sh — apply/remove tc-netem shaping on the loopback interface
#
# Default profile: 50ms delay, 5ms jitter, 0.1% loss (realistic intra-region link)
# Override via env: NETEM_DELAY, NETEM_JITTER, NETEM_LOSS, NETEM_IFACE
#
# Loopback has qdisc=noqueue by default; `tc qdisc replace` installs netem
# in its place. Requires CAP_NET_ADMIN (sudo or capability granted).
# If sudo isn't available, this script warns and exits 0 — the matrix runner
# continues without shaping (relative comparisons across servers remain valid).
#
# Usage:
#   netem_apply           # install shaping
#   netem_restore         # restore noqueue
#   netem_status          # print current qdisc
set -uo pipefail

NETEM_IFACE="${NETEM_IFACE:-lo}"
NETEM_DELAY="${NETEM_DELAY:-50ms}"
NETEM_JITTER="${NETEM_JITTER:-5ms}"
NETEM_LOSS="${NETEM_LOSS:-0.1%}"

_netem_can_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        echo "root"
        return 0
    fi
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        echo "sudo -n"
        return 0
    fi
    return 1
}

netem_apply() {
    local runner
    if ! runner="$(_netem_can_sudo)"; then
        echo "[netem] WARN: no CAP_NET_ADMIN (need root or passwordless sudo); skipping shaping" >&2
        return 0
    fi
    # `replace` is idempotent: works whether current root qdisc is noqueue, netem, or anything else.
    if ! $runner tc qdisc replace dev "$NETEM_IFACE" root netem \
            delay "$NETEM_DELAY" "$NETEM_JITTER" distribution normal \
            loss "$NETEM_LOSS" 2>/dev/null; then
        echo "[netem] WARN: tc qdisc replace failed on $NETEM_IFACE; continuing without shaping" >&2
        return 0
    fi
    echo "[netem] applied: $NETEM_IFACE delay=$NETEM_DELAY jitter=$NETEM_JITTER loss=$NETEM_LOSS" >&2
}

netem_restore() {
    local runner
    if ! runner="$(_netem_can_sudo)"; then
        return 0
    fi
    # Restoring to noqueue is the default for lo; for other ifaces, fall back to pfifo_fast.
    if [ "$NETEM_IFACE" = "lo" ]; then
        $runner tc qdisc replace dev "$NETEM_IFACE" root noqueue 2>/dev/null || \
            $runner tc qdisc del dev "$NETEM_IFACE" root 2>/dev/null || true
    else
        $runner tc qdisc del dev "$NETEM_IFACE" root 2>/dev/null || true
    fi
    echo "[netem] restored: $NETEM_IFACE" >&2
}

netem_status() {
    tc qdisc show dev "$NETEM_IFACE" 2>&1
}

# Allow direct invocation: ./netem.sh apply|restore|status
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        apply)   netem_apply ;;
        restore) netem_restore ;;
        status)  netem_status ;;
        *)       echo "Usage: $0 {apply|restore|status}" >&2; exit 1 ;;
    esac
fi
