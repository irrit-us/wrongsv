#!/usr/bin/env bash
# certs.sh — generate a self-signed ECDSA P-256 cert reusable across all
# competitor server configs (xray, sing-box, mihomo). wrongsv generates its
# own self-signed cert internally when no cert/key is configured, so we only
# need a shared cert for the other three.
#
# The cert is generated once per matrix run into /tmp and reused.
set -uo pipefail

CERT_PATH="${BENCH_CERT_PATH:-/tmp/wrongsv-bench-cert.pem}"
KEY_PATH="${BENCH_KEY_PATH:-/tmp/wrongsv-bench-key.pem}"
CERT_CN="${BENCH_CERT_CN:-localhost}"

ensure_bench_cert() {
    if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
        # Re-issue if expired or > 7d old (avoid stale chain weirdness across runs)
        if [ "$(find "$CERT_PATH" -mtime -7 2>/dev/null)" ]; then
            return 0
        fi
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        echo "[certs] openssl missing; TLS-protocol cells will fail" >&2
        return 1
    fi
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$KEY_PATH" -out "$CERT_PATH" \
        -days 30 -nodes \
        -subj "/CN=${CERT_CN}" \
        -addext "subjectAltName=DNS:${CERT_CN},DNS:www.microsoft.com,IP:127.0.0.1" \
        >/dev/null 2>&1
    chmod 644 "$CERT_PATH" "$KEY_PATH" 2>/dev/null || true
    echo "[certs] generated $CERT_PATH (CN=$CERT_CN)" >&2
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    ensure_bench_cert
fi
