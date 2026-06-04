#!/usr/bin/env bash
# tls-handshake-stress.sh — TLS handshake performance testing
# Uses wrk2 directly against wrongsv's HTTPS endpoint

log "=== TLS Handshake Stress ==="
log "Target: https://$SERVER_HOST:$SERVER_PORT"
log ""

# Phase 1: Rapid TLS connections (wrk2 with HTTPS)
log "Phase 1/3: TLS handshake rate — 100 conn/s"
run_tool "wrk2-tls-100" "$BIN_DIR/wrk2" \
    -t4 -c100 -d15s -R100 --latency \
    "https://$SERVER_HOST:$SERVER_PORT/"

# Phase 2: High concurrency TLS
log "Phase 2/3: High concurrency TLS (500 connections)"
run_tool "wrk2-tls-500" "$BIN_DIR/wrk2" \
    -t4 -c500 -d15s -R200 --latency \
    "https://$SERVER_HOST:$SERVER_PORT/"

# Phase 3: Rapid connect/disconnect (vegeta)
log "Phase 3/3: Rapid TLS connect/disconnect"
for i in $(seq 1 200); do
    curl -k -s -o /dev/null -w "conn $i: %{time_connect}s\n" \
        --connect-timeout 5 "https://$SERVER_HOST:$SERVER_PORT/" &
done 2>/dev/null
wait

log "TLS handshake stress complete"
