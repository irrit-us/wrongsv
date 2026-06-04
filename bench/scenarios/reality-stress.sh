#!/usr/bin/env bash
# reality-stress.sh — REALITY+VLESS protocol-level stress test
# Uses Deathcore for direct protocol-level connection stress

log "=== REALITY Protocol Stress ==="
log "Target: $SERVER_HOST:$SERVER_PORT"
log "Duration: $DURATION | Workers: $CONCURRENT"

REALITY_URL="${REALITY_URL:-vless://12345678-1234-1234-1234-123456789abc@$SERVER_HOST:$SERVER_PORT?security=reality&sni=www.microsoft.com&fp=chrome&pbk=d75c6e2f7e8a1b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4&sid=aaaaaaaa&spiderX=%2F&type=tcp&flow=xtls-rprx-vision}"

# Phase 1: Connection flood — rapid connect/disconnect
log "Phase 1/3: Connection flood (100 workers, 10s)"
run_tool "deathcore-flood" "$BIN_DIR/deathcore" \
    -vless "$REALITY_URL" \
    -target "www.microsoft.com:443" \
    -workers 100 \
    -mode flood \
    -reconnect-delay 0

# Phase 2: Sustained HTTP traffic through REALITY
log "Phase 2/3: HTTP relay stress (50 workers, ${DURATION})"
run_tool "deathcore-http" "$BIN_DIR/deathcore" \
    -vless "$REALITY_URL" \
    -target "www.microsoft.com:443" \
    -workers 50 \
    -mode http \
    -reconnect-delay 500ms

# Phase 3: Max concurrent connections
log "Phase 3/3: Max concurrent ($CONCURRENT workers, ${DURATION})"
run_tool "deathcore-max" "$BIN_DIR/deathcore" \
    -vless "$REALITY_URL" \
    -target "www.microsoft.com:443" \
    -workers "$CONCURRENT" \
    -mode flood \
    -reconnect-delay 0

log "REALITY stress complete"
