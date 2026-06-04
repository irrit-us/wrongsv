#!/usr/bin/env bash
# multi-user-sim.sh — realistic multi-user traffic simulation
# Uses Hellcat-v2 with randomized UUID/SNI to mimic real users

log "=== Multi-User Traffic Simulation ==="
log "Target: $SERVER_HOST:$SERVER_PORT"
log "Duration: $DURATION | Clients: $CONCURRENT"

# Phase 1: VLESS handshake stress — rapid TLS+VLESS auth
log "Phase 1/4: Handshake stress (200 clients, handshake-only mode)"
run_tool "hellcat-handshake" "$BIN_DIR/hellcat" \
    -server "$SERVER_HOST" \
    -port "$SERVER_PORT" \
    -clients 200 \
    -duration 15s \
    -load handshake \
    -proto vless \
    -tls=true

# Phase 2: Mixed traffic — realistic browsing patterns
log "Phase 2/4: Mixed traffic simulation ($CONCURRENT clients)"
run_tool "hellcat-mixed" "$BIN_DIR/hellcat" \
    -server "$SERVER_HOST" \
    -port "$SERVER_PORT" \
    -clients "$CONCURRENT" \
    -duration "$DURATION" \
    -load mixed \
    -proto vless \
    -target "google.com:443"

# Phase 3: SYN flood resistance (tests server's accept loop)
log "Phase 3/4: SYN flood test (500 clients, syn mode)"
run_tool "hellcat-syn" "$BIN_DIR/hellcat" \
    -server "$SERVER_HOST" \
    -port "$SERVER_PORT" \
    -clients 500 \
    -duration 10s \
    -load syn \
    -proto vless

# Phase 4: Sustained real-traffic relay
log "Phase 4/4: Sustained relay (50 clients, 60s, rate-limited)"
run_tool "hellcat-sustained" "$BIN_DIR/hellcat" \
    -server "$SERVER_HOST" \
    -port "$SERVER_PORT" \
    -clients 50 \
    -duration 60s \
    -load mixed \
    -rate 100 \
    -proto vless \
    -target "httpbin.org:443"

log "Multi-user simulation complete"
