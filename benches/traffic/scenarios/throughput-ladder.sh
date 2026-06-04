#!/usr/bin/env bash
# throughput-ladder.sh — throughput vs latency curve measurement
# Uses wrk2 and vegeta through the SOCKS5 proxy

log "=== Throughput Ladder Test ==="
log "Using SOCKS5 proxy at $SERVER_HOST:$SOCKS_PORT"
log ""

# We assume a sing-box/mihomo client is running locally providing SOCKS5 proxy
# pointing to wrongsv. If not, skip this scenario.
if ! curl -x socks5h://127.0.0.1:"$SOCKS_PORT" -s -o /dev/null --connect-timeout 3 http://httpbin.org/get 2>/dev/null; then
    warn "SOCKS5 proxy not available at 127.0.0.1:$SOCKS_PORT — skipping HTTP-level tests"
    warn "Start a sing-box/mihomo client pointing to wrongsv, then re-run"
    exit 0
fi

# Phase 1: wrk2 constant-rate ladder
log "Phase 1/4: wrk2 latency-vs-throughput ladder"
for rate in 10 50 100 200 500 1000; do
    log "  Rate: ${rate} req/s"
    run_tool "wrk2-r${rate}" "$BIN_DIR/wrk2" \
        -t4 -c50 -d15s -R"$rate" --latency \
        "http://httpbin.org/get"
done

# Phase 2: vegeta HTTP attack at various rates
log "Phase 2/4: Vegeta constant-rate attack"
for rate in 100 500 1000 2000; do
    log "  Rate: ${rate} req/s, 15s"
    echo "GET http://httpbin.org/get" | \
        run_tool "vegeta-r${rate}" "$BIN_DIR/vegeta" attack \
        -rate="$rate" -duration=15s | \
        "$BIN_DIR/vegeta" report
done

# Phase 3: Large payload download (10MB)
log "Phase 3/4: Large download test (10MB)"
run_tool "wrk2-download" curl -x socks5h://127.0.0.1:"$SOCKS_PORT" \
    -s -o /dev/null -w "HTTP %{http_code} | Size: %{size_download}B | Time: %{time_total}s | Speed: %{speed_download}B/s\n" \
    --connect-timeout 10 -m 120 "http://ipv4.download.thinkbroadband.com/10MB.zip"

# Phase 4: Concurrent downloads
log "Phase 4/4: 5 concurrent 1MB downloads"
for i in $(seq 1 5); do
    (curl -x socks5h://127.0.0.1:"$SOCKS_PORT" -s -o /dev/null \
        -w "[$i] HTTP %{http_code} | %{size_download}B | %{time_total}s\n" \
        --connect-timeout 10 -m 60 "http://ipv4.download.thinkbroadband.com/1MB.zip" &)
done
wait

log "Throughput ladder complete"
