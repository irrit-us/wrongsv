#!/usr/bin/env bash
# setup.sh — one-shot setup to clone and build all traffic generation tools
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$BENCH_DIR/tools"
BIN_DIR="$TOOLS_DIR/bin"

mkdir -p "$BIN_DIR"

echo "=== wrongsv bench tool setup ==="
echo "Tools dir: $TOOLS_DIR"
echo ""

# ── Deathcore — REALITY-native VLESS stress tester ──────────────────────────
if [ ! -f "$TOOLS_DIR/deathcore/deathcore" ]; then
    echo "[1/5] Cloning and building Deathcore..."
    rm -rf "$TOOLS_DIR/deathcore"
    git clone --depth 1 https://github.com/internetkafe/deathcore.git "$TOOLS_DIR/deathcore"
    cd "$TOOLS_DIR/deathcore"
    go build -o deathcore .
    echo "  -> deathcore built"
else
    echo "[1/5] Deathcore already built, skipping"
fi
ln -sf ../deathcore/deathcore "$BIN_DIR/deathcore"

# ── Hellcat-v2 — realistic multi-user VLESS traffic generator ───────────────
if [ ! -f "$TOOLS_DIR/hellcat/hellcat" ]; then
    echo "[2/5] Cloning and building Hellcat-v2..."
    rm -rf "$TOOLS_DIR/hellcat"
    git clone --depth 1 https://github.com/hellcat443/Hellcat-v2.git "$TOOLS_DIR/hellcat"
    cd "$TOOLS_DIR/hellcat"
    # Only keep the newer version file (hellcatv2-1.go), remove the older one
    rm -f hellcat.go
    go mod init hellcat && go mod tidy
    go build -o hellcat .
    echo "  -> hellcat built"
else
    echo "[2/5] Hellcat-v2 already built, skipping"
fi
ln -sf ../hellcat/hellcat "$BIN_DIR/hellcat"

# ── wrk2 — constant-throughput HTTP benchmark ───────────────────────────────
if [ ! -f "$TOOLS_DIR/wrk2/wrk" ]; then
    echo "[3/5] Cloning and building wrk2..."
    rm -rf "$TOOLS_DIR/wrk2"
    git clone --depth 1 https://github.com/giltene/wrk2.git "$TOOLS_DIR/wrk2"
    cd "$TOOLS_DIR/wrk2"
    make -j"$(nproc)"
    echo "  -> wrk2 built"
else
    echo "[3/5] wrk2 already built, skipping"
fi
ln -sf ../wrk2/wrk "$BIN_DIR/wrk2"

# ── Vegeta — HTTP load testing ──────────────────────────────────────────────
if [ ! -f "$BIN_DIR/vegeta" ]; then
    echo "[4/5] Downloading Vegeta..."
    curl -sL "https://github.com/tsenart/vegeta/releases/download/v12.12.0/vegeta_12.12.0_linux_amd64.tar.gz" \
        -o "$BIN_DIR/vegeta.tar.gz"
    tar xzf "$BIN_DIR/vegeta.tar.gz" -C "$BIN_DIR" vegeta
    rm "$BIN_DIR/vegeta.tar.gz"
    chmod +x "$BIN_DIR/vegeta"
    echo "  -> vegeta $( $BIN_DIR/vegeta --version )"
else
    echo "[4/5] Vegeta already downloaded, skipping"
fi

# ── k6 — modern load testing with JS scripting ──────────────────────────────
if [ ! -f "$BIN_DIR/k6" ]; then
    echo "[5/5] Downloading k6..."
    curl -sL "https://github.com/grafana/k6/releases/download/v0.57.0/k6-v0.57.0-linux-amd64.tar.gz" \
        -o "$BIN_DIR/k6.tar.gz"
    tar xzf "$BIN_DIR/k6.tar.gz" --strip-components=1 -C "$BIN_DIR" k6-v0.57.0-linux-amd64/k6
    rm "$BIN_DIR/k6.tar.gz"
    chmod +x "$BIN_DIR/k6"
    echo "  -> k6 $( $BIN_DIR/k6 version 2>&1 | head -1 )"
else
    echo "[5/5] k6 already downloaded, skipping"
fi

# ── xray-core — required by Deathcore for REALITY protocol testing ──────────
if [ ! -f "$BIN_DIR/xray" ]; then
    echo "[6/6] Setting up xray-core for Deathcore..."
    # Try local build first (requires Go 1.26+), fall back to pre-built binary
    XRAY_SRC="$BENCH_DIR/../../../xray-core"
    if [ -d "$XRAY_SRC/go.mod" ]; then
        echo "  Building from local xray-core source..."
        cd "$XRAY_SRC"
        GOTOOLCHAIN=auto go build -o "$BIN_DIR/xray" ./main/ 2>/dev/null && echo "  -> xray built from source" || true
    fi
    if [ ! -f "$BIN_DIR/xray" ]; then
        echo "  Downloading pre-built xray-core..."
        curl -sL --connect-timeout 30 --max-time 120 \
            "https://github.com/XTLS/Xray-core/releases/download/v1.8.23/Xray-linux-64.zip" \
            -o "$BIN_DIR/xray.zip" 2>/dev/null && \
            unzip -o "$BIN_DIR/xray.zip" xray -d "$BIN_DIR/" 2>/dev/null && \
            rm "$BIN_DIR/xray.zip" && chmod +x "$BIN_DIR/xray" && \
            echo "  -> xray downloaded" || \
            echo "  [WARN] xray-core not available (network or build issue)"
    fi
else
    echo "[6/6] xray-core already available, skipping"
fi

export PATH="$BIN_DIR:$PATH"

echo ""
echo "=== All tools ready ==="
echo "Binaries:"
ls -lh "$BIN_DIR/"
echo ""
echo "Run: ./benches/traffic/run.sh [scenario]"
