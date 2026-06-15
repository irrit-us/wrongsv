#!/usr/bin/env bash
# memory.sh — sample /proc/PID memory over time, compute leak slope at end
#
# Samples VmRSS, VmHWM, VmSize, VmPeak every SAMPLE_INTERVAL seconds for
# SOAK_DURATION seconds. On exit, fits a linear regression through the
# VmRSS time series — skipping a warmup prefix — and writes a JSON sidecar with:
#   - samples: [{t, rss_kb, hwm_kb, size_kb}]
#   - slope_kb_per_min: best-fit slope of RSS over time (post-warmup)
#   - leak: true if slope_kb_per_min > LEAK_THRESHOLD_KB_PER_MIN
#   - rss_peak_kb, rss_initial_kb, rss_final_kb
#
# Usage:
#   sample_memory PID OUT_JSON_PATH       # blocks for SOAK_DURATION
#
# Env:
#   SOAK_DURATION (default 1800 sec / 30 min)
#   SAMPLE_INTERVAL (default 5 sec)
#   LEAK_THRESHOLD_KB_PER_MIN (default 50)
#   WARMUP_SEC (default 60) — first WARMUP_SEC of samples are excluded from
#     the slope fit (steady-state only). If the soak is too short to leave at
#     least 2 post-warmup samples, all samples are used and a `warmup_skipped`
#     flag is set on the output for transparency.
set -uo pipefail

SOAK_DURATION="${SOAK_DURATION:-1800}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-5}"
LEAK_THRESHOLD_KB_PER_MIN="${LEAK_THRESHOLD_KB_PER_MIN:-50}"
WARMUP_SEC="${WARMUP_SEC:-60}"

sample_memory() {
    local pid="$1"
    local out="$2"
    local samples_tmp
    samples_tmp="$(mktemp)"
    local start
    start="$(date +%s)"
    local deadline=$((start + SOAK_DURATION))
    local now t rss hwm size peak

    # Header: TSV `t_sec rss_kb hwm_kb size_kb peak_kb`
    while :; do
        now="$(date +%s)"
        t=$((now - start))
        if [ ! -e "/proc/$pid/status" ]; then
            echo "[memory] PID $pid disappeared at t=${t}s" >&2
            break
        fi
        # status fields are space-separated `name: value kB`
        # awk pulls each known field; missing fields become 0.
        read -r rss hwm size peak < <(awk '
            /^VmRSS:/  {rss=$2}
            /^VmHWM:/  {hwm=$2}
            /^VmSize:/ {size=$2}
            /^VmPeak:/ {peak=$2}
            END {print rss+0, hwm+0, size+0, peak+0}
        ' "/proc/$pid/status" 2>/dev/null) || break
        echo -e "$t\t$rss\t$hwm\t$size\t$peak" >> "$samples_tmp"
        [ "$now" -ge "$deadline" ] && break
        sleep "$SAMPLE_INTERVAL"
    done

    _compute_slope_and_emit_json "$samples_tmp" "$out"
    rm -f "$samples_tmp"
}

# Inline python: linear regression on (t, rss_kb), output JSON.
_compute_slope_and_emit_json() {
    local samples_tsv="$1"
    local out_json="$2"
    SAMPLES_TSV="$samples_tsv" \
    OUT_JSON="$out_json" \
    LEAK_THRESHOLD_KB_PER_MIN="$LEAK_THRESHOLD_KB_PER_MIN" \
    WARMUP_SEC="$WARMUP_SEC" \
        python3 - <<'PYEOF'
import json, os

tsv = os.environ["SAMPLES_TSV"]
out = os.environ["OUT_JSON"]
threshold = float(os.environ["LEAK_THRESHOLD_KB_PER_MIN"])
warmup_sec = int(os.environ["WARMUP_SEC"])

samples = []
with open(tsv) as f:
    for line in f:
        parts = line.strip().split("\t")
        if len(parts) != 5:
            continue
        t, rss, hwm, size, peak = (int(p) for p in parts)
        samples.append({"t": t, "rss_kb": rss, "hwm_kb": hwm, "size_kb": size, "peak_kb": peak})

# Skip the warmup prefix when fitting slope (steady-state only). If too short,
# fall back to all samples and set a flag for transparency.
fit_samples = [s for s in samples if s["t"] >= warmup_sec]
warmup_skipped = True
if len(fit_samples) < 2:
    fit_samples = samples
    warmup_skipped = False

if len(fit_samples) < 2:
    result = {
        "samples": samples,
        "slope_kb_per_min": None,
        "leak": None,
        "leak_threshold_kb_per_min": threshold,
        "rss_initial_kb": samples[0]["rss_kb"] if samples else None,
        "rss_final_kb": samples[-1]["rss_kb"] if samples else None,
        "rss_peak_kb": max((s["hwm_kb"] for s in samples), default=None),
        "n_samples": len(samples),
        "warmup_sec": warmup_sec,
        "warmup_skipped": False,
        "note": "insufficient samples for slope regression",
    }
else:
    xs = [s["t"] for s in fit_samples]
    ys = [s["rss_kb"] for s in fit_samples]
    n = len(fit_samples)
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    slope_kb_per_sec = num / den if den > 0 else 0.0
    slope_kb_per_min = slope_kb_per_sec * 60
    result = {
        "samples": samples,
        "slope_kb_per_min": round(slope_kb_per_min, 3),
        "leak": slope_kb_per_min > threshold,
        "leak_threshold_kb_per_min": threshold,
        "rss_initial_kb": samples[0]["rss_kb"],
        "rss_final_kb": samples[-1]["rss_kb"],
        "rss_peak_kb": max(s["hwm_kb"] for s in samples),
        "n_samples": len(samples),
        "n_fit_samples": n,
        "warmup_sec": warmup_sec,
        "warmup_skipped": warmup_skipped,
        "duration_sec": samples[-1]["t"],
    }

with open(out, "w") as f:
    json.dump(result, f, indent=2)
PYEOF
}

# Direct invocation: ./memory.sh PID OUT.json
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    if [ $# -ne 2 ]; then
        echo "Usage: $0 PID OUT.json" >&2
        exit 1
    fi
    sample_memory "$1" "$2"
fi
