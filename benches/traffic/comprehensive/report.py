#!/usr/bin/env python3
"""
report.py — aggregate matrix cell JSONs into a Markdown report and/or CSV.

Usage:
    # single run, markdown to stdout (legacy)
    python3 report.py /path/to/results/TIMESTAMP > REPORT.md

    # one or more runs, combined; write report + CSV to a directory
    python3 report.py --out-dir OUT /path/to/RUN1 [/path/to/RUN2 ...]

    # only CSV
    python3 report.py --csv OUT.csv RUN1 [RUN2 ...]

Reads $RESULTS/$CONFIG/$SERVER.json for every (config, server) cell.
When multiple result roots are given, each row is labelled with its run id
(the result dir's basename) so the same protocol from different runs can coexist.
"""
import argparse
import csv
import json
import sys
from pathlib import Path

SERVERS_ORDER = ["wrongsv", "xray", "sing-box", "mihomo"]


def load_cells(root: Path):
    cells = {}  # config -> {server -> data}
    for config_dir in sorted(root.iterdir()):
        if not config_dir.is_dir():
            continue
        cfg = config_dir.name
        cells[cfg] = {}
        for f in config_dir.glob("*.json"):
            if f.stem in ("memory", "vegeta"):
                continue
            if f.name.endswith((".memory.json", ".vegeta.json")):
                continue
            try:
                data = json.loads(f.read_text())
            except Exception as e:
                data = {"status": "parse_error", "error": str(e)}
            cells[cfg][f.stem] = data
    return cells


def load_runs(roots):
    """Load multiple result roots. Returns list of (run_id, root, cells)."""
    out = []
    for root in roots:
        out.append((root.name, root, load_cells(root)))
    return out


def fmt_ns_ms(ns):
    if ns is None or not isinstance(ns, (int, float)):
        return "—"
    return f"{ns / 1e6:.1f}"


def fmt_throughput(t):
    if t is None:
        return "—"
    return f"{t:.1f}"


def fmt_pct(r):
    if r is None:
        return "—"
    return f"{r * 100:.2f}"


def fmt_kb(kb):
    if kb is None:
        return "—"
    return f"{kb / 1024:.1f}"


def fmt_slope(s):
    if s is None:
        return "—"
    return f"{s:+.1f}"


def render_markdown(runs) -> str:
    """Render a Markdown report covering one or more runs."""
    multi = len(runs) > 1
    lines = []
    lines.append("# Comprehensive Bench Report")
    lines.append("")
    if multi:
        lines.append("- Combined report across runs:")
        for run_id, root, _ in runs:
            lines.append(f"  - `{run_id}` → `{root}`")
    else:
        lines.append(f"- Results dir: `{runs[0][1]}`")
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append("- Each cell = (wrongsv-config, server impl). One server at a time, sequential.")
    lines.append("- Traffic flow: vegeta → SOCKS5 (xray client, constant) → SUT → local HTTP target.")
    lines.append("- The xray client and HTTP target are CONSTANT across cells; only the SUT varies.")
    lines.append("- Network: `lo` shaped via `tc-netem` (50ms delay, 5ms jitter, 0.1% loss) when SHAPE_NETEM=1.")
    lines.append("- Memory: SUT's `VmRSS` sampled every 5s. Leak slope = linear regression over samples.")
    lines.append("- Throughput: req/s sustained over soak duration.")
    lines.append("")

    # Union of configs across all runs
    all_configs = set()
    for _, _, cells in runs:
        all_configs.update(cells.keys())

    lines.append("## Per-config comparison")
    lines.append("")
    for cfg in sorted(all_configs):
        lines.append(f"### {cfg}")
        lines.append("")
        if multi:
            lines.append("| Run | Server | Status | Req/s | Success % | p50 (ms) | p95 (ms) | p99 (ms) | RSS peak (MB) | RSS slope (KB/min) | Leak? |")
            lines.append("|-----|--------|--------|------:|----------:|---------:|---------:|---------:|--------------:|-------------------:|:-----:|")
        else:
            lines.append("| Server | Status | Req/s | Success % | p50 (ms) | p95 (ms) | p99 (ms) | RSS peak (MB) | RSS slope (KB/min) | Leak? |")
            lines.append("|--------|--------|------:|----------:|---------:|---------:|---------:|--------------:|-------------------:|:-----:|")
        for run_id, _, cells in runs:
            if cfg not in cells:
                continue
            servers_present = list(cells[cfg].keys())
            ordered = [s for s in SERVERS_ORDER if s in servers_present] + \
                      [s for s in servers_present if s not in SERVERS_ORDER]
            for server in ordered:
                d = cells[cfg][server]
                status = d.get("status", "?")
                prefix = f"| {run_id} | {server}" if multi else f"| {server}"
                if status != "ok":
                    lines.append(f"{prefix} | `{status}` | — | — | — | — | — | — | — | — |")
                    continue
                load = d.get("load", {})
                mem = d.get("memory", {})
                leak = mem.get("leak")
                leak_str = "⚠️ yes" if leak is True else ("ok" if leak is False else "—")
                lines.append(
                    f"{prefix} | ok | "
                    f"{fmt_throughput(load.get('throughput_req_s'))} | "
                    f"{fmt_pct(load.get('success_ratio'))} | "
                    f"{fmt_ns_ms(load.get('latency_p50_ns'))} | "
                    f"{fmt_ns_ms(load.get('latency_p95_ns'))} | "
                    f"{fmt_ns_ms(load.get('latency_p99_ns'))} | "
                    f"{fmt_kb(mem.get('rss_peak_kb'))} | "
                    f"{fmt_slope(mem.get('slope_kb_per_min'))} | "
                    f"{leak_str} |"
                )
        lines.append("")

    # Per-server summary across all runs combined
    lines.append("## Per-server summary (across all configs and runs)")
    lines.append("")
    lines.append("| Server | Cells run | OK | Failed | Unsupported | Mean req/s | Mean RSS peak (MB) | Leaks |")
    lines.append("|--------|----------:|---:|-------:|------------:|-----------:|-------------------:|------:|")
    for server in SERVERS_ORDER:
        n_total = n_ok = n_fail = n_unsup = n_leak = 0
        sum_rps = sum_rss = 0.0
        for _, _, cells in runs:
            for _, by_srv in cells.items():
                if server not in by_srv:
                    continue
                n_total += 1
                d = by_srv[server]
                s = d.get("status")
                if s == "ok":
                    n_ok += 1
                    load = d.get("load", {})
                    mem = d.get("memory", {})
                    if load.get("throughput_req_s"):
                        sum_rps += load["throughput_req_s"]
                    if mem.get("rss_peak_kb"):
                        sum_rss += mem["rss_peak_kb"]
                    if mem.get("leak"):
                        n_leak += 1
                elif s == "unsupported":
                    n_unsup += 1
                else:
                    n_fail += 1
        mean_rps = (sum_rps / n_ok) if n_ok else None
        mean_rss = (sum_rss / n_ok) if n_ok else None
        lines.append(
            f"| {server} | {n_total} | {n_ok} | {n_fail} | {n_unsup} | "
            f"{fmt_throughput(mean_rps)} | {fmt_kb(mean_rss)} | {n_leak} |"
        )
    lines.append("")

    # Leak detail
    leaks = []
    for run_id, _, cells in runs:
        for cfg, by_srv in cells.items():
            for server, d in by_srv.items():
                mem = d.get("memory", {}) if isinstance(d, dict) else {}
                if mem.get("leak") is True:
                    leaks.append((run_id, cfg, server, mem.get("slope_kb_per_min"),
                                  mem.get("rss_initial_kb"), mem.get("rss_final_kb")))
    if leaks:
        lines.append("## ⚠️ Memory leak candidates")
        lines.append("")
        lines.append("| Run | Config | Server | Slope (KB/min) | RSS start (MB) | RSS end (MB) |")
        lines.append("|-----|--------|--------|---------------:|---------------:|-------------:|")
        for run_id, cfg, server, slope, start_kb, end_kb in sorted(leaks, key=lambda x: -(x[3] or 0)):
            lines.append(
                f"| {run_id} | {cfg} | {server} | {fmt_slope(slope)} | "
                f"{fmt_kb(start_kb)} | {fmt_kb(end_kb)} |"
            )
        lines.append("")
    else:
        lines.append("## ✓ No memory leaks detected")
        lines.append("")
        lines.append("All cells had RSS slope below the configured threshold "
                     "(see `LEAK_THRESHOLD_KB_PER_MIN`, default 50).")
        lines.append("")

    return "\n".join(lines)


CSV_COLUMNS = [
    "run", "config", "server", "status",
    "duration_sec", "load_rate", "load_payload_bytes", "netem_shaped",
    "load_workers", "load_connections", "load_max_connections",
    "requests", "success_ratio",
    "throughput_req_s", "throughput_bytes_in",
    "latency_p50_ns", "latency_p95_ns", "latency_p99_ns", "latency_max_ns",
    "rss_initial_kb", "rss_final_kb", "rss_peak_kb",
    "slope_kb_per_min", "leak", "leak_threshold_kb_per_min",
    "n_samples", "n_fit_samples", "warmup_sec",
]


def write_csv(runs, out_path: Path) -> int:
    """Write a flat CSV with one row per cell across all runs. Returns row count."""
    rows = 0
    with out_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for run_id, _, cells in runs:
            for cfg, by_srv in cells.items():
                for server in (
                    [s for s in SERVERS_ORDER if s in by_srv] +
                    [s for s in by_srv if s not in SERVERS_ORDER]
                ):
                    d = by_srv[server]
                    load = d.get("load") or {}
                    mem = d.get("memory") or {}
                    netem = d.get("netem") or {}
                    row = {
                        "run": run_id,
                        "config": cfg,
                        "server": server,
                        "status": d.get("status"),
                        "duration_sec": d.get("duration_sec"),
                        "load_rate": d.get("load_rate"),
                        "load_payload_bytes": d.get("load_payload_bytes"),
                        "netem_shaped": netem.get("shaped"),
                        "load_workers": d.get("load_workers"),
                        "load_connections": d.get("load_connections"),
                        "load_max_connections": d.get("load_max_connections"),
                        "requests": load.get("requests"),
                        "success_ratio": load.get("success_ratio"),
                        "throughput_req_s": load.get("throughput_req_s"),
                        "throughput_bytes_in": load.get("throughput_bytes_in"),
                        "latency_p50_ns": load.get("latency_p50_ns"),
                        "latency_p95_ns": load.get("latency_p95_ns"),
                        "latency_p99_ns": load.get("latency_p99_ns"),
                        "latency_max_ns": load.get("latency_max_ns"),
                        "rss_initial_kb": mem.get("rss_initial_kb"),
                        "rss_final_kb": mem.get("rss_final_kb"),
                        "rss_peak_kb": mem.get("rss_peak_kb"),
                        "slope_kb_per_min": mem.get("slope_kb_per_min"),
                        "leak": mem.get("leak"),
                        "leak_threshold_kb_per_min": mem.get("leak_threshold_kb_per_min"),
                        "n_samples": mem.get("n_samples"),
                        "n_fit_samples": mem.get("n_fit_samples"),
                        "warmup_sec": mem.get("warmup_sec"),
                    }
                    w.writerow(row)
                    rows += 1
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("roots", nargs="+", help="One or more results/TIMESTAMP directories")
    ap.add_argument("--csv", metavar="FILE", help="Write CSV to FILE (one row per cell)")
    ap.add_argument("--out", metavar="FILE", help="Write Markdown report to FILE (default: stdout)")
    ap.add_argument("--out-dir", metavar="DIR",
                    help="Write both REPORT.md and results.csv into DIR")
    args = ap.parse_args()

    roots = []
    for r in args.roots:
        p = Path(r)
        if not p.is_dir():
            print(f"Not a directory: {p}", file=sys.stderr)
            sys.exit(1)
        roots.append(p)

    runs = load_runs(roots)
    md = render_markdown(runs)

    wrote_anything = False
    if args.out_dir:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "REPORT.md").write_text(md)
        n = write_csv(runs, out_dir / "results.csv")
        print(f"Wrote {out_dir/'REPORT.md'} and {out_dir/'results.csv'} ({n} rows)",
              file=sys.stderr)
        wrote_anything = True
    if args.csv:
        n = write_csv(runs, Path(args.csv))
        print(f"Wrote {args.csv} ({n} rows)", file=sys.stderr)
        wrote_anything = True
    if args.out:
        Path(args.out).write_text(md)
        print(f"Wrote {args.out}", file=sys.stderr)
        wrote_anything = True
    if not wrote_anything:
        print(md)


if __name__ == "__main__":
    main()
