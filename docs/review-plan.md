# wrongsv Review Plan

This document is now a living review tracker for `wrongsv` as a deployable
server and CLI product, including main config generation, remote deployment,
client config export, external E2E compatibility, and performance benchmarks.

## Review Status (2026-06-17)

### Verified this round

- `wrongsv --help`, `wrongsv generate-main-config --help`,
  `wrongsv eval-server --help`, and `wrongsv eval-client --help` all include
  examples and supported values.
- Added the canonical docs entrypoints that were previously missing:
  - [config-generation.md](config-generation.md)
  - [client-compatibility.md](client-compatibility.md)
  - [deploy.md](deploy.md)
  - [benchmarks.md](benchmarks.md)
  - [migration-notes.md](migration-notes.md)
- Added snapshot fixtures and tests for:
  - every supported generated main-config cluster
  - major client export shapes: mihomo REALITY, mihomo AnyTLS, sing-box
    AnyTLS, xray REALITY, Hiddify ShadowTLS, and Hiddify XHTTP
- Replaced `rustls-pemfile` with `rustls::pki_types::pem::PemObject` in the
  AnyTLS and Hysteria2 PEM parsing paths; `cargo audit` now reports no current
  vulnerabilities or warnings.
- `shellcheck -S warning` passes locally on the deploy and benchmark shell
  scripts with ShellCheck 0.11.0.
- Documented benchmark regression thresholds plus PR-smoke, nightly, and
  extended-soak parameter sets in [benchmarks.md](benchmarks.md).
- CI now runs `scripts/deploy-remote.sh ... --dry-run` in addition to shell
  syntax checks for the deploy path.
- Added `scripts/test-deploy-remote-mock.sh` plus CI coverage for a mocked
  non-dry-run deploy path.
- Added `scripts/test-deploy-remote-mock-failure.sh` plus CI coverage for the
  connectivity-failure/log-tail branch, with assertions that config secrets do
  not appear in script-controlled stdout/stderr or mocked transport logs.
- Added `scripts/test-deploy-remote-local-sshd.sh` plus CI coverage for a real
  localhost-`sshd` deploy using actual `ssh`/`scp` transport and inspection of
  the resulting remote `wrongsv.log`.
- Added `scripts/test-deploy-remote-mock-systemd.sh` plus CI coverage for the
  mocked systemd/`journalctl` failure branch.
- Made manifest generation optional via `--no-manifest` in
  `wrongsv generate-main-config`, `scripts/generate-client-configs.js`, and
  `scripts/deploy-remote.sh`, while keeping manifests enabled by default for
  reproducibility.
- Kept `scripts/deploy_remote.sh` as an intentional compatibility shim to the
  canonical `scripts/deploy-remote.sh`, and added CI dry-run coverage for that
  wrapper path.
- Added `.github/workflows/bench-smoke.yml` as a dedicated manual benchmark
  workflow for the documented smoke/comparison/soak presets, and documented the
  current manual-only policy and rationale.
- Local verification passed for:
  - `cargo fmt --all --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo audit`
  - `cargo test --workspace`
  - `cargo build -p wrongsv --bin wrongsv`
  - `node --check scripts/generate-client-configs.js`
  - `node scripts/generate-client-configs.js --self-test --wrongsv-bin target/debug/wrongsv`
  - `node scripts/generate-client-configs.js --self-test --external-tests-root ../wrongsv-external-tests`
  - `node --check scripts/recheck-external-standing-limitations.js`
  - `node --check scripts/verify-review-evidence.js`
  - `node scripts/verify-review-evidence.js --skip-external --output-file /tmp/wrongsv-review-evidence-summary.json`
  - `node --check scripts/generate-main-configs.js`
  - `bash -n scripts/deploy-remote.sh`
  - `bash -n scripts/deploy_remote.sh`
  - `scripts/deploy-remote.sh example.invalid --dry-run --config configs/anytls-vision.toml --server-host 203.0.113.10 --no-client-configs`
  - `scripts/test-deploy-remote-mock.sh`
  - `scripts/test-deploy-remote-mock-failure.sh`
  - `scripts/test-deploy-remote-local-sshd.sh`
  - `scripts/test-deploy-remote-mock-systemd.sh`
- `target/debug/wrongsv generate-main-config --cluster anytls,vision --output-dir ...`
  generated `anytls-vision.toml`, `manifest.json`, and `README.md` with
  restrictive `0600` permissions on Unix.
- Sample client export for `anytls_tcp` generated FlClash and sing-box configs
  and predictably skipped Hiddify and xray-core because the external capability
  matrix does not declare those combinations runnable. Hiddify AnyTLS skips now
  carry the machine-readable packaged-core gap reason instead of a generic
  “not runnable” message.
- `cargo test -p wrongsv --bin wrongsv` passes with the new snapshot coverage.
- A fresh `cargo test --workspace` rerun passed after hardening the flaky
  VMess metrics test in `tests/metrics_endpoint_tests.rs`.
- The Hiddify AnyTLS packaged-core gap reason is now guarded by both
  `generate-client-configs.js --self-test` and
  `wrongsv-external-tests/scripts/check-capability-docs.js`.
- Direct `wrongsv --print-client-config --format hiddify` and
  `--print-endpoint-diagnostics --format hiddify` now surface that same
  packaged-core AnyTLS reason instead of a separate local-only phrasing.
- `--print-endpoint-diagnostics` now also exposes stable `export.error_code`
  values for current gated export paths, including
  `hiddify_anytls_packaged_core_gap` and
  `webtransport_xray_family_export_disabled`.
- The external GUI harness now runs per-scenario Hiddify/FlClash state inside
  isolated `.runtime/` roots, and Hiddify startup-failure snapshots now record
  the requested runtime config summary and mtimes alongside translated/current
  config paths and log tails.
- `scripts/generate-client-configs.js --self-test` now also guards
  diagnostics-to-scenario drift for Meek, Google Docs Viewer, and
  WebTransport, and an optional `--wrongsv-bin` path now verifies that
  representative real configs in `configs/` resolve to the expected scenario
  IDs instead of collapsing into generic VLESS TLS/raw buckets.
- CI now runs `node scripts/generate-client-configs.js --self-test --wrongsv-bin target/debug/wrongsv`
  in a sibling-repo-free mode, so the internal client-generation drift guard
  is enforced even when `wrongsv-external-tests` is not checked out.
- Direct WebTransport client export is now gated in `wrongsv` itself: the
  current shared xray-format output no longer interoperates with the installed
  xray-core/V2Ray probes, so `--format xray` now fails fast with an explicit
  error instead of handing out a stale QUIC-shaped config.
- The config-backed `generate-client-configs.js --self-test --wrongsv-bin ...`
  path now also verifies the current CLI-level export gates for both
  WebTransport (`--format xray`) and Hiddify AnyTLS (`--format hiddify`).
- Capability-gated client manifests now distinguish skipped outcomes with
  machine-readable `reasonCode` values such as `harness_gap`,
  `scenario_untracked`, and `client_not_runnable_for_scenario`.
- Capability-gated generation now also preflights direct client-family export
  support before wrapping raw harness formats, so a capability-metadata drift
  can surface as a machine-readable `manifest.failed[*].reasonCode` (for
  example `hiddify_anytls_packaged_core_gap`) instead of silently emitting an
  unsupported family artifact.
- `manifest.json` now also records those direct family-export preflight results
  under `exportPreflight`, keyed by family format, so supported vs gated
  families are visible without reconstructing the pipeline from stderr or row
  by row client outcomes.
- Non-zero `generate-client-configs.js` exits now also emit machine-readable
  stderr summaries with top-level `reasonCode` values such as
  `no_compatible_client_configs_generated` and `client_generation_failed`.
- With `wrongsv-external-tests` available, the same self-test now runs
  end-to-end generation probes that verify manifest `reasonCode` behavior for
  untracked scenarios, harness gaps, and drifted family-export failures, plus
  the structured stdout/stderr summary payloads.
- `wrongsv-external-tests` now explicitly documents the intentionally untracked
  `vless_webtransport` state for both xray-core and V2Ray/V2Fly, and
  `scripts/check-capability-docs.js` now guards those notes so they do not
  silently drift out of sync with the capability metadata.
- The external capability metadata itself now records `vless_webtransport` as
  intentionally untracked, and `scripts/generate-client-configs.js` consumes
  that metadata instead of relying on a local-only allowlist for that state.
- `wrongsv-external-tests/scripts/check-capability-docs.js` now also verifies
  that every intentionally untracked scenario still exists in the external
  scenario catalog and remains absent from every client's runnable/gap lists.
- `wrongsv-external-tests/docs/known-limitations.md` now also carries the
  standing Hiddify AnyTLS and xray/V2Ray WebTransport client/runtime
  limitations so those open items are discoverable outside the audit doc.
- `wrongsv-external-tests/scripts/check-capability-docs.js` now also guards
  the `docs/known-limitations.md` entries and README pointers for those
  standing Hiddify AnyTLS and WebTransport limitations.
- `wrongsv-external-tests/scripts/check-capability-docs.js --json` now exposes
  a structured docs-check summary, and the aggregate review-evidence bundles
  now include that object instead of a plain `capability docs OK` string.
- The standing Hiddify AnyTLS gap is now version-pinned in the external docs:
  Hiddify 4.1.2 (build 40102) with bundled Xray 25.3.6, and the external
  checker now guards those version references.
- The same external checker now also validates the stored
  `hiddify-anytls-gap-isolated-2`, `xray-webtransport-matrix-1`, and
  `v2ray-webtransport-matrix-2` `matrix.json` artifacts so the standing gap
  docs stay tied to the actual machine-readable evidence.
- `wrongsv-external-tests/docs/known-limitations.md` now also anchors the
  WebTransport client-shape limitation in the current upstream Xray / V2Fly
  transport docs, and the external checker now guards those source references.
- The standing WebTransport limitation is now also version-pinned in the
  external docs as xray-core 26.5.9 and V2Ray 5.49.0, and the external checker
  now guards those version references.
- `wrongsv-external-tests/scripts/recheck-standing-limitations.js` now provides
  a single entrypoint for rerunning the standing Hiddify AnyTLS and
  WebTransport limitation evidence with expected status and expected reason
  checks drawn from the shared capability metadata, plus the corresponding
  top-level matrix summary counters, and it now writes a durable `summary.json`
  artifact under its chosen output root.
- `scripts/recheck-external-standing-limitations.js` now exposes that same
  standing-limitations recheck from the main `wrongsv` repo root, and it now
  reports a machine-readable `external_review_helper_missing` error when the
  sibling repo is absent. In `--dry-run` mode it now succeeds with a small JSON
  plan even when the sibling repo is missing.
- `scripts/verify-review-evidence.js` now provides a single main-repo entrypoint
  that combines the local client-generation self-test and the external review
  evidence bundle into one JSON result, and it can now persist that combined
  summary via `--output-file` or a default
  `wrongsv-review-evidence-summary.json` under `--output-root`. CI now also
  exercises both its local-only `--skip-external` execution path and its
  missing-sibling `--dry-run` path. `--skip-external` now also forces the
  local self-test into `--local-only` mode so the structured local result
  explicitly reports `usedHarness = false`.
- `generate-client-configs.js --self-test --json` now exposes the local
  self-test as a machine-readable summary, and the aggregate review-evidence
  wrapper now captures that structured local result instead of a plain `OK`
  string.
- `wrongsv-external-tests/scripts/verify-review-evidence.js` now provides a
  single JSON-producing entrypoint that combines the external docs checker,
  reusable core-client binary scans, the Hiddify packaged-core scan, and the
  standing-limitations recheck, and it now writes a durable
  `review-evidence-summary.json` artifact when `--output-root` is supplied.
- `wrongsv-external-tests/scripts/inspect-client-cores.js` now scans the local
  sing-box, Mihomo, xray-core, and V2Ray binaries for version/build metadata,
  file hashes, and feature markers, and the process-level `debug-*.json`
  artifacts for those clients now embed the same `binarySummary` block. Fresh
  focused reruns verified this in
  `/tmp/xray-binary-summary-check-1/vless_raw_tcp/debug-initial.json` and
  `/tmp/clash-verge-binary-summary-check-1/vless_raw_tcp/debug-initial.json`.
- `wrongsv-external-tests/scripts/inspect-hiddify-core.js` now scans the
  current Hiddify desktop bundle plus `hiddify-next` source markers, and the
  latest local run confirms that `json_editor.dart` still lists `anytls` while
  the packaged `lib/hiddify-core.so` exposes no AnyTLS marker at all, but does
  expose reusable ShadowTLS, Hysteria2, TUIC, and Xray wrapper markers with
  embedded `sing-box` `v1.8.9`. That scan is now part of the external review
  evidence bundle instead of a one-off manual inspection.
- `scripts/verify-external-review-evidence.js` now exposes that same external
  review-evidence bundle from the main `wrongsv` repo root, with the same
  machine-readable missing-repo error contract and dry-run fallback.
- `docs/testing.md` and `wrongsv-external-tests/README.md` now describe that
  standing-limitations recheck contract explicitly, including the expected
  `gap_confirmed` / `untracked_confirmed` outcomes and the JSON summary shape.
- `run-client-matrix.js` now treats intentionally untracked scenarios as a
  first-class result state (`untracked_confirmed` / `unexpected_untracked_pass`)
  rather than collapsing them into generic failures, and focused xray-core /
  V2Ray WebTransport matrices now persist that status in machine-readable
  `matrix.json` artifacts.
- `run-client-matrix.js` top-level JSON summaries now also break out
  `confirmedUntracked` plus `unexpectedPasses`,
  `unexpectedDefectPasses`, `unexpectedGapPasses`, and
  `unexpectedUntrackedPasses` so status regressions are visible without parsing
  every scenario row.
- `wrongsv-external-tests/docs/client-capability-audit.md` now explicitly
  documents the `matrix.json` status vocabulary (`passed`, `failed`,
  `defect_confirmed`, `gap_confirmed`, `untracked_confirmed`, and the
  `unexpected_*` variants), and the external checker now guards those status
  names.
- Parallel external matrix runs can now avoid false `Address already in use`
  failures by varying `--listen-port-start`, `--target-port-start`, and
  `--metrics-port`; a local xray-core + V2Ray pair of one-scenario matrix runs
  passed concurrently with distinct port ranges.

### Already satisfied by the current tree

- Invalid clusters such as `anytls-reality` and
  `reality-vision,anytls-vision` are rejected in code and covered by tests.
- Generated configs are validated through `wrongsv_server::Config::validate`
  before being written.
- Secret shapes and restrictive file permissions are tested, and
  `docs/security.md` explains that manifests contain secrets.
- Deploy dry-run already emits JSON and the deploy script performs checksum
  verification, stale-process cleanup, and config `0600` handling.
- The benchmark harness under `benches/traffic/` already parameterizes soak
  duration, rate, payload size, connection settings, shaping, and output
  metadata, and writes both JSON and CSV.
- CI already covers `cargo fmt`, `cargo clippy`, unit tests, integration tests,
  `cargo audit`, Node syntax checks, bash syntax checks, and warning-level
  `shellcheck`.
- CI now exercises the deploy script's dry-run path in addition to syntax.
- CI now also covers mocked success/failure deploy paths plus a localhost-`sshd`
  deploy using real `ssh`/`scp`.
- CI now also covers the mocked systemd/`journalctl` failure branch.
- Canonical docs entrypoints now exist for config generation, deploy, client
  compatibility, and benchmarks.

### Highest-priority open gaps

- Keep `hiddify:anytls_tcp` as a documented external E2E gap until a passing
  direct GUI run is recorded. The latest isolated focused rerun in
  `wrongsv-external-tests/results/hiddify-anytls-gap-isolated-2/` now reports
  `status = "gap_confirmed"` with the machine-readable reason
  `packaged Hiddify core rejected the generated AnyTLS outbound and never
  exposed the local mixed proxy port`. The matrix now carries
  `startupDebugArtifact`, `connectError`, and `gapReason`, and the referenced
  startup artifact embeds `lastConnectResult.connectError =
  "Left(ConnectionFailure.unexpected(error: failed to start background core, stackTrace: null))"`
  plus `runtimeSummary.requestedConfig`, whose outbound summary is still
  `protocol = "anytls"`, while `runtimeSummary.currentConfig` remains `null`.
  The same isolated artifact's `appLogTail` shows
  `decode config: outbounds[0]: unknown outbound type: anytls`, which rules
  out stale reused GUI state and keeps the remaining blocker on Hiddify's
  packaged runtime/core rather than `wrongsv`. A direct code-and-bundle scan
  now corroborates that runtime result: `scripts/inspect-hiddify-core.js`
  reports that Hiddify's editor source still lists `anytls`, but the current
  packaged `lib/hiddify-core.so` exposes no AnyTLS marker while still exposing
  ShadowTLS, Hysteria2, TUIC, and Xray wrapper markers through embedded
  `sing-box` `v1.8.9`. The newer app-manager path now also imports Hiddify
  configs through `ext.hiddify.importAndActivateConfig`, and a fresh
  `results/hiddify-anytls-app-import-native-1/` rerun still fails during
  `profileRepository.addLocal(...)` with
  `[SingboxParser] ... unknown outbound type: anytls`, so the raw SQLite import
  shortcut is no longer a plausible explanation for the standing gap.
  `generate-client-configs.js` now surfaces the same
  packaged-core gap reason in skipped client manifests, and its config-backed
  self-test now verifies the local CLI-side Hiddify export gate as well.
- No additional `wrongsv` server defect is currently confirmed by the expanded
  core-client debug coverage. The newest binary scans and focused process-debug
  reruns strengthened attribution for client/runtime gaps, but they did not
  add any new `defect_confirmed` scenario.
- Keep direct WebTransport xray-family export gated until a current
  xray/v2ray-compatible client config shape exists and has external capability
  metadata. The current `generate-client-configs.js --self-test --wrongsv-bin`
  path now verifies both that `configs/webtransport.toml` resolves to
  `vless_webtransport` and that `wrongsv --print-endpoint-diagnostics --format xray`
  plus `wrongsv --print-client-config --format xray` both report
  `WebTransport export is disabled pending an updated xray/v2ray-compatible client config shape`.
  This remains consistent with current upstream transport docs, which still do
  not define a WebTransport outbound/client shape for either Project X or
  V2Fly (`https://xtls.github.io/en/config/transports/`,
  `https://www.v2fly.org/en_US/v5/config/stream.html`).

### Current decision

- No additional unresolved `wrongsv`-side defect is currently known beyond the
  intentionally gated WebTransport xray-family export path. The remaining
  tracked gaps are:
  - the upstream or packaged-runtime Hiddify AnyTLS limitation
  - the local WebTransport client-export limitation, which now fails fast
    instead of emitting a stale config until a current client shape exists

## Scope

- CLI commands, flags, help text, and examples.
- Main TOML config generation and protocol component compatibility.
- Client config export for FlClash, clash-verge-rev, sing-box, Hiddify,
  xray-core, and v2ray.
- Remote deployment scripts and generated client artifacts.
- Server protocol handlers, TLS-like transports, fallback behavior, metrics,
  and evaluator paths.
- Existing unit, integration, external E2E, and benchmark coverage.

## Baseline Inventory

Capture and maintain the current state before making review-driven changes.

- Public commands:
  - Verified on 2026-06-17:
    - `wrongsv --help`
    - `wrongsv generate-main-config --help`
    - `wrongsv eval-server --help`
    - `wrongsv eval-client --help`
  - Result: all four help surfaces already include examples and supported
    values.
- Supported main config clusters:
  - Verified against `wrongsv generate-main-config --help`:
    - `reality-vision`
    - `anytls-vision`
    - `tls-vision`
    - `ws-tcp`
    - `httpupgrade`
    - `grpc`
    - `xhttp`
    - `vless-raw`
    - `hysteria2-gecko`
    - `hysteria2-salamander`
    - `tuic`
    - `trojan-tls`
    - `shadowsocks-2022`
    - `shadowsocks-aead`
    - `vmess`
- Client compatibility matrix:
  - Source of truth remains
    `wrongsv-external-tests/e2e-harness/capabilities.js`.
  - `scripts/generate-client-configs.js` already filters generation against
    that matrix.
  - Verified sample: `anytls_tcp` generated `flclash` and `sing-box`, and
    skipped `hiddify` and `xray-core` with explicit reasons.
  - Verified skip semantics:
    - `anytls_tcp` -> Hiddify uses `reasonCode = "harness_gap"`
    - `anytls_tcp` -> xray-core uses
      `reasonCode = "client_not_runnable_for_scenario"`
    - `vless_webtransport` uses `reasonCode = "scenario_untracked"` for every
      client until external capability metadata exists
- Existing benchmark inputs and outputs:
  - Criterion benches:
    - `benches/throughput.rs`
    - `benches/protocols.rs`
  - Traffic harness:
    - `benches/traffic/`
    - `benches/traffic/comprehensive/`
  - Published results:
    - `docs/bench-comprehensive.md`
    - `docs/bench-comprehensive.csv`
- Current CI-equivalent command set:
  - `.github/workflows/ci.yml` currently covers:
    - `cargo fmt --all -- --check`
    - `cargo clippy --workspace --all-targets -- -D warnings`
    - `cargo audit`
    - `cargo test --workspace --lib --bins`
    - `cargo build -p wrongsv --bin wrongsv`
    - `node scripts/generate-client-configs.js --self-test --wrongsv-bin target/debug/wrongsv`
    - `cargo test --workspace --tests`
    - `node --check scripts/generate-client-configs.js`
    - `node --check scripts/generate-main-configs.js`
    - `bash -n` on deploy and benchmark shell scripts
    - `shellcheck -S warning` on deploy and benchmark shell scripts
    - deploy dry-run, mocked success/failure deploy tests, and localhost-`sshd`
      deploy integration in the scripts job
  - This review round additionally verified:
    - `cargo build -p wrongsv --bin wrongsv`
    - `generate-client-configs.js --self-test`
    - `generate-client-configs.js --self-test --wrongsv-bin target/debug/wrongsv`
    - `scripts/deploy-remote.sh --dry-run`
    - `scripts/test-deploy-remote-mock.sh`
    - `scripts/test-deploy-remote-mock-failure.sh`
    - `scripts/test-deploy-remote-local-sshd.sh`
    - `scripts/test-deploy-remote-mock-systemd.sh`
    - `shellcheck -S warning` with ShellCheck 0.11.0
    - end-to-end local config generation -> diagnostics -> capability-gated
      client export for `anytls,vision`

## Security Review

Status: mostly green for config generation, validation, and secret-bearing file
handling.

- Confirmed this round:
  - `src/main_config.rs` uses `rand::rngs::OsRng` for generated secret material.
  - Generated TOML is validated through `wrongsv_server::Config::validate`.
  - Mutually exclusive protocol components are rejected before file write.
  - Negative tests already exist for `anytls-reality` and
    `reality-vision,anytls-vision`.
  - `src/main_config.rs`, `scripts/generate-client-configs.js`, and
    `scripts/deploy-remote.sh` all create or chmod secret-bearing files to
    `0600` on Unix when they control creation.
  - `docs/security.md` explicitly states that manifests contain secrets.
  - `cargo audit` now reports no vulnerabilities or warnings.
  - Manifest generation is now optional for safer sharing workflows, while
    staying enabled by default for reproducibility.

## Code Quality Review

Status: core product logic is already better separated than the original plan
assumed, but a few integration and maintenance gaps remain.

- Confirmed this round:
  - `src/main.rs` stays dispatch-oriented and help text is covered by tests.
  - `src/main_config.rs` centralizes cluster parsing, compatibility checks, and
    rendered-config validation.
  - `scripts/generate-client-configs.js` already separates capability
    filtering, raw config generation, runtime wrapping, and validation.
  - CI now enforces formatting, linting, tests, `cargo audit`, Node syntax,
    bash syntax, and warning-level `shellcheck`.
  - CI now also runs the internal `generate-client-configs.js` mapping/config
    self-test against a freshly built `target/debug/wrongsv`.
  - Deploy coverage now includes both dry-run and a mocked non-dry-run script
    path in CI, including the failure/log-tail branch and a localhost-`sshd`
    integration path using real `ssh`/`scp`.
- Remaining work:
  - A single shared metadata file still does not exist, but the new
    `generate-client-configs.js --self-test --wrongsv-bin ...` guard now
    catches scenario-naming drift across wrongsv diagnostics, JS generation,
    and the external harness. When `wrongsv-external-tests` is present, the
    main generation path now also uses the external scenario-mapping helper as
    its source of truth instead of a purely local mapping.
  - Decide whether `vless_webtransport` should gain explicit external scenario
    and capability metadata once a current xray/v2ray-compatible client shape
    exists, or remain intentionally untracked by capability-gated client
    generation.

## Testing Coverage Improvements

Status: broad coverage already exists and the wrongsv binary unit suite now has
snapshot-style regression guards for generated main configs and major client
export outputs.

- Confirmed this round:
  - Unit coverage already exists for:
    - valid and invalid clusters
    - randomized secret field shapes
    - TOML validation for all supported generated clusters
    - unsupported client export rejection cases
    - public help examples and supported values
  - Integration and lifecycle coverage already spans:
    - AnyTLS
    - REALITY
    - WebSocket
    - HTTPUpgrade
    - gRPC
    - XHTTP
    - KCP
    - QUIC
    - Shadowsocks AEAD and AEAD-2022
    - Trojan
    - sing-box, mihomo, and xray-core lifecycle suites
  - `cargo test --workspace` passed locally with no failures.
  - Capability-gated client export behavior was verified locally with an
    `anytls,vision` sample generation flow.
  - Snapshot fixtures now cover:
    - every supported generated main-config cluster
    - mihomo REALITY
    - mihomo AnyTLS
    - sing-box AnyTLS
    - xray REALITY
    - Hiddify ShadowTLS
    - Hiddify XHTTP
- Remaining work:
  - Keep `hiddify:anytls_tcp` documented as a gap until external direct E2E
    records a pass.
  - Add a mocked or dry-run-focused deploy test path if deploy behavior becomes
    more complex than the current shell smoke tests.

## Benchmark Improvements

Status: the benchmark harness is already substantially ahead of the original
plan, and a concrete regression policy is now documented.

- Confirmed this round:
  - Criterion microbenchmarks exist in:
    - `benches/throughput.rs`
    - `benches/protocols.rs`
  - The traffic harness under `benches/traffic/` already parameterizes:
    - protocol/config subset
    - soak duration
    - request rate
    - payload size
    - worker and connection settings
    - shaped vs unshaped networking
  - Comprehensive benchmark output already includes JSON, CSV, commit, OS, CPU,
    build profile, protocol config, and load parameters.
  - Published benchmark summaries already exist in
    `docs/bench-comprehensive.md` and `docs/bench-comprehensive.csv`.
  - A canonical benchmark entrypoint now exists at `docs/benchmarks.md`.
  - Benchmark regression thresholds and parameter presets are now documented in
    `docs/benchmarks.md`.
  - `.github/workflows/bench-smoke.yml` now provides a dedicated manual
    workflow for the documented presets, with an explicit manual-only policy.
- Remaining work:
  - Compare GitHub-hosted unshaped runs against any future self-hosted shaped
    runner policy before promoting benchmark runs into release gating.

## Mature Software Essentials

Status: help text, JSON-oriented automation surfaces, deploy dry-run, CI, and
canonical docs are already in place; remaining gaps are release-process polish
and policy documentation.

- Confirmed this round:
  - Every public command already has useful `--help`.
  - Long help includes supported values and examples where it matters.
- Automation-friendly JSON surfaces already exist:
    - `--print-endpoint-diagnostics`
    - `scripts/deploy-remote.sh --dry-run`
  - `--print-endpoint-diagnostics` now includes machine-readable
    `export.error_code` values when client export is unsupported.
  - `--dry-run` for deploy exists and was verified locally.
  - CI already covers fmt, clippy, tests, `cargo audit`, Node syntax, bash
    syntax, and warning-level `shellcheck`.
  - Canonical docs entrypoints now exist:
    - `docs/config-generation.md`
    - `docs/deploy.md`
    - `docs/client-compatibility.md`
    - `docs/benchmarks.md`
    - `docs/migration-notes.md`
    - `docs/testing.md`
- Remaining work:
  - Keep `docs/migration-notes.md` updated whenever CLI or client-generation
    behavior changes in user-visible ways.

## Initial Verification Commands

Run these before and after review-driven changes:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
cargo test --workspace
cargo build -p wrongsv --bin wrongsv
node --check scripts/generate-client-configs.js
node --check scripts/recheck-external-standing-limitations.js
node --check scripts/verify-review-evidence.js
node --check scripts/verify-external-review-evidence.js
node scripts/generate-client-configs.js --self-test --wrongsv-bin target/debug/wrongsv
node scripts/generate-client-configs.js --self-test --external-tests-root ../wrongsv-external-tests
node scripts/generate-client-configs.js --self-test --wrongsv-bin target/debug/wrongsv --external-tests-root ../wrongsv-external-tests
node scripts/verify-review-evidence.js --skip-external --output-file /tmp/wrongsv-review-evidence-summary.json
node scripts/verify-review-evidence.js --standing-only xray-webtransport
node scripts/recheck-external-standing-limitations.js --only xray-webtransport
node scripts/verify-external-review-evidence.js --standing-only xray-webtransport
node --check scripts/generate-main-configs.js
bash -n scripts/deploy-remote.sh
bash -n scripts/deploy_remote.sh
scripts/deploy-remote.sh example.invalid --dry-run \
  --config configs/anytls-vision.toml \
  --server-host 203.0.113.10 \
  --no-client-configs
scripts/test-deploy-remote-mock.sh
scripts/test-deploy-remote-mock-failure.sh
scripts/test-deploy-remote-local-sshd.sh
scripts/test-deploy-remote-mock-systemd.sh
shellcheck -S warning \
  scripts/deploy-remote.sh \
  scripts/deploy_remote.sh \
  scripts/eval-remote.sh \
  benches/traffic/run.sh \
  benches/traffic/setup.sh \
  benches/traffic/comprehensive/matrix.sh \
  benches/traffic/comprehensive/lib/certs.sh \
  benches/traffic/comprehensive/lib/load.sh \
  benches/traffic/comprehensive/lib/memory.sh \
  benches/traffic/comprehensive/lib/netem.sh \
  benches/traffic/comprehensive/lib/server.sh \
  benches/traffic/scenarios/multi-user-sim.sh \
  benches/traffic/scenarios/reality-stress.sh \
  benches/traffic/scenarios/throughput-ladder.sh \
  benches/traffic/scenarios/tls-handshake.sh
```

Status: all commands above passed locally on 2026-06-17.

Run generation and client compatibility checks:

```bash
target/debug/wrongsv generate-main-config --cluster anytls,vision --output-dir /tmp/wrongsv-anytls
target/debug/wrongsv --config /tmp/wrongsv-anytls/anytls-vision.toml \
  --print-endpoint-diagnostics \
  --server-host 127.0.0.1 \
  --servername cloudfront.net
node scripts/generate-client-configs.js \
  --wrongsv-bin target/debug/wrongsv \
  --config /tmp/wrongsv-anytls/anytls-vision.toml \
  --external-tests-root ../wrongsv-external-tests \
  --output-dir /tmp/wrongsv-anytls-clients \
  --server-host 127.0.0.1 \
  --servername cloudfront.net \
  --clients flclash,hiddify,sing-box,xray-core
```

Status: verified locally on 2026-06-17. The AnyTLS sample generated FlClash and
sing-box configs and skipped Hiddify and xray-core according to external
capability metadata.

## Next Review Iterations

1. Keep the external Hiddify AnyTLS gap under review until a direct GUI pass is
   recorded in `wrongsv-external-tests`.

## Acceptance Criteria

The review is complete when:

- [done] Security findings are classified and tracked.
- [done] Every supported cluster has positive tests.
- [done] Invalid clusters fail deterministically.
- [done] FlClash AnyTLS remains covered.
- [done] Client compatibility is generated from external-test capability
  metadata.
- [done] Benchmarks accept parameters and record environment metadata.
- [done] Every public command has useful help and examples.
