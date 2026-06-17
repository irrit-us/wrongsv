# Client Compatibility

This page is the canonical entrypoint for how wrongsv-generated server configs
become client runtime configs and how external client compatibility is tracked.

## Source Of Truth

- `scripts/generate-client-configs.js`
- `../wrongsv-external-tests/e2e-harness/capabilities.js` when the sibling repo
  is checked out next to `wrongsv/`
- `../wrongsv-external-tests/docs/client-capability-audit.md` for the latest
  protocol-by-client audit

## Supported Client Families

The current external harness knows how to adapt wrongsv output for:

- `flclash`
- `clash-verge-rev`
- `sing-box`
- `hiddify`
- `xray-core`
- `v2ray`

Generation succeeds only when the external capability metadata says a scenario
is runnable for that client and not currently marked as a harness gap.

## Generation Flow

`scripts/generate-client-configs.js` performs these steps:

1. load capability and scenario metadata from `wrongsv-external-tests`
2. run `wrongsv --print-endpoint-diagnostics` on the selected server config
3. map that diagnostic shape onto a scenario ID such as `anytls_tcp` or
   `vless_reality_vision`
4. ask wrongsv for the raw client config format that the external harness
   expects for that client and scenario
5. validate the raw structure and wrap it into a runtime artifact
6. write `manifest.json`, `manifest.md`, runtime files, and raw JSON copies

That scenario mapping is intentionally more specific than a coarse
"VLESS + TLS" bucket. For example, `meek`, `gdocsviewer`, and
`webtransport` keep distinct scenario IDs instead of collapsing into generic
TLS or raw-TCP VLESS cases.

When `wrongsv-external-tests` is present, the main generation path now uses the
external harness helper in `e2e-harness/scenarios.js` as its scenario-mapping
source of truth. The local mapping function remains as a sibling-repo-free
fallback and is checked for drift in `--self-test`.

When `--print-endpoint-diagnostics` is called with a client `--format`, the
`export` block now also carries a machine-readable `error_code` whenever
`supported` is `false`.

## Quick Start

```bash
cargo build -p wrongsv --bin wrongsv

target/debug/wrongsv generate-main-config \
  --cluster anytls,vision \
  --output-dir /tmp/wrongsv-anytls

node scripts/generate-client-configs.js \
  --wrongsv-bin target/debug/wrongsv \
  --config /tmp/wrongsv-anytls/anytls-vision.toml \
  --external-tests-root ../wrongsv-external-tests \
  --output-dir /tmp/wrongsv-anytls-clients \
  --server-host 127.0.0.1 \
  --servername cloudfront.net \
  --clients flclash,hiddify,sing-box,xray-core
```

The script also has a built-in mapping self-test:

```bash
node scripts/generate-client-configs.js \
  --self-test \
  --external-tests-root ../wrongsv-external-tests
```

Add `--json` when you want a machine-readable summary instead of the plain
`generate-client-configs self-test OK` line:

```bash
node scripts/generate-client-configs.js \
  --self-test \
  --json \
  --wrongsv-bin target/debug/wrongsv \
  --external-tests-root ../wrongsv-external-tests
```

Pass `--wrongsv-bin` when you want that self-test to also verify real
representative configs from `configs/`:

```bash
node scripts/generate-client-configs.js \
  --self-test \
  --wrongsv-bin target/debug/wrongsv \
  --external-tests-root ../wrongsv-external-tests
```

If `wrongsv-external-tests` is unavailable, the self-test still runs the
internal scenario-mapping and config-backed checks. External capability
assertions are skipped in that mode, which is how the guard now runs in CI.
That config-backed mode also verifies:

- the current WebTransport xray export gate through both
  `--print-endpoint-diagnostics` and `--print-client-config`
- the current Hiddify AnyTLS export gate through both
  `--print-endpoint-diagnostics` and `--print-client-config`

When `wrongsv-external-tests` is available, the same self-test also exercises
real generation runs to verify manifest-level outcomes for:

- `reasonCode = "scenario_untracked"`
- `reasonCode = "harness_gap"`
- drifted family-export failures such as
  `reasonCode = "hiddify_anytls_packaged_core_gap"`
- success stdout / failure stderr summary fields such as
  `exportPreflight`, `generatedCount`, and top-level `reasonCode`

For safer sharing workflows, the script can skip its manifest files:

```bash
node scripts/generate-client-configs.js \
  --wrongsv-bin target/debug/wrongsv \
  --config /tmp/wrongsv-anytls/anytls-vision.toml \
  --external-tests-root ../wrongsv-external-tests \
  --output-dir /tmp/wrongsv-anytls-shareable \
  --server-host 127.0.0.1 \
  --servername cloudfront.net \
  --clients flclash,sing-box \
  --no-manifest
```

## Output Layout

Example output directory:

```text
/tmp/wrongsv-anytls-clients/
├── flclash.yaml
├── sing-box.json
├── manifest.json
├── manifest.md
└── raw/
    ├── flclash-mihomo.json
    └── sing-box-sing-box.json
```

`manifest.json` records:

- the selected scenario ID
- the endpoint diagnostics used to derive that scenario
- `exportPreflight`, keyed by direct client-family format (`mihomo`,
  `sing-box`, `hiddify`, `xray`)
- generated client files
- skipped clients, their `reasonCode`, and human-readable reasons
- failed clients, their `reasonCode`, and their error text

The output files are written with restrictive permissions on Unix-like systems
when the script controls file creation.

`--no-manifest` suppresses both `manifest.json` and `manifest.md`, but still
generates the runtime files and raw JSON copies.

When the command exits non-zero, stderr now emits a machine-readable JSON
summary with:

- top-level `reasonCode`
- `scenarioId`
- `generatedCount`
- `skipped`
- `failed`

## Skip And Gap Semantics

Client generation is intentionally not "best effort" for unsupported
combinations.

- If a scenario is not in `runnableScenarios`, the client is skipped.
- If a scenario is in `harnessGaps`, the client is skipped with the
  machine-readable gap reason from `wrongsv-external-tests` when available.
- If diagnostics resolve to a distinct scenario that is not yet represented in
  the external capability metadata, the script preserves that scenario ID in
  the manifest and skips all clients instead of silently treating the config as
  a more generic VLESS case.
- If capability metadata says a client should be generated but the direct
  client-family export is currently unsupported, the script now records a
  `manifest.failed[*].reasonCode` derived from
  `--print-endpoint-diagnostics` `export.error_code` instead of silently
  emitting a wrapper artifact from the raw harness format.
- If wrongsv returns a structurally invalid raw config for the expected runtime,
  the client is marked as failed.

Current `manifest.json` `skipped[*].reasonCode` values include:

- `harness_gap`
- `scenario_untracked`
- `client_not_runnable_for_scenario`
- `scenario_unrecognized`

Current `manifest.json` `failed[*].reasonCode` values can include:

- `unknown_client`
- direct export gate codes such as
  `hiddify_anytls_packaged_core_gap`
- structural pipeline codes such as
  `raw_config_invalid_json`, `raw_config_shape_invalid`,
  `runtime_artifact_generation_failed`, or `output_write_failed`

`manifest.json` `exportPreflight.<format>` entries record:

- `clients`
- `supported`
- `reasonCode`
- `error`

Current top-level stderr summary `reasonCode` values include:

- `no_compatible_client_configs_generated`
- `client_generation_failed`

Current `--print-endpoint-diagnostics` `export.error_code` values include:

- `hiddify_anytls_packaged_core_gap`
- `webtransport_xray_family_export_disabled`

Example: `anytls_tcp` currently generates FlClash, clash-verge-rev, and
sing-box configs, while Hiddify remains gated until a passing direct GUI E2E
run is recorded and xray-family clients remain non-runnable for AnyTLS. The
current Hiddify skip reason is surfaced as
`packaged Hiddify core rejected the generated AnyTLS outbound and never exposed the local mixed proxy port`.
The direct CLI Hiddify export gate now includes that same packaged-core reason
plus `export.error_code = "hiddify_anytls_packaged_core_gap"` in
`--print-endpoint-diagnostics --format hiddify` and
`--print-client-config --format hiddify`. If capability metadata ever drifts
and incorrectly marks Hiddify AnyTLS runnable, client generation now fails with
that same `manifest.failed[*].reasonCode` instead of producing a wrapper
artifact from the raw sing-box export.

Additional examples:

- `configs/meek.toml` now resolves to `vless_meek` and generates only `v2ray`.
- `configs/gdocsviewer.toml` now resolves to `vless_gdocsviewer` and generates
  only `v2ray`.
- `configs/webtransport.toml` now resolves to `vless_webtransport`. Because
  `wrongsv-external-tests` now records that scenario as intentionally
  untracked in external capability metadata rather than runnable or a harness
  gap, and direct `--format xray` export is currently gated pending an
  updated xray/v2ray-compatible client shape, capability-gated generation
  skips every client with `reasonCode = "scenario_untracked"` and exits
  non-zero instead of mislabeling the config as generic TLS VLESS. The direct
  diagnostics surface also reports
  `export.error_code = "webtransport_xray_family_export_disabled"`. The
  external matrix now also records focused explicit probes as
  `status = "untracked_confirmed"` for xray-core and V2Ray/V2Fly.
 - an AnyTLS sample with `--clients flclash,hiddify,xray-core` now records
   `exportPreflight.mihomo.supported = true`,
   `exportPreflight.hiddify.reasonCode = "hiddify_anytls_packaged_core_gap"`,
   and `exportPreflight.xray.reasonCode = "anytls_format_unsupported"`.
  This is also consistent with the current upstream transport docs:
  Project X currently documents `network` values `raw`, `xhttp`, `mkcp`,
  `grpc`, `websocket`, `httpupgrade`, and `hysteria`, while V2Fly currently
  documents TCP, WebSocket, mKCP, gRPC, QUIC, Meek, Google Docs Viewer,
  HTTPUpgrade, and Hysteria2 stream transports, with no WebTransport outbound
  shape documented for either family.
  Source refs:
  `https://xtls.github.io/en/config/transports/`
  `https://www.v2fly.org/en_US/v5/config/stream.html`

## External Verification

Use the sibling repo for end-to-end validation:

```bash
cd ../wrongsv-external-tests

node run-client-suite.js --client flclash
node run-client-suite.js --client sing-box
node run-client-suite.js --client xray-core \
  --wrongsv-config ../wrongsv/configs/reality-vision.toml

node run-client-matrix.js --client clash-verge-rev
node run-client-matrix.js --client v2ray
```

For the latest per-client coverage status and harness gaps, use
`../wrongsv-external-tests/docs/client-capability-audit.md`.
