# Migration Notes

This page records user-visible behavior changes that matter when upgrading
`wrongsv`, especially around config generation, client export, and deployment
automation.

## 2026-06 Review Round

### Capability-gated client generation is stricter

- `scripts/generate-client-configs.js` now preserves distinct scenario IDs for
  `meek`, `gdocsviewer`, and `webtransport` instead of collapsing them into
  generic VLESS TLS/raw buckets.
- When `wrongsv-external-tests` is present, `generate-client-configs.js` now
  uses the external scenario-mapping helper as its source of truth and checks
  the local fallback mapper against it during `--self-test`.
- `manifest.json` skipped entries now also include a machine-readable
  `reasonCode`, for example `harness_gap`, `scenario_untracked`, or
  `client_not_runnable_for_scenario`.
- `manifest.json` failed entries now also include a machine-readable
  `reasonCode`. When a direct family export is unsupported, that value now
  reuses the same `export.error_code` surfaced by
  `--print-endpoint-diagnostics`.
- `manifest.json` now also includes an `exportPreflight` block keyed by direct
  client-family format, so generated artifacts can record which families were
  supported, skipped, or locally gated before any harness wrapping happened.
- Non-zero exits now also emit a machine-readable stderr summary with a
  top-level `reasonCode`, `scenarioId`, `generatedCount`, `skipped`, and
  `failed`.
- As a result:
  - `configs/meek.toml` now resolves to `vless_meek` and generates only the
    `v2ray` client artifact.
  - `configs/gdocsviewer.toml` now resolves to `vless_gdocsviewer` and
    generates only the `v2ray` client artifact.
  - `configs/webtransport.toml` now resolves to `vless_webtransport`. Because
    external capability metadata now records that scenario as intentionally
    untracked rather than runnable or a harness gap, capability-gated
    generation skips every client with
    `reasonCode = "scenario_untracked"` and exits non-zero instead of silently
    treating the config as generic VLESS over TLS. Focused external matrix runs
    for xray-core and V2Ray/V2Fly now also record that state as
    `status = "untracked_confirmed"`.

### Direct WebTransport xray export is now gated

- `wrongsv --print-client-config --format xray` for WebTransport configs now
  fails fast with:
  `WebTransport export is disabled pending an updated xray/v2ray-compatible client config shape`
- This replaces the earlier behavior where `wrongsv` emitted a QUIC-shaped
  xray config that no longer interoperated with current xray-core/V2Ray probes.
- `--print-endpoint-diagnostics --format xray` now reports the same export as
  unsupported in its `export.error` field and
  `export.error_code = "webtransport_xray_family_export_disabled"`.

### Direct Hiddify AnyTLS export now carries the packaged-core reason

- `wrongsv --print-client-config --format hiddify` for AnyTLS configs now
  fails with:
  `Hiddify AnyTLS export is disabled: packaged Hiddify core rejected the generated AnyTLS outbound and never exposed the local mixed proxy port; use --format mihomo for FlClash or --format sing-box`
- `--print-endpoint-diagnostics --format hiddify` now reports the same
  packaged-core reason in its `export.error` field and
  `export.error_code = "hiddify_anytls_packaged_core_gap"`.
- This aligns the direct CLI export gate with the machine-readable gap reason
  already used by capability-gated client generation and the external Hiddify
  audit trail. If capability metadata drifts and incorrectly marks Hiddify
  AnyTLS runnable, capability-gated generation now fails with the same
  `manifest.failed[*].reasonCode` instead of producing a wrapper artifact from
  the raw sing-box export.

### Self-test behavior changed

- `node scripts/generate-client-configs.js --self-test` still performs the
  mapping and capability checks when `wrongsv-external-tests` is available.
- `node scripts/generate-client-configs.js --self-test --json` now emits a
  machine-readable local summary (`status`, `usedHarness`,
  `usedWrongsvBin`, case counts, and notes) instead of the plain `OK` line.
- When the sibling repo is not checked out, the self-test now falls back to the
  internal scenario-mapping and config-backed checks instead of failing.
- CI uses that sibling-repo-free mode together with
  `--wrongsv-bin target/debug/wrongsv`.
- With the sibling repo present, the self-test now also runs end-to-end
  generation probes to validate manifest `reasonCode` behavior for untracked
  scenarios, harness gaps, and drifted family-export failures, plus the
  structured stdout/stderr summary payloads.
