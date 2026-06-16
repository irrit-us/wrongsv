# wrongsv Review Plan

This plan covers `wrongsv` as a deployable server and CLI product, including
main config generation, remote deployment, client config export, external E2E
compatibility, and performance benchmarks.

## Scope

- CLI commands, flags, help text, and examples.
- Main TOML config generation and protocol component compatibility.
- Client config export for FlClash, clash-verge-rev, sing-box, Hiddify, xray-core, and v2ray.
- Remote deployment scripts and generated client artifacts.
- Server protocol handlers, TLS-like transports, fallback behavior, metrics, and evaluator paths.
- Existing unit, integration, external E2E, and benchmark coverage.

## Baseline Inventory

Capture the current state before making review-driven changes:

- Public commands:
  - `wrongsv --help`
  - `wrongsv generate-main-config --help`
  - `wrongsv eval-server --help`
  - `wrongsv eval-client --help`
- Supported main config clusters:
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
- Client compatibility matrix from `wrongsv-external-tests/e2e-harness/capabilities.js`.
- Existing benchmark inputs and outputs.
- Current CI-equivalent command set.

## Security Review

Review the following areas with findings classified by severity.

- Secret generation:
  - Confirm UUIDs, REALITY private keys, REALITY short IDs, AnyTLS passwords,
    Shadowsocks PSKs, TUIC passwords, and Trojan passwords use CSPRNG.
  - Verify generated key and password lengths match protocol requirements.
  - Decide whether generated manifests should include secrets; if they do,
    document this clearly and set restrictive file permissions where practical.
- Config validation:
  - Reject mutually exclusive protocol components before writing files.
  - Validate every generated TOML through `wrongsv_server::Config::validate`.
  - Add negative tests for invalid clusters such as `anytls-reality` and
    `reality-vision,anytls-vision`.
- Remote deployment:
  - Review SSH command quoting, remote path handling, service restart behavior,
    checksum verification, stale-process handling, and log output.
  - Ensure deploy scripts fail closed when `--config` is missing or invalid.
  - Avoid leaking generated secrets in stdout, logs, shell traces, or error text.
- Client export:
  - Ensure unsupported client/protocol combinations fail or skip predictably.
  - Keep FlClash AnyTLS support explicitly tested and capability-gated.
  - Confirm generated client configs do not silently omit required credentials.
- TLS and transport defaults:
  - Review `skip-cert-verify`, self-signed TLS defaults, SNI defaults, fallback
    destinations, and padding defaults.
  - Document which generated configs are intended for local test, remote E2E, or
    production-like deployment.
- Supply chain:
  - Add or document `cargo audit` and/or `cargo deny`.
  - Review Node helper scripts for dependency-free behavior or pinned dependencies.

## Code Quality Review

- CLI structure:
  - Keep `main.rs` focused on dispatch.
  - Put product logic in modules or library crates.
  - Prefer actionable errors over panics.
- Config generation:
  - Centralize protocol component compatibility rules.
  - Prefer typed config rendering where practical.
  - Avoid duplicating protocol names across generator, diagnostics, and E2E harness.
- Client generation:
  - Separate capability filtering, raw config generation, runtime wrapping, and validation.
  - Add golden snapshots for major outputs.
  - Keep external-test capability assumptions explicit.
- Scripts:
  - Keep shell scripts thin.
  - Move product logic into Rust subcommands.
  - Add `shellcheck` coverage for shell scripts if they remain operationally important.
- Error handling:
  - Ensure user-facing CLI errors contain enough context.
  - Ensure automation-facing commands return stable non-zero exit codes on failure.

## Testing Coverage Improvements

- Unit tests:
  - Component compatibility matrix for valid and invalid clusters.
  - Randomized field shape: UUID format, key length, base64 length, hex length.
  - TOML validation for every generated cluster.
  - Client export rejection cases.
- Golden tests:
  - Generated main configs for each supported cluster.
  - Client configs for FlClash AnyTLS, FlClash REALITY, sing-box AnyTLS,
    Hiddify ShadowTLS/XHTTP, and xray REALITY.
  - Hiddify AnyTLS must remain a skip/negative case until
    `wrongsv-external-tests` records a passing direct GUI run.
- Integration tests:
  - `wrongsv generate-main-config` -> diagnostics -> client config generation.
  - Deploy dry-run or mocked SSH path.
  - Generated configs consumed by `wrongsv-external-tests` helpers.
- External E2E:
  - `flclash:anytls_tcp`
  - `flclash:vless_reality_vision`
  - `sing-box:anytls_tcp`
  - `hiddify:shadowtls_tcp`
  - `hiddify:anytls_tcp` as a documented gap until direct E2E passes
  - `xray-core:vless_reality_vision`
- Negative tests:
  - `anytls-reality` must fail.
  - `reality-vision,anytls-vision` must fail.
  - Unsupported client/protocol combinations must skip or fail predictably.

## Benchmark Improvements

- Parameterize benches:
  - Protocol or cluster.
  - Payload size.
  - Concurrency.
  - Connection count.
  - Test duration.
  - Warmup duration.
  - TCP versus UDP where applicable.
- Capture metrics:
  - Throughput.
  - p50, p95, and p99 latency.
  - Handshake time.
  - CPU and memory where available.
  - Error rate and reconnect behavior.
- Output format:
  - JSON and CSV.
  - Include commit, OS, CPU, build profile, protocol config, and benchmark parameters.
- Regression policy:
  - Define acceptable deltas for major protocol paths.
  - Keep benchmark parameter sets small enough for CI and broad enough for nightly runs.

## Mature Software Essentials

- Command help:
  - Every public command must have useful `--help`.
  - Long help should include supported values and examples.
  - Automation-friendly commands should support JSON output where useful.
- Documentation:
  - `docs/config-generation.md`
  - `docs/deploy.md`
  - `docs/client-compatibility.md`
  - `docs/security.md`
  - `docs/benchmarks.md`
- Operational UX:
  - `--dry-run` for deploy.
  - Consistent exit codes.
  - Clear generated manifests.
  - Clear distinction between local test defaults and production-like defaults.
- Release quality:
  - CI for fmt, clippy, tests, shell syntax, and Node script checks.
  - Versioned changelog.
  - Reproducible build notes.
  - Migration notes when CLI behavior changes.

## Initial Verification Commands

Run these before and after review-driven changes:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build -p wrongsv --bin wrongsv
node --check scripts/generate-client-configs.js
node scripts/generate-client-configs.js --self-test --external-tests-root ../wrongsv-external-tests
node --check scripts/generate-main-configs.js
bash -n scripts/deploy-remote.sh
bash -n scripts/deploy_remote.sh
```

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

## Acceptance Criteria

The review is complete when:

- Security findings are classified and tracked.
- Every supported cluster has positive tests.
- Invalid clusters fail deterministically.
- FlClash AnyTLS remains covered.
- Client compatibility is generated from external-test capability metadata.
- Benchmarks accept parameters and record environment metadata.
- Every public command has useful help and examples.
