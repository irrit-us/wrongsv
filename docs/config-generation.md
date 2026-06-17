# Config Generation

`wrongsv generate-main-config` is the canonical entrypoint for producing a
deployable main TOML config, validating it, and carrying it into diagnostics or
client export.

## Source Of Truth

- CLI help:
  `cargo run -q -p wrongsv --bin wrongsv -- generate-main-config --help`
- Convenience wrapper:
  `node scripts/generate-main-configs.js`
- Validation path:
  `wrongsv_server::Config::validate`
- Secret-handling notes:
  [security.md](security.md)

## Quick Start

```bash
cargo build -p wrongsv --bin wrongsv

target/debug/wrongsv generate-main-config \
  --cluster reality-vision \
  --output-dir /tmp/wrongsv-reality

target/debug/wrongsv generate-main-config \
  --cluster anytls,vision \
  --output-dir /tmp/wrongsv-anytls

node scripts/generate-main-configs.js \
  --cluster vmess \
  --output-dir /tmp/wrongsv-vmess
```

## Selecting A Cluster

Use `--help` for the authoritative current list. The currently supported preset
clusters are:

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

Component form also works with comma or plus separators:

```bash
target/debug/wrongsv generate-main-config --cluster anytls,vision
target/debug/wrongsv generate-main-config --cluster reality+vision
```

Mutually exclusive combinations are rejected before any files are written. For
example, `anytls-reality` and `reality-vision,anytls-vision` are invalid.

## Common Options

- `--cluster` selects the preset or component combination.
- `--output` writes one TOML file.
- `--output-dir` writes the TOML file plus manifest files.
- `--no-manifest` skips `manifest.json` while keeping the TOML file and
  `README.md`.
- `--listen` overrides the bind address.
- `--email` sets the generated user email / metrics key.
- `--reality-dest` sets the REALITY fallback / spider destination.
- `--fallback-dest` sets the fallback destination for TLS-like protocols.
- `--shadowsocks-method` picks the 2022 method for `shadowsocks-2022`.
- `--tuic-congestion` sets the TUIC congestion controller.

## Output Layout

`--output` writes a single TOML file.

`--output-dir` writes:

- `<cluster>.toml`
- `manifest.json`
- `README.md`

On Unix-like systems these files are written with mode `0600` when wrongsv
controls file creation. `manifest.json` intentionally includes generated
credentials, so treat it like the main config file.

If you want a directory output without the secret-bearing manifest metadata, add
`--no-manifest`:

```bash
target/debug/wrongsv generate-main-config \
  --cluster anytls,vision \
  --output-dir /tmp/wrongsv-anytls-shareable \
  --no-manifest
```

## Validation

Every generated config is:

1. rendered from the selected cluster
2. parsed back into `wrongsv_server::Config`
3. validated through `wrongsv_server::Config::validate`

Generation fails if the rendered TOML is not accepted by the runtime config
validator.

## Follow-Up Commands

Inspect the effective endpoint stack:

```bash
target/debug/wrongsv \
  --config /tmp/wrongsv-anytls/anytls-vision.toml \
  --print-endpoint-diagnostics \
  --server-host 127.0.0.1 \
  --servername cloudfront.net
```

Generate capability-gated client configs from the same TOML:

```bash
node scripts/generate-client-configs.js \
  --wrongsv-bin target/debug/wrongsv \
  --config /tmp/wrongsv-anytls/anytls-vision.toml \
  --external-tests-root ../wrongsv-external-tests \
  --output-dir /tmp/wrongsv-anytls-clients \
  --server-host 127.0.0.1 \
  --servername cloudfront.net \
  --clients flclash,hiddify,sing-box,xray-core
```

See [client-compatibility.md](client-compatibility.md) for the capability and
runtime-export flow.
