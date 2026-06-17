# Deploy

`scripts/deploy-remote.sh` is the canonical automated deploy entrypoint for
`wrongsv`. `scripts/deploy_remote.sh` is a compatibility wrapper that forwards
to the hyphenated script and remains intentionally available for existing
callers.

For a manual TLS / REALITY walkthrough that shows the underlying service and
client steps without the automation wrapper, see
[simple-deploy.md](simple-deploy.md).

## Prerequisites

The deploy script runs locally and expects:

- a working Rust toolchain
- `ssh` and `scp`
- `python3`
- `node`
- access to the remote host
- the sibling repo `../wrongsv-external-tests` if client config generation is
  enabled

The remote host only needs SSH access plus whatever runtime environment the
chosen config requires.

## Build Notes

Current release/build reproducibility notes:

- Rust is pinned by [rust-toolchain.toml](../rust-toolchain.toml) to `1.93.0`.
- CI and release automation build from a checked-out Git commit using the repo's
  committed `Cargo.lock`.
- Release artifacts are currently produced for:
  - `x86_64-unknown-linux-gnu`
  - `x86_64-unknown-linux-musl`
  - `x86_64-pc-windows-msvc`
  - `x86_64-unknown-freebsd`
- The release workflow is the source of truth for target-specific toolchain
  setup, including `musl-tools`, `cross`, and `protoc`.

Current limitations:

- The repo documents a pinned toolchain and release matrix, but it does not
  claim bit-for-bit reproducible binaries across machines.
- Linux release packaging strips native binaries after build, which is another
  source of output variation to keep in mind when comparing local artifacts to
  release artifacts.
- If you want the closest local match to the Linux release artifact, prefer the
  release target path used by CI:

```bash
cargo build --release --target x86_64-unknown-linux-musl -p wrongsv --bin wrongsv
```

## Dry Run First

Use dry-run to validate paths, defaults, and derived values without building or
contacting the remote host:

```bash
scripts/deploy-remote.sh example.invalid --dry-run \
  --config configs/anytls-vision.toml \
  --server-host 203.0.113.10 \
  --no-client-configs
```

Dry-run prints a JSON deployment plan and does not run `ssh`, `scp`, `cargo`,
remote commands, or client generation.

## Real Deploy

```bash
scripts/deploy-remote.sh root@203.0.113.10 \
  --config configs/reality-vision.toml \
  --server-host 203.0.113.10 \
  --servername download-porter.hoyoverse.com \
  --clients flclash,sing-box
```

When `--output-dir` is omitted, generated client artifacts go under
`deploy-output/<host>-<timestamp>/`.

## What The Script Does

On a real deploy, `scripts/deploy-remote.sh` will:

1. build `wrongsv` for the selected target and profile
2. derive endpoint diagnostics from the selected config
3. stop an existing systemd unit or stray `wrongsv` process on the remote host
4. upload the binary and config
5. set executable and restrictive config permissions
6. verify the uploaded binary checksum
7. start the systemd unit if present, otherwise launch `wrongsv` directly
8. perform a TCP reachability check or a process check for UDP-only listeners
9. optionally generate capability-gated client configs locally

## Common Options

- `--config` selects the main TOML config to deploy.
- `--remote-dir` changes the remote install directory.
- `--service` changes the systemd service name.
- `--target` and `--profile` control the build artifact.
- `--server-host` sets the address written into generated client configs.
- `--servername` sets the SNI / server name written into generated client
  configs.
- `--clients` limits generated client files to a CSV subset.
- `--no-manifest` skips `manifest.json` and `manifest.md` in the local client
  output directory.
- `--no-client-configs` skips local client config generation.
- `--output-dir` selects where the generated client artifacts are written.

If `--servername` is omitted, the script derives it from the REALITY `dest`
when present, otherwise from the resolved server host.

## Client Generation

When client generation is enabled, the deploy script calls
`scripts/generate-client-configs.js` after the remote listener check passes.
That output is capability-gated against `wrongsv-external-tests`.

If you need shareable client artifacts without the manifest files, add
`--no-manifest` to the deploy command. The generated client runtime files still
contain credentials and remain secret-bearing.

See [client-compatibility.md](client-compatibility.md) for the runtime config
generation details and skip behavior.

## Manual Walkthrough

Use [simple-deploy.md](simple-deploy.md) when you want to:

- install a released binary manually
- write the systemd unit yourself
- compare the automated script against the underlying TLS or REALITY steps

## Verification

Useful follow-up commands:

```bash
ssh root@203.0.113.10 journalctl -u wrongsv -f

target/debug/wrongsv \
  --config configs/reality-vision.toml \
  --print-endpoint-diagnostics \
  --server-host 203.0.113.10 \
  --servername download-porter.hoyoverse.com
```

Secret-bearing deployment artifacts are covered by [security.md](security.md).
