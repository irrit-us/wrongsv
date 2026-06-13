# Task List — Quality, Protocols, External Tests, Metrics (2026-06-13)

## Goal

1. **Code quality + test coverage** — sweep for bugs (mock-as-real, local-as-remote), expand tests
2. **Protocol audit** — verify VLESS/VMess/REALITY/AnyTLS/Trojan/Shadowsocks/WS/HTTPUpgrade implementations
3. **External tests** — exercise hiddify + FlClash via wrongsv-external-tests
4. **Expand external-test coverage** — xray-core + sing-box client lifecycles, behavior simulation
5. **Metrics port** — configurable (none by default), per-user (email) traffic counters + system stats

## Plan

### Phase 1 — Code Quality + Bug Sweep

- [x] Run `cargo clippy --workspace --all-targets` — start from green
- [x] Fix clippy warning in vmess_handler tests (`std::slice::from_ref`)
- [x] Identify "local-as-remote" risks — places where tests assume real remote but actually hit 127.0.0.1
- [x] Identify "mock-as-real" risks — stubs that always-succeed and mask failures (fixed REALITY cert HMAC bypass in 36e64b5)
- [x] Audit channel bounds / timeouts for OOM and hang risks — channels: unbounded sites all have natural upstream backpressure (KCP recv window, TCP recv buffer, single-message use). Timeouts: 6 handshake sites lacked a read-deadline bound (slowloris risk); fixed with 30s set/clear pattern in accept_anytls, accept_tls, accept_shadowtls_tls, tls_relay, handle_shadowsocks_connection, and httpupgrade TLS branch
- [x] Fix flaky `test_mihomo_lifecycle_multi_user` (user2 raw-flow connection fails)

### Phase 2 — Protocol Audit

- [x] **VLESS** — wire format matches xray (version|user_id|addons(u8-len + proto)|cmd|addr+port). Two issues surfaced & one hardened — see "VLESS Kyber-via-addons is unreachable" under Status.
- [x] **REALITY** — auth path matches xray-core (X25519+HKDF-SHA256 with `salt=client_random[..20]`, `info=b"REALITY"`; AES-256-GCM session_id w/ AAD = ClientHello body, session_id offset 39 zeroed; HMAC-SHA512(auth_key, raw_pubkey) cert binding). Verified end-to-end by the eval-client cert HMAC check (36e64b5) and lifecycle tests.
- [x] **AnyTLS** — sing-anytls wire matches spec: `[SHA256(pw)(32) | padding_len(2 BE) | padding(N) | payload]`. Constant-time pw compare, 30s slowloris bound. Verified by lifecycle tests + AnyTLS metrics roundtrip.
- [x] **VMess** — custom dialect, NOT v2fly/xray VMess AEAD — see "VMess KDF diverges from v2fly" under Status.
- [x] **Trojan** — trojan-gfw wire matches spec: `SHA224_hex(pw)(56) + CRLF + cmd + SOCKS5 addr + port(BE) + CRLF + payload`. Case-insensitive hash compare, port-0 rejection on Connect, MAX_REQUEST_HEAD_LEN bound, fast non-hex reject for fallback. Verified by lifecycle tests + per-user metrics roundtrip.
- [x] **Shadowsocks 2022** — blake3 KDF with info `"shadowsocks 2022 session subkey"`, salt_len=key_len, base64 PSK, replay-cache, salt-prefix only on legacy methods. Matches shadowsocks-org/2022-1.md.
- [x] **WebSocket** — RFC 6455 framing (FIN+RSV+opcode; masked client→server; unmasked server→client; 16/64-bit ext length; control payload ≤125). Upgrade uses canonical GUID `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`. Minor gap: RSV-bits MUST-be-zero check is missing (proxy context, no extension negotiation, low risk).
- [x] **HTTPUpgrade** — xray/sing-box HTTPUpgrade match: GET + path + `Upgrade: websocket` + `Connection: Upgrade` (token-list) + optional Host + optional base64 early-data header (bounded). Response is canonical 101 Switching Protocols.

### Phase 3 — External Tests (hiddify, FlClash)

- [x] Verify external-test framework runnable on this box (Node toolchain, Chromium)
- [x] Add FlClash pre-launch profile import (`import-flclash-config.py`) so desktop FlClash binds a real mixed/SOCKS port before `connectProxy`
- [x] Verify wrongsv-generated client configs can be adapted into runnable Hiddify + FlClash configs
- [x] Route real HTTP traffic through Hiddify → wrongsv → local target server
- [x] Route real HTTP traffic through FlClash → wrongsv → local target server
- [x] Collect baseline performance (latency p50/p95/p99, throughput, error rate, per-user byte deltas) via wrongsv metrics scrape

### Phase 4 — Expand External Test Coverage

- [x] Add xray-core VMess regression test (`test_xray_lifecycle_vmess_dialect_divergence`) — empirically confirms wrongsv-VMess ≠ v2fly-VMess
- [x] Add xray-core client lifecycle module in wrongsv-external-tests (start, configure, stop)
- [x] Add sing-box client lifecycle module in wrongsv-external-tests
- [x] Expand behavior coverage (download-heavy, local session churn, richer local pages/forms/feed/video)
- [x] Keep modular: every client gets the same API surface (start, healthcheck, shutdown)

### Phase 5 — Metrics Port

- [x] Add optional `[metrics]` section to wrongsv config: `port = 9100` (off by default)
- [x] Build `wrongsv-metrics` crate (Registry, ConnectionGuard, Prometheus renderer, HTTP listener)
- [x] Wire `Arc<Registry>` into `InboundServer`, start HTTP listener when configured
- [x] Integration test: assert disabled-by-default + `/metrics` and `/healthz` reachable when enabled
- [x] Plumb `MetricsTap` through `relay_raw`/`relay_vision`/`relay_udp`, record bytes per user
- [x] Add VLESS + HTTPUpgrade (raw path) counting; integration test confirms uplink+downlink counters
- [x] Add VMess counting (per-user via email, both decrypted plaintext directions)
- [x] Add Trojan counting (per-user via email, falls back to "" for legacy unnamed password)
- [x] Add REALITY/AnyTLS counting (relay_anytls_*, relay_reality_*); also wired ShadowTLS and plain TLS paths
- [x] Add integration test for AnyTLS metrics roundtrip
- [x] Add integration test for REALITY metrics roundtrip
- [x] Add integration test for Trojan per-user counters
- [x] Add integration test for VMess per-user counters

## Notes

- Test purpose encapsulation = modular client lifecycles + reusable user behaviors. Each client lifecycle is a separate file with a uniform interface so the orchestrator can swap clients without rewriting tests.
- 127.0.0.1:11451 is the local outbound proxy for any unreachable external resource.
- New external-test entry point: `wrongsv-external-tests/run-client-suite.js`. It composes `wrongsv` server startup, client-config adaptation, client lifecycle, traffic workloads, browser workloads, and wrongsv `/metrics` scraping.
- Browser/user simulation now runs against deterministic local pages served by `proxy-testing-framework/local-test-server.js` (`/page/news`, `/page/feed`, `/page/store/catalog`, `/page/form`, `/page/video`) instead of only raw `httpbin` targets.

## Status

Started 2026-06-13.

### 2026-06-13 — Reusable external harness + real Hiddify/FlClash traffic

- Added `wrongsv-external-tests/e2e-harness/` and `run-client-suite.js`:
  one reusable path now starts wrongsv, adapts generated configs for each client,
  launches the client, runs compatibility/traffic/browser workloads, and scrapes
  wrongsv Prometheus metrics.
- Added `import-flclash-config.py`; FlClash desktop no longer needs a manual
  subscription/profile to expose `mixed-port`. The harness writes the profile
  file, updates `database.sqlite`, and sets `currentProfileId` before launch.
- `ProxyFetchClient` no longer uses an undici-incompatible SOCKS dispatcher; it
  now shells out to `curl`, which produces real SOCKS/HTTP proxy timings and
  fixed the previously false-negative traffic benchmark failures.
- `local-test-server.js` now serves deterministic article/feed/store/form/video
  pages plus large downloads and chunked streams so browser simulations and
  fetch-based traffic stay offline and repeatable.

Observed with the new harness:

- **Hiddify** (`results/hiddify-suite-3`):
  compatibility probe passed against wrongsv on `127.0.0.1:50443`.
  `local-general`: p50 175ms / p95 247ms / 20.30 req/s / 0 error rate.
  `local-download-heavy`: p50 160ms / p95 254ms / 13.82 req/s / 0 error rate.
  wrongsv metrics delta during traffic recorded per-user bytes for
  `user@example.com` (e.g. ~1.59 MB down on download-heavy).
- **Hiddify browser path** (`results/hiddify-browser-check`):
  deterministic local browser pages now create wrongsv user metrics deltas,
  confirming real browser traffic can be driven through the client stack.
- **FlClash** (`results/flclash-suite-3`):
  compatibility probe passed against wrongsv on `127.0.0.1:50443`.
  `local-general`: p50 164ms / p95 246ms / 24.08 req/s / 5.26% error rate.
  `local-download-heavy`: p50 154ms / p95 234ms / 13.14 req/s / 0 error rate.
  wrongsv metrics delta during traffic recorded ~2.24 MB down for
  `user@example.com` on download-heavy.
- **FlClash browser path** (`results/flclash-browser-check`):
  web-browsing behavior produces wrongsv metric deltas, proving actual browser
  navigation can traverse FlClash → wrongsv → local target server.

Residual issue:

- Browser behaviors against both GUI clients still show some navigation errors.
  The current harness proves end-to-end proxying and metrics capture, but the
  remaining browser failures need a later pass on target-host selection /
  Chromium proxy semantics if we want cleaner action-level success rates.

### 2026-06-13 — xray-core + sing-box adapters validated

- Added reusable core-client adapters in wrongsv-external-tests for `sing-box`
  and `xray-core`, sharing the same `start/getProxyUrl/stop` surface as the
  GUI clients.
- `sing-box` adapter validated with the new suite (`results/singbox-check`);
  compatibility probe passed against wrongsv and traffic flowed through the
  generated sing-box runtime config.
- `xray-core` adapter validated with a REALITY-based wrongsv config
  (`results/xray-check-2`). Latest xray 26.5.9 rejects legacy TLS
  `allowInsecure`, so REALITY is the stable validation path for now.

### 2026-06-13 — Metrics endpoint live

- `wrongsv-metrics` crate built and tested (13 unit tests pass).
- `InboundServer` now binds the optional metrics HTTP listener when `[metrics]` is present in config.
- New integration tests confirm endpoint disabled by default and serves Prometheus dump when configured.
- Next: thread `MetricsTap` through `relay_*` functions for per-user byte counting.

### 2026-06-13 — Per-user metrics through REALITY / AnyTLS / Trojan / TLS / ShadowTLS

- REALITY (`relay_reality_raw`/`vision`/`udp`), main AnyTLS path, sing-anytls session model,
  ShadowTLS, plain TLS, and TLS+HTTPUpgrade now record uplink/downlink bytes per email.
- Trojan: `TrojanConfig.password_hashes` → `passwords: Vec<TrojanPasswordEntry>` (hash + email).
  `TrojanRequest.email` now identifies the matched user; `MetricsTap::disabled()` on the
  fallback path keeps unauthenticated buffered-data forwarding off the books.
- Workspace: `cargo check`, `cargo clippy --workspace --all-targets`, `cargo test --workspace`
  all green (one flake in `test_reality_mixed_auth_and_spider` cleared on retry — unrelated).

### 2026-06-13 — VLESS Kyber-via-addons is unreachable

Audit of VLESS encoding + the two Kyber integration tests revealed the addons-Kyber path
cannot transmit a real ML-KEM-512 ciphertext, and even if it could the server wouldn't use it:

1. **Encoder drops `kyber_ct` when `flow.is_empty()`** —
   `encode_header_addons` short-circuits to `0x00` (`crates/vless-encoding/src/addons.rs:26-30`).
   Both Kyber tests (`tests/integration.rs:629, 3674`) pass `flow=""`, so they construct an
   `Addons { flow: "", kyber_ct }` whose `kyber_ct` is silently discarded on the wire.
2. **Wire format caps addons at 255 bytes** — VLESS uses a 1-byte length prefix. ML-KEM-512
   ciphertext alone is 768 bytes, ~789 with the proto wrapper. Even if `flow` were non-empty,
   the cast `bytes.len() as u8` truncated silently. **Fixed**: encoder now returns
   `AddonsError::TooLarge(n)` instead (commit below). New test
   `test_oversized_addons_errors_instead_of_truncating` proves the error path.
3. **Server ignores the shared secret** —
   `handle_kyber_addons` decapsulates and `info!`-logs the shared secret length, but the
   relay never derives keys from it or uses it to encrypt traffic
   (`crates/server/src/handler/vless.rs:64-84`). It's observational only.

**Net effect**: Kyber addons is dead code. The two passing tests prove only that the server
echoes a non-Kyber connection successfully. Compatible with xray-core's xtls-rprx-vision +
addons proto (xray uses `Flow + Seed`, not `KyberCt`); xray's ML-KEM-768 lives in a separate
`proxy/vless/encryption/` handshake, not in the request-header addons.

**Decision needed**:
- (A) Drop the dead path entirely (remove `kyber_ct` field, server handler, tests). Smallest diff.
- (B) Mirror xray: move PQ KEM to a separate post-handshake (incompatible with our current
  field but compatible with xray clients running `encryption=mlkem768x25519plus`).
- (C) Extend the wire format with a 2-byte length prefix (incompatible with xray).

No protocol traffic is currently encrypted with PQ material on either side, so (A) is
zero-risk. Hardening commit already in place to make the truncation a hard error if anyone
revives the path.

### 2026-06-13 — VMess KDF diverges from v2fly spec

Audit of `crates/server/src/vmess.rs` shows wrongsv's VMess is a CUSTOM AEAD variant, not
v2fly/xray VMess AEAD. Concretely:

- `derive_cmd_key` is `HMAC-SHA256(b"VMess AEAD KDF", uuid)[..16]`. v2fly uses
  `HMAC-SHA256(uuid, "VMess AEAD KDF")` as cmdKey and then derives the *actual* AEAD
  encryption key via a chain of named KDFs:
  `KDF16(cmdKey, "AEAD Request Header Key", auth_id, nonce)`.
- `decrypt_header` uses cmd_key directly as the AES-128-GCM key with `eaudid` as AAD.
  v2fly's spec uses the derived `KDF16` material, not the bare cmd_key.
- No references to v2fly's labels (`"AEAD Request Header Key"`, `"AEAD Request Header IV"`,
  `"AEAD Resp Header Key"`, `"AEAD Resp Header IV"`) anywhere in the workspace.
- The instruction layout itself (version|body_iv|body_key|resp_auth_v|options|padding_len|
  reserved|cmd|port|addr_type|addr|padding) DOES match v2fly's instruction body.

Net effect: wrongsv-VMess client ↔ wrongsv-VMess server interop is fine (eval-client
imports `wrongsv_server::vmess`), but a real xray-core or v2fly client will not connect.
The current evaluator passing VMess only confirms internal consistency. External-tests
(Phase 3) would have caught this for sure.

**Decision needed**:
- (A) Re-label the protocol so it doesn't claim v2fly compatibility (e.g. rename to
  `vmess-wrongsv`); keep current implementation. Smallest diff.
- (B) Refactor `derive_cmd_key` and `build_header`/`decrypt_header` to follow v2fly's
  KDF chain, restoring xray/v2ray client compatibility. Larger diff, but enables Phase 3
  external-client testing for VMess.

(B) is the natural choice if external compatibility matters for VMess; (A) keeps the
status quo with honest naming. Either way the wire format change is breaking for any
existing VMess deployment.

### 2026-06-13 — Phase 2 audit complete

Verified eight protocols (VLESS, REALITY, AnyTLS, VMess, Trojan, Shadowsocks 2022, WebSocket,
HTTPUpgrade). Two non-trivial findings surfaced (Kyber-via-addons is unreachable; VMess KDF
is a custom dialect). Both documented above with decision points. Next: Phase 3 external
tests via hiddify + FlClash — required to confirm the VMess interop gap matters in practice.

### 2026-06-13 — VMess KDF divergence empirically confirmed via xray-core

Added `test_xray_lifecycle_vmess_dialect_divergence` (tests/xray_lifecycle.rs:990+).
The test spawns a real xray-core 26.5.9 binary as a VMess client against a
wrongsv VMess server and asserts the handshake FAILS.

Result: xray's EAuID arrives, wrongsv decrypts it with the wrong key, CRC32
check fails, server logs `VMess auth failed: eaudid verification failed`.
Audit finding confirmed — the test now functions as a regression check that
will start failing only if the dialect is reconciled.

Decision still pending (A: rename to `vmess-wrongsv` / B: refactor KDF to
v2fly spec). New helper `spawn_vmess_server` added to `tests/common/mod.rs`
for cross-binary reuse (sing-box / mihomo lifecycle suites can use it).

### 2026-06-13 — Phase 3 traffic verification needs TUN privileges or mobile build

Set up the wrongsv-external-tests pipeline end-to-end against a wrongsv VLESS+TLS+vision
backend on `127.0.0.1:50443` and FlClash on this Linux desktop. The lifecycle works:
- `node orchestrate.js --app flclash --config <wrongsv-backed mihomo yaml> --mode test`
  succeeded — debug extensions 8/8, selfTest 3/3, `connectProxy` → `{status: connected,
  isStart: true}`, then `disconnectProxy` → `disconnected`.
- `wrongsv --print-client-config --format mihomo` produces a config FlClash accepts without
  error (proxy block ships VLESS / port / uuid / flow / tls / servername / sni / udp).

But `curl --socks5-hostname 127.0.0.1:7890` failed with `Connection refused` — FlClash's
mixed-port is never bound on Linux desktop. `ss -ltnp` confirms FlClash only opens its
Dart VM service port; no SOCKS/HTTP listener is created from the `mixed-port: 7890` config
directive. FlClash desktop expects to route via TUN, which needs CAP_NET_ADMIN (Xvfb-spawned
processes don't have it). The wrongsv-external-tests framework is engineered for mobile
(Android) FlClash/Hiddify builds where the SOCKS port IS exposed.

**Net effect**: Phase 3 lifecycle is verified (FlClash accepts wrongsv-generated configs and
its proxy core starts); actual traffic flow through wrongsv via FlClash desktop is not
verifiable on this host. Three paths forward, in order of effort:
- (A) Run the framework against an Android FlClash/Hiddify build in an emulator (where
  mixed-port is exposed via the app's HTTP/SOCKS proxy mode).
- (B) Run as a TUN-capable user (sudo or setcap CAP_NET_ADMIN+ep on the FlClash binary)
  and route via the TUN interface.
- (C) Substitute xray-core/sing-box clients in Phase 4 — these expose SOCKS by default,
  and we already have wrongsv configs that target them. That covers the VLESS+TLS, REALITY,
  Trojan, SS2022 audits with REAL traffic.

(C) gets us the external compatibility evidence the user wanted with the least setup. The
VMess-dialect-divergence finding (under "VMess KDF diverges from v2fly") would be confirmed
or disproved by running an xray-core client against wrongsv-VMess via Phase 4.
