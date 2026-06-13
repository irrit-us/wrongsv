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
- [x] Audit channel bounds / timeouts for OOM and hang risks — channels: unbounded sites all have natural upstream backpressure (KCP recv window, TCP recv buffer, single-message use). Timeouts: 6 handshake sites lacked a read-deadline bound (slowloris risk); fixed with 30s set/clear pattern in accept_anytls, accept_tls, the ShadowTLS accept path, tls_relay, handle_shadowsocks_connection, and httpupgrade TLS branch
- [x] Fix flaky `test_mihomo_lifecycle_multi_user` (user2 raw-flow connection fails)

### Phase 2 — Protocol Audit

- [x] **VLESS** — wire format matches xray (version|user_id|addons(u8-len + proto)|cmd|addr+port). Two issues surfaced & one hardened — see "VLESS Kyber-via-addons is unreachable" under Status.
- [x] **REALITY** — auth path matches xray-core (X25519+HKDF-SHA256 with `salt=client_random[..20]`, `info=b"REALITY"`; AES-256-GCM session_id w/ AAD = ClientHello body, session_id offset 39 zeroed; HMAC-SHA512(auth_key, raw_pubkey) cert binding). Verified end-to-end by the eval-client cert HMAC check (36e64b5) and lifecycle tests.
- [x] **AnyTLS** — sing-anytls wire matches spec: `[SHA256(pw)(32) | padding_len(2 BE) | padding(N) | payload]`. Constant-time pw compare, 30s slowloris bound. Verified by lifecycle tests + AnyTLS metrics roundtrip.
- [x] **VMess** — reconciled with standard xray/v2fly VMess AEAD; see "VMess standard interop restored" under Status.
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

- [x] Add xray-core VMess real-client lifecycle coverage (`test_xray_lifecycle_vmess_tcp_echo`) — now proves positive xray-core interop against wrongsv VMess
- [x] Add xray-core client lifecycle module in wrongsv-external-tests (start, configure, stop)
- [x] Add sing-box client lifecycle module in wrongsv-external-tests
- [x] Add clash-verge-rev capability path via Mihomo core adapter in wrongsv-external-tests
- [x] Add V2Ray / V2Fly core lifecycle module in wrongsv-external-tests
- [x] Expand behavior coverage (download-heavy, local session churn, richer local pages/forms/feed/video)
- [x] Keep modular: every client gets the same API surface (start, healthcheck, shutdown)
- [x] Add capability-driven multi-scenario audit (`run-client-matrix.js`) so each client can be swept across the protocol stacks it claims to support

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
- New capability entry point: `wrongsv-external-tests/run-client-matrix.js`. It iterates protocol scenarios per client, records pass/fail/defect status, and emits `matrix.json` / `matrix.md`.
- Core-client debug surfaces are now available in external runs: Mihomo-based paths use the Clash
  controller API, sing-box uses its Clash API surface, and GUI clients keep using VM-service
  snapshots. Each suite writes `debug-*.json` artifacts next to `report.json` when the client
  supports them.
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

### 2026-06-13 — Capability-driven protocol matrices added

- Added `e2e-harness/scenarios.js` + `capabilities.js` and a new
  `run-client-matrix.js` entry point. The audit now starts from the client's
  declared capability set and executes the matching wrongsv server stacks,
  instead of only validating one transport per client.
- Added two new client entries to the reusable interface:
  `clash-verge-rev` (Mihomo core path) and `v2ray` (V2Fly core).
- Manual runtime builders were added for protocol families that wrongsv's
  built-in client-config generator does not yet cover:
  Shadowsocks AEAD / 2022 and Trojan for Mihomo, sing-box/Hiddify, and the
  Xray/V2Ray family.

Executed matrices:

- `results/clash-verge-matrix`
  covered: VLESS raw TCP, WebSocket, HTTPUpgrade, Shadowsocks AEAD, Shadowsocks 2022, Trojan TLS
  confirmed defect: VMess standard interop (resolved later, see below)
  newly surfaced defect: Mihomo gRPC interop (resolved later, see below)
- `results/singbox-matrix-2` + `results/singbox-quic-check-2`
  covered: VLESS REALITY Vision, HTTPUpgrade, QUIC, Shadowsocks 2022, Trojan TLS
  confirmed defect: VMess standard interop (resolved later, see below)
  harness gap: sing-box XHTTP config path still needs a capability-grounded mapping
- `results/xray-matrix`
  covered: VLESS REALITY Vision, HTTPUpgrade, Shadowsocks 2022
  confirmed defect: VMess standard interop (resolved later, see below)
  newly surfaced defect: xray-core gRPC interop instability (resolved later, see below)
  harness gap: latest xray 26.5.9 mKCP config migration breaks our current KCP runtime builder
- `results/v2ray-matrix-check-2` + `results/v2ray-extra-check`
  covered: VLESS raw TCP, WebSocket, Shadowsocks AEAD
  confirmed defect: VMess standard interop (resolved later, see below)
  newly surfaced defect: V2Fly gRPC interop instability (resolved later, see below)
  client-side note: tested V2Ray 5.49.0 does not accept `httpupgrade` as a transport keyword, so
  it was removed from the runnable capability set

New server-side defects recorded from client-capability sweeps:

- ~~`server.mihomo_grpc_interop`~~ resolved later on 2026-06-13 by graceful h2 stream-reset
  handling on reused gRPC connections
- ~~`server.xray_xhttp_interop`~~ resolved later on 2026-06-13 by adding plaintext HTTP/1.1
  stream-one support to wrongsv's XHTTP server
- ~~`server.xray_grpc_interop`~~ resolved later on 2026-06-13 by graceful h2 stream-reset
  handling on reused gRPC connections
- ~~`server.v2ray_grpc_interop`~~ resolved later on 2026-06-13 by graceful h2 stream-reset
  handling on reused gRPC connections
- ~~`server.vmess_standard_interop`~~ resolved later on 2026-06-13 by standardizing wrongsv VMess
  AuthID/KDF/header/body framing and fixing standalone VMess client-config UUID selection

Non-server gaps identified during the sweep:

- xray-core KCP runtime config startup has been updated to the current finalmask schema, but the
  runtime behavior of `vless_kcp` is still under investigation
- sing-box / Hiddify Hysteria2 and TUIC are still harness gaps even though wrongsv already
  implements those server-side protocols; Hiddify AnyTLS also remains blocked by its packaged core
- sing-box / Hiddify XHTTP still need a capability-grounded config mapping before they should be
  treated as server defects

### 2026-06-13 — gRPC server path partly hardened

- Investigated the gRPC matrix failures and confirmed at least one real
  server-side bug: wrongsv's gRPC handler only serviced the first HTTP/2
  request stream on a connection and rejected follow-on streams.
- Refactored `crates/server/src/handler/grpc.rs` so one h2 connection can
  process multiple gRPC request streams, and added
  `test_grpc_multiple_streams_same_h2_connection` to lock that behavior in.
- Result: the in-tree multi-stream gRPC regression test now passes, so the
  old one-stream-only bug is fixed.
- Residual reality: Mihomo / xray-core / V2Fly gRPC interoperability is still
  not fully clean in external runs (`Empty reply from server` / stream reset
  after some successful requests), so those defects remain open despite the
  server-side improvement.

### 2026-06-13 — gRPC interop defects resolved across Mihomo / xray-core / V2Fly

- Root cause of the remaining gRPC failures: wrongsv still treated graceful
  `RST_STREAM(CANCEL/NO_ERROR/STREAM_CLOSED)` on completed h2 streams as fatal,
  which tore down the shared gRPC connection after otherwise successful
  requests.
- Hardened both gRPC and XHTTP h2 stream drivers so graceful client-side stream
  cancellation is treated as normal EOF instead of a connection error.
- External rechecks after that change:
  `wrongsv-external-tests/results/clash-verge-grpc-recheck-3`,
  `wrongsv-external-tests/results/xray-grpc-recheck-6`, and
  `wrongsv-external-tests/results/v2ray-grpc-recheck-4` all pass compatibility
  probes and sustained traffic while also reporting per-user metrics deltas.
- Remaining caveat: xray-core and V2Ray/V2Fly still show materially higher
  latency on gRPC than Mihomo in these local runs, but the earlier
  empty-reply/follow-on-request interop defect is no longer reproducible.

### 2026-06-13 — XHTTP still fails real-client interop

- Rechecked XHTTP after refactoring the raw relay path.
- For Mihomo-based clients, forcing `mode: "stream-one"` in the generated
  client config changed the result from failure to pass
  (`results/clash-verge-xhttp-recheck-2`).
- That removed `server.mihomo_xhttp_interop` from the confirmed defect list.
- `xray-core` still fails XHTTP (`results/xray-xhttp-check-3`), so the
  remaining XHTTP defect is now narrowed to Xray-family interoperability.
- sing-box no longer stays in the server-defect bucket until we have a
  capability-grounded XHTTP config mapping for its current schema.

### 2026-06-13 — xray-core XHTTP interop and carrier metrics fixed

- wrongsv XHTTP now detects plaintext HTTP/1.1 `stream-one` requests alongside
  h2/h2c, decodes chunked upload bodies, and streams chunked HTTP/1.1 responses
  back to the client on the same connection.
- Added in-tree regressions for the new carrier path and metrics coverage:
  `test_xhttp_http1_chunked_tcp_echo`,
  `metrics_count_bytes_per_user_through_xhttp_http1_relay`, and
  `metrics_count_bytes_per_user_through_grpc_relay`.
- Wired the shared `MetricsTap` into both XHTTP and gRPC carrier relays so the
  metrics endpoint now reports per-user bytes and connection counts for those
  transports too.
- External recheck: `wrongsv-external-tests/results/xray-xhttp-check-7` now
  shows `xray-core` `vless_xhttp` passing compatibility probes and sustained
  traffic, with per-user metrics deltas for `user@example.com`.
- Follow-up hardening: clean EOF at an HTTP/1.1 chunk boundary is now treated as
  a normal XHTTP stream shutdown, which removed the earlier noisy
  `connection closed while reading HTTP/1.1 line` warnings from the server log.

### 2026-06-13 — Longer-duration capability sweeps

- Added traffic-profile selection to `run-client-matrix.js` so capability sweeps can run with
  `local-general`, `local-download-heavy`, and `local-session-churn` instead of only a quick
  smoke profile.
- Longer matrix runs now exist for stable combinations:
  `results/clash-verge-long` and `results/singbox-long`.
- These runs confirmed the previously passing protocol families still hold up under sustained
  load while continuing to emit per-user wrongsv metrics deltas.

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

### 2026-06-13 — VMess KDF diverges from v2fly spec (historical, resolved later)

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

### 2026-06-13 — VMess KDF divergence empirically confirmed via xray-core (historical, resolved later)

Added `test_xray_lifecycle_vmess_dialect_divergence` (later replaced by
`test_xray_lifecycle_vmess_tcp_echo`). The original regression proved the old
wrongsv VMess dialect was incompatible with xray-core.

Result: xray's EAuID arrives, wrongsv decrypts it with the wrong key, CRC32
check fails, server logs `VMess auth failed: eaudid verification failed`.
Audit finding confirmed at the time — and later retired once the dialect was
reconciled.

The implementation was later moved to option (B): wrongsv now follows the
standard xray/v2fly AEAD path. `spawn_vmess_server` remains in
`tests/common/mod.rs` for cross-binary reuse.

### 2026-06-13 — VMess standard interop restored across clients

- wrongsv VMess now uses the standard command-key derivation
  (`MD5(uuid || c48619fe-8f02-49e0-b9e9-edf763e17e21)`), xray-style nested KDF
  salts for AuthID/header/response-header handling, and standard masked/padded
  AEAD body chunks with encrypted EOF markers.
- Standalone VMess client-config generation was also fixed so VMess clients now
  receive the real `[[vmess.users]]` UUID instead of a placeholder build UUID.
- In-tree verification now passes for:
  `test_xray_lifecycle_vmess_tcp_echo`,
  `metrics_count_bytes_per_user_through_vmess_relay`, and the VMess helper
  unit tests in `crates/server/src/vmess.rs`.
- External rechecks now pass for standard-VMess clients:
  `xray-core` (`results/xray-vmess-recheck-2`),
  `v2ray` (`results/v2ray-vmess-recheck-1`),
  `sing-box` (`results/singbox-vmess-recheck-1`),
  `clash-verge-rev` (`results/clash-verge-vmess-recheck-1`),
  `FlClash` (`results/flclash-vmess-recheck-1`), and
  `Hiddify` (`results/hiddify-vmess-recheck-1`).

### 2026-06-13 — xray-core KCP runtime-config migration fixed, runtime still open

- Updated wrongsv's xray-format client config generation so KCP no longer emits
  the removed `seed` field. It now uses the current `finalmask.udp` schema with
  `mkcp-original` or `mkcp-aes128gcm`.
- Result: `xray-core` no longer fails at startup on `vless_kcp`.
- Residual issue: `results/xray-kcp-check-2` still times out under sustained
  traffic and produces no server-side metrics deltas, so KCP remains an open
  follow-up item rather than a confirmed resolved capability.

### 2026-06-13 — KCP outer packet compatibility fixed, inner transport still mismatched

- wrongsv KCP no longer uses the stale custom `FNV + cmd` datagram wrapper.
  It now accepts and emits xray-style `mkcp-original` / `mkcp-aes128gcm`
  packet masks based on the configured seed.
- Result: current xray-core KCP clients now reach wrongsv far enough to create
  KCP sessions; the failure moved from config-load / packet-drop to
  `KCP closed before VLESS header`.
- Current conclusion: the remaining KCP bug is inside the KCP stream/session
  implementation itself, not the outer packet mask layer.

### 2026-06-13 — sing-box AnyTLS harness gap partially closed

- Added reusable `AnyTLS` runtime-config generation for sing-box-family clients
  in `wrongsv-external-tests`.
- `sing-box` now passes `anytls_tcp`
  (`wrongsv-external-tests/results/singbox-anytls-check-3`), so `anytls` is no
  longer a harness gap for the core sing-box path.
- The standalone sing-anytls SOCKS5 branch now also records per-user byte and
  connection counters when wrongsv is configured with a single user email.
- `Hiddify` still fails the same scenario
  (`wrongsv-external-tests/results/hiddify-anytls-check-4`). The deeper cause is
  now confirmed: Hiddify's packaged core on this box rejects
  `type: "anytls"` as an unknown outbound type, so this remains a
  Hiddify-specific client/runtime gap rather than a wrongsv server defect.

### 2026-06-13 — ShadowTLS v3 interop fixed for sing-box / Hiddify

- Replaced wrongsv's old exporter-HMAC ShadowTLS path with a ShadowTLS v3 server
  implementation: ClientHello session-id verification, relayed/local cover
  handshake, and authenticated post-handshake records before VLESS.
- Added a reusable sing-box-family ShadowTLS runtime builder that composes
  `VLESS over ShadowTLS` through a detour instead of treating ShadowTLS as a
  standalone final outbound.
- External rechecks now pass on both supported client families:
  `wrongsv-external-tests/results/singbox-shadowtls-check-2` and
  `wrongsv-external-tests/results/hiddify-shadowtls-check-1`.
- Capability status updated accordingly: ShadowTLS is no longer a harness gap
  for the sing-box core path or Hiddify on this box.

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
