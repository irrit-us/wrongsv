# TASKS.md — VLESS+REALITY Server (Rust)

Refactor `xray-core/proxy/vless/` and supporting Go packages into a minimal
Rust server under `./wrongsv/`. The primary deliverable is a terminal-based
runtime that accepts VLESS+REALITY connections, validates users, decodes
XTLS Vision traffic, and forwards to the target destination.

Each phase produces a compilable, testable unit. Checks are listed at the end
of each phase — run them before moving on.

---

## Phase 1: Project Scaffold & Core Types

**Goal:** Cargo workspace with crates for shared types and UUID handling.
All types are `Copy`/`Clone`/`Debug`/`PartialEq` where appropriate.
No external I/O yet — pure data types and parsing.

### 1.1 Workspace setup
- `Cargo.toml` at `wrongsv/` with workspace members: `uuid`, `net-types`, `protocol`, `vless-encoding`, `vless`, `server`
- `rust-toolchain.toml` pinning stable Rust
- Dependencies: `uuid` (crate, for v4), `bytes`, `thiserror`, `prost` (for proto encoding of addons), `sha2` (for UUID v5 fallback), `md-5` (for command key)

### 1.2 UUID crate (`wrongsv/uuid/`)
- `Uuid` type: `[u8; 16]` newtype
- `Uuid::new_v4()` — random UUID with version/variant bits set
- `Uuid::parse_bytes(bytes: &[u8; 16]) -> Result<Self>`
- `Uuid::parse_string(s: &str) -> Result<Self>` — hex format, also SHA-1 v5 fallback for short names (< 32 chars)
- `Display` impl: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` format
- `ProcessUUID` function: zero bytes 6 and 7 (used for routing in VLess)

**Check:** `cargo test -p uuid` passes with tests for round-trip parse/display, v5 fallback, ProcessUUID masking.

### 1.3 Net-types crate (`wrongsv/net-types/`)
- `AddressFamily` enum: `IPv4`, `IPv6`, `Domain`
- `Address` enum: `IPv4([u8; 4])`, `IPv6([u8; 16])`, `Domain(String)`
  - `family()` -> `AddressFamily`
  - `parse(s: &str) -> Self` — detect IP vs domain, strip brackets from `[::1]`
- `Port(u16)` newtype with `Display` and `From<u16>`
- `Network` enum: `Tcp`, `Udp`, `Unix` with `as_str()`
- `Destination` struct: `address: Address, port: Port, network: Network`

**Check:** `cargo test -p net-types` — parse IPv4/IPv6/domain addresses, port display.

### 1.4 Protocol crate (`wrongsv/protocol/`)

Types mirroring `xray-core/common/protocol/`:

- `RequestCommand` enum: `Tcp = 0x01`, `Udp = 0x02`, `Mux = 0x03`, `Rvs = 0x04`
- `SecurityType` enum: `Unknown = 0`, `Legacy = 1`, `Auto = 2`, `Aes128Gcm = 3`, `ChaCha20Poly1305 = 4`, `None = 5`, `Zero = 6`
- `RequestHeader` struct:
  ```rust
  pub struct RequestHeader {
      pub version: u8,
      pub command: RequestCommand,
      pub address: Address,
      pub port: Port,
      pub user: MemoryUser,
  }
  ```
- `ResponseHeader` struct: `version: u8`
- `MemoryUser` struct: `account: MemoryAccount, email: String, level: u32`
- `ID` struct: `uuid: Uuid, cmd_key: [u8; 16]` — `new(uuid)` computes MD5(uuid || "c48619fe-...") for cmd_key
- `MemoryAccount` struct (VLESS-specific):
  ```rust
  pub struct MemoryAccount {
      pub id: ID,
      pub flow: String,        // "" | "xtls-rprx-vision"
      pub encryption: String,  // "" | "none" | base64-encoded key chain
      pub xor_mode: u32,
      pub seconds: u32,
      pub padding: String,
      pub testpre: u32,
      pub testseed: Vec<u32>,
  }
  ```
- `AddressParser` — reads/writes Address+Port from byte streams.
  - Wire format: type byte (1=IPv4, 2=Domain, 3=IPv6) + address bytes + port (2 bytes big-endian)
  - Port-first variant for VLESS encoding

**Check:** `cargo test -p protocol` — ID command key derivation, address round-trip through AddressParser.

---

## Phase 2: VLESS Encoding & Decoding

**Goal:** Correct binary codec for VLESS request/response headers and body
framing. Matches the wire format byte-for-byte with the Go implementation.

### 2.1 VLess-encoding crate (`wrongsv/vless-encoding/`)

#### Header encoding
- `encode_request_header(buf, request, addons) -> Result<()>`
  - Byte layout: version(1) | user_id(16) | addons(variable) | command(1) | [address+port if TCP/UDP]
- `decode_request_header(reader, validator) -> Result<RequestHeader>`
  - Returns the parsed header and the raw `[u8; 16]` user_sent_id
- `encode_response_header(buf, request, addons) -> Result<()>`
  - Byte layout: version(1) | addons(variable)
- `decode_response_header(reader, request) -> Result<Addons>`

#### Addons (protobuf)
- `Addons` struct: `flow: String`
- Wire format: length-prefixed protobuf (1 byte length, then proto bytes), or `0x00` for empty
- Use `prost` to derive protobuf encoding for `Addons`
- Write the `.proto` file: `message Addons { string Flow = 1; }`

#### Body framing
- `MultiLengthPacketWriter` — UDP packet framing: 2-byte big-endian length prefix per buffer
- `LengthPacketReader` — reads 2-byte length, then payload
- Integration with `Addons::Flow` for selecting body codec:
  - Flow == "xtls-rprx-vision" → body passes through Vision reader/writer
  - Flow == "" (default) → raw passthrough
  - UDP always → length-prefixed packets

**Check:** `cargo test -p vless-encoding`
- Round-trip: encode request header + decode → fields match
- Round-trip: encode response header + decode → version and addons match
- UDP packet: write lengths → read lengths → payload matches
- Addons proto: serialize with flow="xtls-rprx-vision", deserialize, field matches

---

## Phase 3: VLESS User Validator

**Goal:** In-memory user registry keyed by UUID and email. Thread-safe.

### 3.1 VLESS crate (`wrongsv/vless/`)

- `Validator` trait:
  ```rust
  pub trait Validator: Send + Sync {
      fn get(&self, id: &[u8; 16]) -> Option<MemoryUser>;
      fn add(&self, user: MemoryUser) -> Result<()>;
      fn del(&self, email: &str) -> Result<()>;
      fn get_by_email(&self, email: &str) -> Option<MemoryUser>;
      fn get_all(&self) -> Vec<MemoryUser>;
      fn get_count(&self) -> i64;
  }
  ```
- `MemoryValidator` — `RwLock<HashMap<[u8; 16], MemoryUser>>` + `RwLock<HashMap<String, MemoryUser>>`
  - Keys UUID by `ProcessUUID(id)` (bytes 6-7 zeroed)
  - Emails stored lowercased
  - `add` enforces unique email

**Check:** `cargo test -p vless`
- Add user, retrieve by UUID → matches
- Add user, retrieve by email → matches
- Delete by email → UUID lookup returns None
- Duplicate email → error
- ProcessUUID zeroes bytes 6-7

---

## Phase 4: Encrypted Transport Layer

**Goal:** TLS-1.3-disguised AEAD transport that encrypts all payload bytes to
look like TLS 1.3 application data records. This is the encryption layer
*surrounding* the VLESS traffic (not the inner VLESS flow encryption).

**Note:** For a *minimal* server, implement the server-side handshake
(`ServerInstance`) and the `CommonConn` read/write loop. Skip 0-RTT
session tickets and client-side padding — those can be added later if needed.

### 4.1 Encryption crate (`wrongsv/encryption/`)

- `CommonConn` — wraps a `TcpStream`, encrypts writes as TLS 1.3 records
  - Write path: AEAD seal payload + 5-byte TLS record header (0x17 0x03 0x03 ...)
  - Read path: parse TLS record header, AEAD open, handle nonce exhaustion
  - `EncodeHeader(buf, len)` / `DecodeHeader(buf) -> Result<usize>` — TLS 1.3 record framing
  - AEAD nonce management: 12-byte incrementing nonce, wrap detection at MaxNonce

- `ServerInstance`:
  - `Init(nfs_keys, xor_mode, seconds_from, seconds_to, padding_config)`
  - `Handshake(conn) -> CommonConn`
  - NFS key chain: X25519 + ML-KEM-768 relay chain
  - PFS via ML-KEM-768 encapsulation + X25519 ECDH
  - Ticket-based 0-RTT support (skip for minimal, return error)

- `AEAD` wrapper: AES-128-GCM or ChaCha20-Poly1305 via `ring` or `aes-gcm`/`chacha20poly1305` crates
  - `NewAEAD(ctx, key, use_aes)` — derives 32-byte key via BLAKE3 KDF, creates cipher
  - `Seal/Open` with auto-incrementing nonce

**Check:** `cargo test -p encryption`
- EncodeHeader/DecodeHeader round-trip
- AEAD seal/open round-trip with incrementing nonces
- Nonce exhaustion triggers new AEAD derivation

---

## Phase 5: XTLS Vision (Flow = "xtls-rprx-vision")

**Goal:** Wire-compatible XTLS Vision padding/unpadding and TLS traffic
analysis. This is the inner flow that pads VLESS payload to eliminate
length-based fingerprinting.

### 5.1 Vision module (`wrongsv/vless/src/vision.rs`)

- `TrafficState` struct:
  - `user_uuid: [u8; 16]`
  - `number_of_packet_to_filter: i32` (starts at 8)
  - `enable_xtls: bool`
  - `is_tls12_or_above: bool`
  - `is_tls: bool`
  - `cipher: u16`
  - `remaining_server_hello: i32`
  - Inbound/Outbound sub-states (padding buffers, remaining command/content/padding, current command, direct copy flags)

- `VisionReader`:
  - Wraps a raw `Read` source
  - Calls `XtlsUnpadding` on each read buffer
  - Calls `XtlsFilterTls` for first N packets
  - Detects when to switch to direct-copy mode (splice)

- `VisionWriter`:
  - Wraps a raw `Write` sink
  - Calls `XtlsPadding` to add padding before TLS application data records
  - Manages padding state: Continue(0x00), End(0x01), Direct(0x02)

- `XtlsPadding(buf, command, user_uuid, long_padding) -> Vec<u8>`
  - Prefixes with user_uuid (first write only)
  - Adds command byte + 2-byte content length + 2-byte padding length
  - Appends random padding bytes
  - Total frame: UUID(16) + command(1) + content_len(2) + padding_len(2) + content + padding

- `XtlsUnpadding(buf, state) -> Vec<u8>`
  - Parses the padding frame header
  - Extracts content bytes, discards padding
  - Handles split frames across multiple reads

- `XtlsFilterTls(buf, state)`
  - Inspects first 8 packets for TLS 1.3 ServerHello
  - Detects TLS version, cipher suite
  - Sets `enable_xtls` flag for AES-GCM/ChaCha20-Poly1305 ciphers

- `IsCompleteRecord(buf) -> bool` — validates complete TLS application data records

- `ReshapeMultiBuffer(buffers) -> Vec<Vec<u8>>` — splits large buffers to leave room for padding headers

**Check:** `cargo test -p vless`
- XtlsPadding + XtlsUnpadding round-trip
- Small content: padding adds random bytes, unpadding recovers exact content
- Multi-packet sequence: Continue→Continue→End transitions work
- Direct command triggers direct-copy flag
- XtlsFilterTls: real TLS 1.3 ServerHello bytes → enable_xtls = true
- IsCompleteRecord: valid TLS record returns true, truncated returns false

---

## Phase 6: Inbound Server Handler

**Goal:** Accept TCP connections, perform VLESS handshake, dispatch to
target. This is the core server logic.

### 6.1 Server crate (`wrongsv/server/`)

- `Config` struct (loaded from TOML):
  ```rust
  pub struct Config {
      pub listen: String,           // "0.0.0.0:443"
      pub users: Vec<UserConfig>,
      pub decryption: Option<String>,
      pub flow: Option<String>,     // default flow for all users
  }
  
  pub struct UserConfig {
      pub id: String,               // UUID string
      pub email: String,
      pub flow: String,             // "" or "xtls-rprx-vision"
      pub encryption: String,
  }
  ```

- `InboundServer`:
  - `new(config: Config) -> Result<Self>`
  - `run(&self) -> Result<()>` — main accept loop
  - On each connection:
    1. Optionally perform encryption handshake (if decryption configured)
    2. Read first buffer from connection
    3. `DecodeRequestHeader` — extract user ID, command, address, port
    4. Validate user via `Validator`
    5. If XRV flow: set up Vision reader/writer, inspect TLS state
    6. `EncodeResponseHeader` to client
    7. Connect to target destination (the address:port from the request)
    8. Bidirectional copy: client↔target with Vision padding if XRV

- Connection handling:
  - `handle_tcp(ctx, conn, validator, config) -> Result<()>`
  - Read deadline for handshake phase
  - Spawn async task for bidirectional relay
  - Handle splice/direct-copy mode for XTLS (Linux only)
  - Log access (accepted/rejected)

**Check:** `cargo test -p server`
- Config parse from TOML string
- Integration test: encode a valid request header, feed to server handler, verify it decodes and routes correctly (use localhost target)

---

## Phase 7: Terminal-Based Runtime

**Goal:** Binary that reads a config file (or accepts inline JSON), starts
the VLESS+REALITY server, and logs connections.

### 7.1 CLI binary (`wrongsv/src/main.rs`)

- CLI args via `clap`:
  ```
  wrongsv --config config.toml
  wrongsv --listen 0.0.0.0:443 --user id:uuid123,flow:xtls-rprx-vision
  ```
- Signal handling: graceful shutdown on SIGINT/SIGTERM
- Structured logging: connection accepted/rejected, target, duration, bytes transferred
- Stats output on SIGUSR1: active connections, users, uptime

### 7.2 Config validation
- UUID format validation for user IDs
- Flow must be "" or "xtls-rprx-vision"
- Port range validation
- Warn on unrecognized fields (don't error)

**Check:**
- `cargo run -- --config sample.toml` starts and listens
- Connect with a VLESS+REALITY client → traffic flows
- SIGTERM → graceful shutdown with connection drain

---

## Phase 8: Tests & Benchmarks

### 8.1 Integration tests (`wrongsv/tests/`)

- `test_vless_handshake`: Encode request → server decodes → validates user → responds
- `test_vision_flow`: Full XRV flow with padded packets
- `test_encryption_layer`: ServerInstance handshake → CommonConn read/write
- `test_end_to_end`: Client sends data → server receives → server forwards → target responds → response back to client

### 8.2 Benchmarks (`wrongsv/benches/`)

- `bench_encode_request_header` — throughput (MB/s)
- `bench_decode_request_header` — throughput
- `bench_xtls_padding` — padding overhead for various content sizes
- `bench_aead_encrypt` — encryption throughput (AES-GCM vs ChaCha20)
- `bench_end_to_end` — full proxy throughput with 1KB/64KB/1MB payloads

### 8.3 Fuzz targets (`wrongsv/fuzz/`)

- `fuzz_decode_request_header` — random bytes into decoder, no panic
- `fuzz_xtls_unpadding` — random bytes into unpadder, no panic

**Check:** `cargo test` passes all integration tests. `cargo bench` runs without error.

---

## Module Dependency Graph

```
uuid ─────────────────────────────────────────────┐
                                                   │
net-types ────────────────────────────────────────┤
                                                   │
protocol ── (depends on: uuid, net-types) ────────┤
                                                   │
vless-encoding ── (depends on: protocol, prost) ──┤
                                                   │
vless ── (depends on: protocol, uuid) ────────────┤
                                                   │
encryption ── (depends on: ring/aes-gcm) ─────────┤
                                                   │
server ── (depends on: vless, vless-encoding,     │
           encryption, net-types) ────────────────┤
                                                   │
wrongsv (binary) ── (depends on: server) ─────────┘
```

## File Count Budget

| Crate | Files | Max lines each |
|-------|-------|----------------|
| uuid | 2 (lib.rs + types) | 120 |
| net-types | 3 (address, port, network) | 100 |
| protocol | 4 (types, id, user, address_parser) | 150 |
| vless-encoding | 5 (encoding, addons, addons.proto, body, packet) | 150 |
| vless | 4 (account, validator, vision, lib) | 200 |
| encryption | 4 (common, server, aead, header) | 250 |
| server | 4 (config, inbound, handler, relay) | 200 |
| wrongsv | 1 (main.rs) | 150 |
| **Total** | **27 files** | ~4,000 lines |

## What We Intentionally Skip (for minimal server)

- Outbound (client-side) handler — server only
- Mux (multiplexing) — single-connection TCP/UDP only
- Reverse proxy (`RequestCommandRvs`)
- Fallback handling (TLS SNI-based routing)
- Proxy protocol (PROXY v1/v2)
- Pre-connect (connection pooling)
- 0-RTT session tickets (encryption)
- UDS (Unix domain socket) transport
- UDP over TCP (XUDP) framing
- Observatory (connection monitoring)
- Stats counters (can be added later)
