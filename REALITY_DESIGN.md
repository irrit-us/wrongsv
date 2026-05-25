# REALITY Protocol — Implementation Reference

## Protocol Summary

REALITY hijacks the TLS 1.3 handshake. The server presents a dynamically-generated
self-signed certificate to authenticated clients; unauthenticated probes are forwarded
to a real target (spider mode).

### ClientHello SessionID (32 bytes)

```
[0..3]:   Version bytes (1, 2, 3)
[3]:      Reserved (must be 0)
[4..8]:   Unix timestamp (big-endian uint32)
[8..16]:  ShortId (8 bytes, server identifier)
```

The full 32-byte SessionID is AES-256-GCM encrypted, producing 16 bytes ciphertext + 16 bytes tag.

### Auth Flow

1. Client X25519 ECDH: `shared = client_ephemeral_priv.diffie_hellman(server_pub)`
2. Auth key: `HKDF-SHA256(salt=client_random[0..20], ikm=shared, info="REALITY")` → 32 bytes
3. Encrypt payload (16 bytes) with AES-256-GCM(nonce=client_random[20..32], aad=ClientHello with zeroed session_id)
4. Server reverses: extract client's ephemeral pub from key_share extension, ECDH, HKDF, decrypt
5. Verify: timestamp within max_time_diff, shortId in allow-list
6. Dynamic cert: clone Ed25519 template cert + patch last 64 bytes with HMAC-SHA512(auth_key, raw_pubkey)

## Implementation (crates/reality/)

| Module | File | Purpose |
|--------|------|---------|
| Public API | `lib.rs` | RealityConfig, RealityError, RealityAcceptError, re-exports |
| ClientHello parser | `hello.rs` | Parse TLS record, extract random(32), session_id(32), key_share extension |
| Auth engine | `auth.rs` | X25519 ECDH, HKDF-SHA256, AES-256-GCM decrypt, timestamp + shortId verify, HMAC-SHA512 |
| Cert generation | `cert.rs` | Ed25519 keypair at startup, clone + HMAC-patch per connection |
| TLS acceptor | `tls.rs` | BufferedStream for ClientHello replay, rustls integration with dynamic cert resolver, spider fallback |

### Spider Mode

On REALITY auth failure with a configured `dest`, the server forwards the connection
to a real HTTPS target (e.g. `www.microsoft.com:443`). The buffered ClientHello is
replayed to the target, then TCP is bidirectionally relayed between client and target.

## Config Reference

```toml
[reality]
private_key = "d75c6e2f..."           # X25519 32-byte hex
short_ids = ["aaaaaaaaaaaaaaaa"]      # hex-encoded 8-byte short IDs
max_time_diff = 300                   # seconds, default 300
dest = "www.microsoft.com:443"        # optional spider fallback target
```

## Testing

- **Unit tests** in `crates/reality/src/`: auth roundtrip (3), cert generation (3), ClientHello parsing (4) — 10 total
- **Cross-validation tests** (6): HKDF derivation, session ID encrypt/decrypt, cert HMAC, cert generation, full auth flow — validated against Go-generated test vectors
- **33 REALITY-specific integration tests**: config parsing (5), basic accept/reject (2), short-id allow-listing (3), timestamp validation (2), spider fallback (3), malformed/rejected inputs (7), TLS 1.2, large ClientHello, missing key share, wrong key share group, 50 concurrent connections, mixed auth, large payload tunnel, rapid connect/disconnect
- **Go client E2E test**: black-box handshake verification against Rust server
