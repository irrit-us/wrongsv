# REALITY Protocol — Missing Components

## Protocol Summary

REALITY hijacks the TLS 1.3 handshake. The server presents a dynamically-generated
self-signed certificate to authenticated clients; unauthenticated probes are forwarded
to a real target (spider mode).

### ClientHello SessionID (32 bytes)
```
[0..3]:   Version bytes
[3]:      Reserved (0)
[4..8]:   Unix timestamp (big-endian uint32)
[8..16]:  ShortId (8 bytes, server identifier)
[16..32]: AES-GCM encrypted auth payload (16 bytes)
```

### Auth Flow
1. Client X25519 ECDH: `shared = client_ephemeral_priv.diffie_hellman(server_pub)`
2. Auth key: `HKDF-SHA256(shared, salt=client_random[0..20], info="REALITY")`
3. Encrypt SessionID[0..16] with AES-GCM(nonce=client_random[20..32], aad=ClientHello.raw)
4. Server reverses: extract client's ephemeral pub from key_share, ECDH, HKDF, decrypt
5. Verify: timestamp in range, shortId in allow-list
6. Client verifies server via: HMAC-SHA512(auth_key, server_cert_pubkey)

## What Exists

| Component | Status |
|-----------|--------|
| build.rs X25519 keypair | compile-time `BUILD_X25519_SK` / `BUILD_X25519_PK` |
| Short ID generation | compile-time `BUILD_SHORT_ID` |
| VLESS + XTLS Vision | raw TCP in handler.rs |
| AES-GCM | via aes-gcm crate |
| SHA2 | via sha2 crate |
| Kyber KEM | optional, in crates/kyber |

## What's Missing

| # | Component | Description |
|---|-----------|-------------|
| 1 | **ClientHello parser** | Parse TLS record + handshake headers, extract random(32), session_id(32), key_share extension |
| 2 | **X25519 ECDH (runtime)** | `x25519-dalek` as runtime dep: `StaticSecret::diffie_hellman()` |
| 3 | **HKDF-SHA256** | `hkdf` crate: derive auth key from shared secret |
| 4 | **SessionID decryption** | AES-GCM decrypt of session_id[16..32] with AAD=ClientHello.raw |
| 5 | **Timestamp + shortId verify** | Check unix timestamp vs maxTimeDiff, shortId in allow-list |
| 6 | **Dynamic cert generation** | `rcgen`: self-signed X.509 cert per connection |
| 7 | **TLS 1.3 server** | `rustls` with custom `ResolvesServerCert` + buffered ClientHello replay |
| 8 | **Spider mode** | On auth failure: TCP connect to dest, relay between client and target |
| 9 | **Server config** | reality section: private_key, short_ids, dest, server_names, max_time_diff |
| 10 | **Integration into handler** | Accept TLS → REALITY auth → VLESS decode → relay |
| 11 | **Tests** | Unit tests per component, integration test end-to-end |

## Implementation Order

1. `crates/reality/` — REALITY crate with auth logic (components 1-5)
2. Dynamic cert generation (component 6)
3. TLS integration + handler wiring (components 7-8)
4. Config extension (component 9)
5. Integration test (component 11)
