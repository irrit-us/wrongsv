# Protocol Coverage

This matrix tracks protocol support researched from upstream project
documentation and maps it to wrongsv implementation status.

## Implemented

| Protocol | wrongsv status | Upstream overlap |
| --- | --- | --- |
| VLESS raw TCP | Implemented | xray, sing-box, mihomo |
| VLESS + TLS | Implemented | xray, sing-box, mihomo |
| VLESS + REALITY | Implemented | xray, sing-box, mihomo |
| VLESS + WebSocket | Implemented for raw WS and TLS+WS, including raw VLESS UDP packet relay and Mux.Cool/XUDP UDP relay over WS | xray, sing-box, mihomo |
| VLESS + HTTPUpgrade | Implemented for raw HTTPUpgrade and optional TLS-wrapped HTTPUpgrade, including raw VLESS TCP/UDP and packetaddr UDP relay | xray, sing-box, mihomo |
| VLESS + gRPC | Implemented for HTTP/2 gRPC transport with protobuf Hunk framing, configurable service name, optional TLS, TCP/Vision/UDP relay (V2Ray-compatible) | xray, sing-box, mihomo |
| VLESS + XHTTP (SplitHTTP) | Implemented for HTTP/2 raw byte streaming (stream-one mode), configurable path prefix, optional host validation, optional TLS, TCP/Vision/UDP relay (xray-compatible) | xray, sing-box |
| VLESS + Meek | Implemented for V2Ray-compatible HTTPS request sessions using `X-Session-ID`-keyed HTTP POST polling, configurable path/host validation, static or generated TLS, TCP/Vision/UDP relay, and reusable request-session buffering. | v2ray-core |
| VLESS + Google Docs Viewer | Implemented for the V2Ray `gdocsviewer` origin endpoint, including plaintext or AES-256-GCM shared-key request envelopes, configurable origin path prefix, optional TLS, TCP/Vision/UDP relay, and reusable request-session buffering behind viewer/text fetches. | v2ray-core |
| VLESS + QUIC | Implemented for QUIC transport with bidirectional stream VLESS relay, TLS (self-signed or custom), TCP/Vision/UDP relay (xray-compatible) | xray, sing-box |
| VLESS + KCP (mKCP) | Implemented for UDP-based mKCP transport with FNV1a authentication, KCP session multiplexing, TCP/Vision/UDP relay (xray-compatible) | xray |
| XTLS Vision | Implemented for TCP | xray, sing-box, mihomo |
| VLESS UDP packet relay | Implemented for non-Vision flows, including raw length-prefixed UDP and V2Ray 5+ packetaddr UDP | xray, sing-box, mihomo |
| AnyTLS | Implemented, including sing-anytls stream mode | sing-box |
| Shadowsocks AEAD TCP/UDP | Implemented for `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, including real-client lifecycle coverage. | Shadowsocks, Outline, GOST, sing-box, xray, mihomo |
| Shadowsocks AEAD-2022 TCP/UDP | Implemented for required `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm` methods, including fixed-length base64 PSKs, BLAKE3 session subkeys, TCP timestamp/replay checks, response request-salt binding, UDP separate-header encryption, session packet counters, sliding replay protection, and real-client lifecycle coverage. | Shadowsocks, sing-box, xray, mihomo |
| Outline-style Shadowsocks prefixes | Implemented for generated TCP and UDP response salts; prefixed client salts are accepted as ordinary Shadowsocks salts | Outline |
| Mixed SOCKS4/4A / SOCKS5 / HTTP proxy | Implemented for SOCKS4/4A CONNECT, SOCKS5 CONNECT, HTTP absolute-form forwarding, and HTTP CONNECT. Optional shared credentials apply to SOCKS5/HTTP; SOCKS4/4A is rejected when credentials are set. | GOST, sing-box, xray, local client proxy protocols |
| Trojan over TLS TCP/UDP | Implemented for TLS-wrapped TCP CONNECT, UDP ASSOCIATE packet relay, SHA224 password authentication, SOCKS5-style address headers, pipelined payload relay, decrypted plaintext fallback for invalid post-TLS probes, and real-client lifecycle coverage. | trojan-gfw, xray, sing-box, mihomo |
| Hysteria2 | Implemented for HTTP/3 `/auth` authentication, `Hysteria-UDP` negotiation, `Hysteria-CC-RX` bandwidth hints, TCP relay over bidirectional QUIC streams, UDP relay over QUIC datagrams, and fragment reassembly. | sing-box, Hysteria 2 |
| TUIC | Implemented for HTTP/3 `/auth` authentication, TLS-exporter token derivation, TCP relay over bidirectional QUIC streams, UDP relay over QUIC datagrams, dissociate handling, heartbeat handling, and fragment reassembly. | sing-box |
| VLESS + WebTransport | Implemented for HTTP/3 WebTransport carrier with bidirectional stream VLESS relay, TLS (self-signed or custom), configurable path, optional host validation, TCP/Vision/UDP relay (GOST-compatible). | GOST |
| VLESS + ShadowTLS | Implemented for TLS 1.3 + RFC 8446 exporter HMAC-SHA256 authentication with VLESS relay, optional self-signed or custom certificates, fallback destination for unauthenticated probes, TCP/Vision/UDP relay. | sing-box |
| VMess AEAD | Implemented for standalone proxy protocol with UUID-based EAuID authentication, AES-128-GCM header encryption, chunked AES-128-GCM body encryption, response auth, TCP relay, and real-client lifecycle coverage. | v2ray-core, xray, sing-box |

## Research Notes

| Project | Documented support | wrongsv coverage | Next practical gaps |
| --- | --- | --- | --- |
| GOST | Separates proxy protocols from channel protocols. Proxy protocols include HTTP, HTTP/2, SOCKS4/4A, SOCKS5, Shadowsocks, Shadowsocks UDP relay, SNI, and relay. Channels include raw TCP/UDP, TLS/DTLS, WebSocket/WSS, HTTP/2/H2C, gRPC, KCP, QUIC, HTTP/3, and WebTransport. Source: https://latest.gost.run/en/tutorials/protocols/overview/ | Shadowsocks AEAD/AEAD-2022 TCP/UDP plus mixed SOCKS4/4A, SOCKS5, and HTTP proxy cover common GOST proxy protocol families. | WebSocket/TLS carrier modes. |
| Shadowsocks | Classic AEAD TCP starts with a random salt, then encrypted length and payload chunks; UDP packets carry a salt plus encrypted address header and payload. SIP022 AEAD-2022 requires fixed-length base64 PSKs, BLAKE3 subkeys, timestamped request/response headers, replay protection, separate AES-encrypted UDP headers, session IDs, and packet counters. Sources: https://shadowsocks.org/doc/aead.html and https://shadowsocks.org/doc/sip022.html | Classic AEAD TCP/UDP and AEAD-2022 TCP/UDP are implemented. | SIP003 plugins. |
| Outline | Outline access keys are Shadowsocks-based and support optional TCP/UDP prefixes at the start of the salt for disguises. Source: https://developer.getoutline.org/vpn/advanced/prefixing/ | Standard Shadowsocks AEAD TCP/UDP works without prefixes; optional generated TCP/UDP response prefixes are configurable. | WebSocket transport compatibility. |
| SoftEther | Supports SoftEther VPN over HTTPS, OpenVPN, L2TP/IPsec, MS-SSTP, L2TPv3/IPsec, and EtherIP/IPsec. Source: https://www.softether.org/spec | No direct coverage; these are L2/L3 VPN protocols rather than stream proxy protocols. | Only consider SSTP/OpenVPN if wrongsv expands into VPN tunneling. |
| mihomo | VLESS supports REALITY, Vision flow, TCP transport, WebSocket/gRPC/XHTTP-style transports, and UDP packet encodings where empty means raw and `packetaddr`/`xudp` select extended encodings; `ws-opts.v2ray-http-upgrade` enables the HTTPUpgrade-style carrier; Shadowsocks supports AEAD and 2022 methods; Trojan proxy entries support TLS, password auth, SNI, certificate verification controls, and UDP. Sources: https://wiki.metacubex.one/en/config/proxies/vless/ and https://wiki.metacubex.one/en/config/proxies/transport/ and https://wiki.metacubex.one/en/config/proxies/ss/ and https://wiki.metacubex.one/en/config/proxies/trojan/ | VLESS + REALITY + Vision lifecycle tests exist; VLESS packetaddr UDP lifecycle tests exist; VLESS + WebSocket TCP, HTTPUpgrade TCP, gRPC TCP, XHTTP TCP, and Mux.Cool/XUDP UDP lifecycle tests exist; Shadowsocks AEAD/AEAD-2022 TCP/UDP real-client lifecycle tests added; Trojan TCP/UDP real-client lifecycle tests added; VMess AEAD implemented. | Hysteria2 brate edge cases. |
| Trojan | The original protocol performs a real TLS handshake, then sends `hex(SHA224(password))`, CRLF, a SOCKS5-like request, CRLF, and optional pipelined payload. Valid TCP requests open a direct tunnel; UDP ASSOCIATE packets carry address, port, length, CRLF, and payload; invalid post-TLS traffic can be relayed to a fallback endpoint. Source: https://trojan-gfw.github.io/trojan/protocol | TLS-wrapped TCP CONNECT, UDP ASSOCIATE packet relay, multi-password auth, pipelined payload, plaintext fallback, and sing-box/mihomo/xray real-client TCP/UDP lifecycle coverage are implemented. | Carrier variants such as WebSocket/gRPC where clients support them. |
| xray-core | Inbound protocols include HTTP, Shadowsocks, SOCKS, Trojan, VLESS, VMess, WireGuard, Hysteria, and TUN. Transports include raw, XHTTP, mKCP, gRPC, WebSocket, HTTPUpgrade, Hysteria; security includes TLS and REALITY. Mux.Cool can distribute UDP as XUDP over an established stream. Sources: https://xtls.github.io/en/config/inbounds/ and https://xtls.github.io/en/config/transports/ and https://xtls.github.io/en/config/outbounds/trojan.html and https://xtls.github.io/en/development/protocols/vless.html and https://xtls.github.io/en/development/protocols/muxcool.html | VLESS + REALITY + Vision lifecycle tests exist; VLESS + WebSocket TCP, HTTPUpgrade TCP, gRPC TCP, XHTTP TCP, and Mux.Cool/XUDP UDP lifecycle tests exist; Shadowsocks AEAD/AEAD-2022 TCP/UDP with real-client lifecycle tests, mixed SOCKS4/4A/SOCKS5/HTTP proxy, and Trojan TLS TCP/UDP with real-client lifecycle tests added; VMess AEAD implemented. | WireGuard inbound. |
| sing-box | Inbounds include mixed, SOCKS, HTTP, Shadowsocks, VMess, Trojan, Naive, Hysteria, ShadowTLS, VLESS, TUIC, Hysteria2, AnyTLS, tun, redirect, and tproxy. Trojan inbound requires users and TLS; Shadowsocks inbound lists AEAD 2022 and classic AEAD methods. VLESS outbound supports V2Ray transports, defaults UDP packet encoding to `xudp`, and also supports `packetaddr`. Sources: https://sing-box.sagernet.org/configuration/inbound/ and https://sing-box.sagernet.org/configuration/inbound/trojan/ and https://sing-box.sagernet.org/configuration/inbound/shadowsocks/ and https://sing-box.sagernet.org/configuration/outbound/trojan/ and https://sing-box.sagernet.org/configuration/outbound/vless/ | VLESS + REALITY lifecycle tests, VLESS packetaddr UDP lifecycle tests, VLESS + WebSocket TCP, HTTPUpgrade TCP, gRPC TCP, XHTTP TCP, and Mux.Cool/XUDP UDP lifecycle tests, AnyTLS/sing-anytls tests, Shadowsocks AEAD/AEAD-2022 TCP/UDP with real-client lifecycle tests, mixed SOCKS4/4A/SOCKS5/HTTP proxy, Trojan TLS TCP/UDP with real-client lifecycle tests, and TUIC/Hysteria2 server-side coverage added; VMess AEAD implemented. | Naive inbound, tun/redirect/tproxy modes. |
| Hysteria2 | Official docs describe a QUIC transport with HTTP/3-style `/auth` handshake, UDP enablement flag, bandwidth negotiation, TCP stream requests, UDP datagrams, and fragmenting support. Source: https://v2.hysteria.network/docs/developers/Protocol/ and https://v2.hysteria.network/docs/advanced/Full-Server-Config/ | HTTP/3 auth, QUIC stream TCP relay, QUIC datagram UDP relay, auth response headers, and config validation are implemented. | Future obfuscation features. |
| TUIC | TUIC v5 uses QUIC over TLS with a client-authenticate stream, a TLS exporter-derived token, TCP CONNECT over bidirectional streams, UDP packet relay over datagrams or streams, dissociate messages, and heartbeat support. Source: https://github.com/EAimTY/tuic/blob/main/spec.md | HTTP/3 auth, TLS exporter token validation, TCP stream relay, UDP datagram relay, dissociate handling, and fragment reassembly are implemented. | Real-client lifecycle coverage and any optional extensions not exercised yet. |

## Protocol Specs

- SOCKS5 CONNECT and replies follow RFC 1928: https://www.rfc-editor.org/rfc/rfc1928
- SOCKS5 username/password authentication follows RFC 1929: https://www.rfc-editor.org/rfc/rfc1929
- SOCKS4 CONNECT follows the current IETF SOCKS4 draft: https://www.ietf.org/archive/id/draft-vance-socks-v4-07.html
- SOCKS4A domain signaling follows the current IETF SOCKS4A draft: https://www.ietf.org/archive/id/draft-vance-socks-v4a-02.html
- HTTP CONNECT tunnel semantics follow RFC 9110: https://www.rfc-editor.org/rfc/rfc9110
- HTTP/1.1 proxy absolute-form forwarding follows RFC 9112: https://www.rfc-editor.org/rfc/rfc9112.html
- VLESS packetaddr framing follows V2Fly's packetaddr implementation: https://github.com/v2fly/v2ray-core/tree/master/common/net/packetaddr
- V2Ray HTTPUpgrade performs an HTTP/1.1 101 upgrade and then carries raw bytes, following V2Fly's HTTPUpgrade implementation: https://github.com/v2fly/v2ray-core/tree/master/transport/internet/httpupgrade
- Mux.Cool/XUDP framing follows Xray's Mux.Cool protocol: https://xtls.github.io/en/development/protocols/muxcool.html
- Shadowsocks AEAD-2022 follows SIP022: https://shadowsocks.org/doc/sip022.html
- Trojan over TLS follows the original trojan-gfw protocol: https://trojan-gfw.github.io/trojan/protocol

## Recommended Protocol Stacks (2026)

Based on current GFW bypass research and community practice, the following
protocol stack combinations provide optimal stealth + resilience. The
gold standard is a **dual-protocol setup** on the same port (TCP+UDP/443)
with automatic failover.

### Tier 1 — Stealth General Purpose

```
VLESS + REALITY + XTLS-Vision (TCP/443)
```

| Component | Config file | Rationale |
|-----------|------------|-----------|
| VLESS | — | Stateless, no handshake fingerprint |
| REALITY | `reality-vision.toml` | Active probe resistance via TLS hijacking + spider fallback |
| XTLS Vision | flow=`xtls-rprx-vision` | Traffic analysis resistance (padding/unpadding) |

SNI should be a major CDN-backed domain (e.g. `www.microsoft.com`, `www.apple.com`)
— never the default `www.google.com`. Use uTLS Chrome fingerprint for browser mimicry.

### Tier 2 — Multi-Protocol Resilient (Recommended)

```
Primary:   VLESS + REALITY + Vision (TCP/443)
Fallback:  Hysteria2 + Salamander (UDP/443)
```

Run both on the same server. URLTest failover selects the fastest working path
every 5 minutes. When REALITY's TLS handshake gets fingerprinted by whitelist DPI,
Hysteria2's XOR-obfuscated QUIC stream defeats it because the first packet looks
like random bytes.

| Config | Transport | Protocol |
|--------|-----------|----------|
| `reality-vision.toml` | TCP/443 | VLESS + REALITY + Vision |
| `hysteria2.toml` | UDP/443 | Hysteria2 + Salamander obfuscation |

### Tier 3 — CDN-Friendly (WebSocket behind Nginx/Caddy)

```
VLESS + WebSocket + TLS (TCP/443 via CDN)
```

For deployments behind Cloudflare/Akamai. REALITY is **incompatible** with CDN
(requires TLS termination). Use Let's Encrypt certificates + standard TLS.

| Config | Transport | CDN |
|--------|-----------|-----|
| `ws-tcp.toml` + TLS cert | WebSocket + TLS | ✅ CDN-compatible |

### Tier 4 — TLS Mimicry (No Pre-Shared Keys)

```
VLESS + ShadowTLS v3 (TCP/443)
```

ShadowTLS performs a REAL TLS 1.3 handshake to a real website, then switches to
proxy mode after HMAC auth. Unlike REALITY, it doesn't need X25519 key
distribution — just a shared password. Wildcard SNI mode (v3) adds multi-domain
mimicry.

| Config | Auth | TLS |
|--------|------|-----|
| `shadowtls.toml` | RFC 8446 exporter HMAC-SHA256 | TLS 1.3 |

### Protocol Stack Decision Matrix

| Use Case | Primary Protocol | Fallback | Key Config |
|----------|-----------------|----------|------------|
| Maximum stealth | VLESS + REALITY + Vision | Hysteria2 + Salamander | `reality-vision.toml` + `hysteria2.toml` |
| CDN fronting | VLESS + WS + TLS | — | Custom TLS cert + `[websocket]` |
| No key distribution | ShadowTLS v3 | AnyTLS | `shadowtls.toml` + `anytls-vision.toml` |
| Post-quantum | VLESS + REALITY + Vision + ML-KEM-512 | — | `kyber-vision.toml` |
| Legacy client compat | VMess AEAD | Shadowsocks AEAD-2022 | `vmess.toml` + `shadowsocks-2022.toml` |

### Critical Deployment Rules

- **Port 443 only** — non-standard ports are immediate red flags
- **Major cloud IPs** — AWS/GCP/Oracle. Small VPS ranges are cataloged and
  blanket-blocked at the country edge with zero collateral damage
- **Split DNS** — DoH/DoQ for foreign domains, direct resolution for domestic
- **Health-check failover** — URLTest outbounds re-evaluate every 5 minutes
- **Rotate short IDs periodically** — if packet loss or RSTs appear, rotate
- **Never use Shadowsocks (original)** alone in 2026 — deeply analyzed by GFW
- **Never use WireGuard/OpenVPN** — DPI signatures are well-known

## Priority

1. ~~VLESS WebSocket TCP/raw UDP/Mux.Cool XUDP, packetaddr UDP, HTTPUpgrade TCP/UDP, gRPC, XHTTP, QUIC, and KCP carrier coverage~~ → **Done**.
2. ~~WebTransport carrier mode.~~ → **Done**.
3. ~~ShadowTLS~~ → **Done**. ~~VMess~~ → **Done**.
4. SoftEther/OpenVPN/SSTP only if the project scope expands from proxy relay to VPN tunneling.
