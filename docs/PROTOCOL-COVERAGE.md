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
| VLESS + QUIC | Implemented for QUIC transport with bidirectional stream VLESS relay, TLS (self-signed or custom), TCP/Vision/UDP relay (xray-compatible) | xray, sing-box |
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

## Research Notes

| Project | Documented support | wrongsv coverage | Next practical gaps |
| --- | --- | --- | --- |
| GOST | Separates proxy protocols from channel protocols. Proxy protocols include HTTP, HTTP/2, SOCKS4/4A, SOCKS5, Shadowsocks, Shadowsocks UDP relay, SNI, and relay. Channels include raw TCP/UDP, TLS/DTLS, WebSocket/WSS, HTTP/2/H2C, gRPC, KCP, QUIC, HTTP/3, and WebTransport. Source: https://latest.gost.run/en/tutorials/protocols/overview/ | Shadowsocks AEAD/AEAD-2022 TCP/UDP plus mixed SOCKS4/4A, SOCKS5, and HTTP proxy cover common GOST proxy protocol families. | WebSocket/TLS carrier modes. |
| Shadowsocks | Classic AEAD TCP starts with a random salt, then encrypted length and payload chunks; UDP packets carry a salt plus encrypted address header and payload. SIP022 AEAD-2022 requires fixed-length base64 PSKs, BLAKE3 subkeys, timestamped request/response headers, replay protection, separate AES-encrypted UDP headers, session IDs, and packet counters. Sources: https://shadowsocks.org/doc/aead.html and https://shadowsocks.org/doc/sip022.html | Classic AEAD TCP/UDP and AEAD-2022 TCP/UDP are implemented. | SIP003 plugins. |
| Outline | Outline access keys are Shadowsocks-based and support optional TCP/UDP prefixes at the start of the salt for disguises. Source: https://developer.getoutline.org/vpn/advanced/prefixing/ | Standard Shadowsocks AEAD TCP/UDP works without prefixes; optional generated TCP/UDP response prefixes are configurable. | WebSocket transport compatibility. |
| SoftEther | Supports SoftEther VPN over HTTPS, OpenVPN, L2TP/IPsec, MS-SSTP, L2TPv3/IPsec, and EtherIP/IPsec. Source: https://www.softether.org/spec | No direct coverage; these are L2/L3 VPN protocols rather than stream proxy protocols. | Only consider SSTP/OpenVPN if wrongsv expands into VPN tunneling. |
| mihomo | VLESS supports REALITY, Vision flow, TCP transport, WebSocket/gRPC/XHTTP-style transports, and UDP packet encodings where empty means raw and `packetaddr`/`xudp` select extended encodings; `ws-opts.v2ray-http-upgrade` enables the HTTPUpgrade-style carrier; Shadowsocks supports AEAD and 2022 methods; Trojan proxy entries support TLS, password auth, SNI, certificate verification controls, and UDP. Sources: https://wiki.metacubex.one/en/config/proxies/vless/ and https://wiki.metacubex.one/en/config/proxies/transport/ and https://wiki.metacubex.one/en/config/proxies/ss/ and https://wiki.metacubex.one/en/config/proxies/trojan/ | VLESS + REALITY + Vision lifecycle tests exist; VLESS packetaddr UDP lifecycle tests exist; VLESS + WebSocket TCP, HTTPUpgrade TCP, gRPC TCP, XHTTP TCP, and Mux.Cool/XUDP UDP lifecycle tests exist; Shadowsocks AEAD/AEAD-2022 TCP/UDP real-client lifecycle tests added; Trojan TCP/UDP real-client lifecycle tests added. | VMess. |
| Trojan | The original protocol performs a real TLS handshake, then sends `hex(SHA224(password))`, CRLF, a SOCKS5-like request, CRLF, and optional pipelined payload. Valid TCP requests open a direct tunnel; UDP ASSOCIATE packets carry address, port, length, CRLF, and payload; invalid post-TLS traffic can be relayed to a fallback endpoint. Source: https://trojan-gfw.github.io/trojan/protocol | TLS-wrapped TCP CONNECT, UDP ASSOCIATE packet relay, multi-password auth, pipelined payload, plaintext fallback, and sing-box/mihomo/xray real-client TCP/UDP lifecycle coverage are implemented. | Carrier variants such as WebSocket/gRPC where clients support them. |
| xray-core | Inbound protocols include HTTP, Shadowsocks, SOCKS, Trojan, VLESS, VMess, WireGuard, Hysteria, and TUN. Transports include raw, XHTTP, mKCP, gRPC, WebSocket, HTTPUpgrade, Hysteria; security includes TLS and REALITY. Mux.Cool can distribute UDP as XUDP over an established stream. Sources: https://xtls.github.io/en/config/inbounds/ and https://xtls.github.io/en/config/transports/ and https://xtls.github.io/en/config/outbounds/trojan.html and https://xtls.github.io/en/development/protocols/vless.html and https://xtls.github.io/en/development/protocols/muxcool.html | VLESS + REALITY + Vision lifecycle tests exist; VLESS + WebSocket TCP, HTTPUpgrade TCP, gRPC TCP, XHTTP TCP, and Mux.Cool/XUDP UDP lifecycle tests exist; Shadowsocks AEAD/AEAD-2022 TCP/UDP with real-client lifecycle tests, mixed SOCKS4/4A/SOCKS5/HTTP proxy, and Trojan TLS TCP/UDP with real-client lifecycle tests added. | VMess. |
| sing-box | Inbounds include mixed, SOCKS, HTTP, Shadowsocks, VMess, Trojan, Naive, Hysteria, ShadowTLS, VLESS, TUIC, Hysteria2, AnyTLS, tun, redirect, and tproxy. Trojan inbound requires users and TLS; Shadowsocks inbound lists AEAD 2022 and classic AEAD methods. VLESS outbound supports V2Ray transports, defaults UDP packet encoding to `xudp`, and also supports `packetaddr`. Sources: https://sing-box.sagernet.org/configuration/inbound/ and https://sing-box.sagernet.org/configuration/inbound/trojan/ and https://sing-box.sagernet.org/configuration/inbound/shadowsocks/ and https://sing-box.sagernet.org/configuration/outbound/trojan/ and https://sing-box.sagernet.org/configuration/outbound/vless/ | VLESS + REALITY lifecycle tests, VLESS packetaddr UDP lifecycle tests, VLESS + WebSocket TCP, HTTPUpgrade TCP, gRPC TCP, XHTTP TCP, and Mux.Cool/XUDP UDP lifecycle tests, AnyTLS/sing-anytls tests, Shadowsocks AEAD/AEAD-2022 TCP/UDP with real-client lifecycle tests, mixed SOCKS4/4A/SOCKS5/HTTP proxy, Trojan TLS TCP/UDP with real-client lifecycle tests, and TUIC/Hysteria2 server-side coverage added. | VMess. |
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

## Priority

1. ~~VLESS WebSocket TCP/raw UDP/Mux.Cool XUDP, packetaddr UDP, HTTPUpgrade TCP/UDP, gRPC, XHTTP, and QUIC carrier coverage~~ → **Done**.
2. KCP/WebTransport carrier modes.
3. VMess, ShadowTLS.
4. SoftEther/OpenVPN/SSTP only if the project scope expands from proxy relay to VPN tunneling.
