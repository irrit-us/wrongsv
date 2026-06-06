# Protocol Coverage

This matrix tracks protocol support researched from upstream project
documentation and maps it to wrongsv implementation status.

## Implemented

| Protocol | wrongsv status | Upstream overlap |
| --- | --- | --- |
| VLESS raw TCP | Implemented | xray, sing-box, mihomo |
| VLESS + TLS | Implemented | xray, sing-box, mihomo |
| VLESS + REALITY | Implemented | xray, sing-box, mihomo |
| XTLS Vision | Implemented for TCP | xray, sing-box, mihomo |
| VLESS UDP packet relay | Implemented for non-Vision flows | xray, sing-box, mihomo |
| AnyTLS | Implemented, including sing-anytls stream mode | sing-box |
| Shadowsocks AEAD TCP/UDP | Implemented for `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` | Shadowsocks, Outline, GOST, sing-box, xray, mihomo |
| Outline-style Shadowsocks prefixes | Implemented for generated TCP and UDP response salts; prefixed client salts are accepted as ordinary Shadowsocks salts | Outline |
| Mixed SOCKS4/4A / SOCKS5 / HTTP proxy | Implemented for SOCKS4/4A CONNECT, SOCKS5 CONNECT, HTTP absolute-form forwarding, and HTTP CONNECT. Optional shared credentials apply to SOCKS5/HTTP; SOCKS4/4A is rejected when credentials are set. | GOST, sing-box, xray, local client proxy protocols |
| Trojan over TLS TCP | Implemented for TLS-wrapped TCP CONNECT, SHA224 password authentication, SOCKS5-style address headers, pipelined payload relay, and decrypted plaintext fallback for invalid post-TLS probes. | trojan-gfw, xray, sing-box, mihomo |

## Research Notes

| Project | Documented support | wrongsv coverage | Next practical gaps |
| --- | --- | --- | --- |
| GOST | Separates proxy protocols from channel protocols. Proxy protocols include HTTP, HTTP/2, SOCKS4/4A, SOCKS5, Shadowsocks, Shadowsocks UDP relay, SNI, and relay. Channels include raw TCP/UDP, TLS/DTLS, WebSocket/WSS, HTTP/2/H2C, gRPC, KCP, QUIC, HTTP/3, and WebTransport. Source: https://latest.gost.run/en/tutorials/protocols/overview/ | Shadowsocks AEAD TCP/UDP plus mixed SOCKS4/4A, SOCKS5, and HTTP proxy cover common GOST proxy protocol families. | WebSocket/TLS carrier modes. |
| Shadowsocks | AEAD TCP starts with a random salt, then encrypted length and payload chunks; payload length is a 2-byte big-endian value capped at `0x3fff`. AEAD UDP packets carry a salt plus encrypted address header and payload. Recommended AEAD methods include ChaCha20-Poly1305 and AES-GCM. Source: https://shadowsocks.org/doc/aead.html | AEAD TCP chunking, UDP packets, and address headers implemented. | AEAD-2022, SIP003 plugins. |
| Outline | Outline access keys are Shadowsocks-based and support optional TCP/UDP prefixes at the start of the salt for disguises. Source: https://developer.getoutline.org/vpn/advanced/prefixing/ | Standard Shadowsocks AEAD TCP/UDP works without prefixes; optional generated TCP/UDP response prefixes are configurable. | WebSocket transport compatibility. |
| SoftEther | Supports SoftEther VPN over HTTPS, OpenVPN, L2TP/IPsec, MS-SSTP, L2TPv3/IPsec, and EtherIP/IPsec. Source: https://www.softether.org/spec | No direct coverage; these are L2/L3 VPN protocols rather than stream proxy protocols. | Only consider SSTP/OpenVPN if wrongsv expands into VPN tunneling. |
| mihomo | VLESS supports REALITY, Vision flow, TCP transport, and packet encodings such as `packetaddr`/`xudp`; Shadowsocks supports AEAD and 2022 methods. Sources: https://wiki.metacubex.one/en/config/proxies/vless/ and https://wiki.metacubex.one/en/config/proxies/ss/ | VLESS + REALITY + Vision lifecycle tests exist; Shadowsocks AEAD TCP/UDP added. | xudp/packetaddr UDP encodings, Shadowsocks 2022. |
| Trojan | The original protocol performs a real TLS handshake, then sends `hex(SHA224(password))`, CRLF, a SOCKS5-like request, CRLF, and optional pipelined payload. Valid TCP requests open a direct tunnel; invalid post-TLS traffic can be relayed to a fallback endpoint. Source: https://trojan-gfw.github.io/trojan/protocol | TLS-wrapped TCP CONNECT, multi-password auth, pipelined payload, and plaintext fallback are implemented. | UDP ASSOCIATE packet relay. |
| xray-core | Inbound protocols include HTTP, Shadowsocks, SOCKS, Trojan, VLESS, VMess, WireGuard, Hysteria, and TUN. Transports include raw, XHTTP, mKCP, gRPC, WebSocket, HTTPUpgrade, Hysteria; security includes TLS and REALITY. Sources: https://xtls.github.io/en/config/inbounds/ and https://xtls.github.io/en/config/transports/ | VLESS + REALITY + Vision lifecycle tests exist; Shadowsocks AEAD TCP/UDP, mixed SOCKS4/4A/SOCKS5/HTTP proxy, and Trojan TLS TCP added. | WebSocket/gRPC/XHTTP carriers, VMess. |
| sing-box | Inbounds include mixed, SOCKS, HTTP, Shadowsocks, VMess, Trojan, Naive, Hysteria, ShadowTLS, VLESS, TUIC, Hysteria2, AnyTLS, tun, redirect, and tproxy. Trojan inbound requires users and TLS; Shadowsocks inbound lists AEAD 2022 and classic AEAD methods. Sources: https://sing-box.sagernet.org/configuration/inbound/ and https://sing-box.sagernet.org/configuration/inbound/trojan/ and https://sing-box.sagernet.org/configuration/inbound/shadowsocks/ | VLESS + REALITY lifecycle tests, AnyTLS/sing-anytls tests, Shadowsocks AEAD TCP/UDP, mixed SOCKS4/4A/SOCKS5/HTTP proxy, and Trojan TLS TCP added. | Shadowsocks 2022, VMess, Hysteria2/TUIC. |

## Protocol Specs

- SOCKS5 CONNECT and replies follow RFC 1928: https://www.rfc-editor.org/rfc/rfc1928
- SOCKS5 username/password authentication follows RFC 1929: https://www.rfc-editor.org/rfc/rfc1929
- SOCKS4 CONNECT follows the current IETF SOCKS4 draft: https://www.ietf.org/archive/id/draft-vance-socks-v4-07.html
- SOCKS4A domain signaling follows the current IETF SOCKS4A draft: https://www.ietf.org/archive/id/draft-vance-socks-v4a-02.html
- HTTP CONNECT tunnel semantics follow RFC 9110: https://www.rfc-editor.org/rfc/rfc9110
- HTTP/1.1 proxy absolute-form forwarding follows RFC 9112: https://www.rfc-editor.org/rfc/rfc9112.html
- Trojan over TLS follows the original trojan-gfw protocol: https://trojan-gfw.github.io/trojan/protocol

## Priority

1. Shadowsocks AEAD-2022.
2. Trojan UDP ASSOCIATE.
3. VLESS WebSocket/gRPC/XHTTP carriers.
4. QUIC/KCP/WebTransport carrier modes.
5. VMess, Hysteria2, TUIC, ShadowTLS.
6. SoftEther/OpenVPN/SSTP only if the project scope expands from proxy relay to VPN tunneling.
