# Protocol Hierarchy Status

This document indexes `wrongsv` by the protocol hierarchy defined in
[design_constraint.md](./design_constraint.md) instead of by flat product or
client names.

Status labels used here:

- `implemented`: server/runtime behavior is wired and tested
- `partial`: the project supports the capability in some layers, but not all
- `missing`: the capability is documented upstream but not yet implemented here

## 1. Proxy Or Tunnel Protocol Layer

### 1.1 VLESS family

| Protocol/profile | Server | Endpoint layer | Client export | Notes |
| --- | --- | --- | --- | --- |
| VLESS raw | implemented | implemented | implemented | canonical `raw` transport is now explicit |
| VLESS + TLS | implemented | implemented | implemented | |
| VLESS + REALITY | implemented | implemented | implemented | |
| VLESS + WebSocket | implemented | implemented | implemented | optional TLS modeled as outer security |
| VLESS + HTTPUpgrade | implemented | implemented | implemented | |
| VLESS + gRPC | implemented | implemented | implemented | |
| VLESS + XHTTP | implemented | implemented | implemented | |
| VLESS + Meek | implemented | implemented | xray-only | optional TLS now resolves correctly |
| VLESS + Google Docs Viewer | implemented | implemented | xray-only | optional TLS resolves correctly |
| VLESS + QUIC | implemented | implemented | implemented | |
| VLESS + KCP | implemented | implemented | implemented | |
| VLESS + WebTransport | implemented | implemented | xray-only | |

### 1.2 VMess

| Protocol/profile | Server | Endpoint layer | Client export | Notes |
| --- | --- | --- | --- | --- |
| VMess AEAD | implemented | implemented | implemented | protocol-internal security is surfaced as `vmess_aead` |

### 1.3 Shadowsocks family

| Protocol/profile | Server | Endpoint layer | Client export | Notes |
| --- | --- | --- | --- | --- |
| Shadowsocks AEAD | implemented | implemented | implemented | mihomo/sing-box/xray/hiddify renderers wired |
| Shadowsocks 2022 | implemented | implemented | implemented | method-specific internal security resolves to `shadowsocks_2022` |

### 1.4 Trojan

| Protocol/profile | Server | Endpoint layer | Client export | Notes |
| --- | --- | --- | --- | --- |
| Trojan over TLS | implemented | implemented | implemented | mihomo/sing-box/xray/hiddify renderers wired |

### 1.5 QUIC-native proxy protocols

| Protocol/profile | Server | Endpoint layer | Client export | Notes |
| --- | --- | --- | --- | --- |
| Hysteria2 | implemented | implemented | partial | mihomo/sing-box/hiddify export implemented; xray export intentionally unsupported (no native handler in xray) |
| TUIC | implemented | implemented | partial | mihomo/sing-box/hiddify export implemented; xray export intentionally unsupported (no native handler in xray) |

### 1.6 Tunnel protocols

| Protocol/profile | Server | Endpoint layer | Client export | Notes |
| --- | --- | --- | --- | --- |
| WireGuard tunnel service | implemented | implemented | partial | mihomo/sing-box-family export implemented; xray export intentionally unsupported |

### 1.7 Local proxy / gateway protocols

| Protocol/profile | Server | Endpoint layer | Client export | Notes |
| --- | --- | --- | --- | --- |
| Mixed SOCKS4/4A + SOCKS5 + HTTP proxy | implemented | implemented | missing | modeled as a peer protocol for diagnostics; not a remote client export target |

### 1.8 Naive (HTTP/2 CONNECT over TLS)

| Protocol/profile | Server | Endpoint layer | Client export | Notes |
| --- | --- | --- | --- | --- |
| Naive v1 (h2 CONNECT + Basic auth + padded framing) | implemented | implemented | missing | HTTP/3 variant and RST_STREAM obfuscation are deferred — see [deferred-work.md](./deferred-work.md) |

## 2. Transport Method Layer

| Transport method | Status | Notes |
| --- | --- | --- |
| raw | implemented | now explicit in the normalized endpoint model and registry defaults |
| websocket | implemented | |
| httpupgrade | implemented | |
| grpc | implemented | |
| xhttp | implemented | |
| meek | implemented | optional TLS modeled correctly |
| gdocsviewer | implemented | optional TLS modeled correctly |
| quic | implemented | fixed for Hysteria2/TUIC, selectable for VLESS |
| kcp | implemented | |
| webtransport | implemented | |
| h2-connect | implemented | HTTP/2 `CONNECT` over TLS; currently used by Naive inbound |

## 3. Outer Security Layer

| Outer security | Status | Notes |
| --- | --- | --- |
| none | implemented | |
| tls | implemented | fixed for Trojan/Hysteria2/TUIC, optional/selectable for VLESS families |
| reality | implemented | VLESS-specific outer security profile |

## 4. Protocol-Internal Security Layer

| Internal security | Status | Notes |
| --- | --- | --- |
| vmess_aead | implemented | |
| shadowsocks_aead | implemented | |
| shadowsocks_2022 | implemented | |
| wireguard_noise | implemented | |

## 5. Optional Component Layer

### 5.1 Camouflage

| Component | Status | Attached to | Notes |
| --- | --- | --- | --- |
| vision | implemented | VLESS | performance-oriented VLESS flow marker |
| anytls | implemented | VLESS | modeled as camouflage around a raw/TLS VLESS stack |
| shadowtls | implemented | VLESS | modeled as camouflage around a raw/TLS VLESS stack |
| hysteria-salamander | implemented | Hysteria2 | per-packet QUIC UDP obfuscation |
| hysteria-gecko | implemented | Hysteria2 | Salamander-based QUIC long-header fragmentation and padding |
| naive-padding | implemented | Naive | random 3-byte-header padded framing on the first 8 ops per direction; RST_STREAM obfuscation deferred (see [deferred-work.md](./deferred-work.md)) |

### 5.2 Ingress

| Component class | Status | Notes |
| --- | --- | --- |
| fallback destinations / plaintext relays | implemented | normalized as `components.ingress = [fallback-destination]` when a protocol has a configured `dest` (REALITY, AnyTLS, TLS, Trojan, ShadowTLS, WebSocket+TLS, HTTPUpgrade+TLS, gRPC+TLS, XHTTP+TLS, Meek+TLS, Google Docs Viewer+TLS, QUIC, WebTransport, Hysteria2, TUIC) |
| reverse-proxy / CDN deployment components | missing | deployment patterns exist, but no normalized endpoint component model yet |

### 5.3 Performance

| Component class | Status | Notes |
| --- | --- | --- |
| KCP tuning | implemented | mtu/tti/seed modeled in config/export |
| QUIC relay toggles | partial | per-protocol toggles exist; not yet normalized as shared performance components |
| TUIC congestion control | implemented | server behavior wired; endpoint layer metadata still minimal |
| Hysteria bandwidth hints | implemented | `down_mbps` flows into `Hysteria-CC-RX`; `up_mbps` is honored as a 200 ms BDP cap on the QUIC send window (quinn does not implement Brutal CC) |

### 5.4 Network

| Component class | Status | Notes |
| --- | --- | --- |
| low-level socket / routing controls | missing | endpoint layer has a `network` bucket, but no server-facing network components are normalized yet |
| full-tunnel WireGuard routing/NAT | partial | TCP and UDP outbound routing are now implemented via `wireguard.outbound = true` and surface as `components.network = [routed-tunnel]`; ICMP outbound routing remains missing |

## 6. Current Constraint Obstacles

These are the main remaining obstacles to fully satisfying
`docs/design_constraint.md`:

1. The endpoint layer now models more of the implemented server protocols, and
   client export adapters cover VLESS, VMess, WireGuard, Shadowsocks, Trojan,
   Hysteria2 (mihomo/sing-box/hiddify), and TUIC (mihomo/sing-box/hiddify).
   Naive export adapters are still missing.

2. Ingress/deployment features such as reverse-proxy/CDN coexistence are still
   missing. Fallback destinations are now normalized as
   `components.ingress = [fallback-destination]` when configured.

3. Performance-related options for Hysteria2, TUIC, QUIC, and KCP are still
   protocol-specific config fields rather than shared endpoint-layer component
   descriptors.

4. Some config fields are parsed but not fully consumed:
   - (none currently — `hysteria2.up_mbps` is now applied via the QUIC
     send-window BDP cap; `tuic.zero_rtt_handshake` toggles rustls
     `max_early_data_size`.)

## 7. Priority Queue For Missing Popular Components

This queue is ordered by a mix of upstream popularity, architectural fit with
the endpoint model, and implementation size.

1. `Hysteria2/TUIC/Trojan/Shadowsocks export adapters`
   - Server support exists.
   - Endpoint diagnostics now recognize these protocols.
   - Export adapters are implemented: Shadowsocks and Trojan across mihomo,
     sing-box, xray, and hiddify; Hysteria2 and TUIC across mihomo, sing-box,
     and hiddify (xray is not a target because xray does not natively support
     the Hysteria2/TUIC protocols).

2. `Normalize ingress components`
   - Fallback destinations now surface as `Component::FallbackDestination` in
     `components.ingress` (the per-handler `dest` knob is preserved at the
     config layer and exposed through diagnostics).
   - Reverse-proxy / CDN deployment components remain to be modeled.

3. `Full routed WireGuard mode`
   - TCP and UDP outbound routing are implemented; peers can now reach arbitrary
     TCP and UDP destinations via `wireguard.outbound = true`, surfaced as
     `components.network = [routed-tunnel]`. UDP sessions time out after 60s
     of bidirectional idle.
   - ICMP outbound routing remains to be wired through the gvisor stack
     before the mode can be called fully routed.

4. `Naive inbound`
   - v1 (HTTP/2 CONNECT over TLS + HTTP Basic auth + padded framing) is
     implemented as a server-side inbound. Client export adapters are not
     yet wired.
   - RST_STREAM obfuscation and the HTTP/3 variant are intentionally out
     of v1 scope — see [deferred-work.md](./deferred-work.md).

## 8. Upstream Research Index

Primary source references used for this hierarchy and priority list:

- Hysteria 2 full server configuration and protocol docs:
  - https://v2.hysteria.network/docs/advanced/Full-Server-Config/
  - https://v2.hysteria.network/docs/developers/Protocol/
- Hysteria upstream obfuscation code:
  - https://github.com/apernet/hysteria/tree/master/extras/obfs
- sing-box inbound and outbound protocol docs:
  - https://sing-box.sagernet.org/configuration/inbound/
  - https://sing-box.sagernet.org/configuration/outbound/vless/
- Xray transport and inbound docs:
  - https://xtls.github.io/en/config/transports/
  - https://xtls.github.io/en/config/inbounds/
