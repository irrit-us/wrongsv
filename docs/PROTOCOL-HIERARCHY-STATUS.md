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
| Shadowsocks AEAD | implemented | implemented | missing | endpoint diagnostics distinguish built-in crypto instead of outer TLS |
| Shadowsocks 2022 | implemented | implemented | missing | method-specific internal security resolves to `shadowsocks_2022` |

### 1.4 Trojan

| Protocol/profile | Server | Endpoint layer | Client export | Notes |
| --- | --- | --- | --- | --- |
| Trojan over TLS | implemented | implemented | missing | raw transport + fixed TLS model |

### 1.5 QUIC-native proxy protocols

| Protocol/profile | Server | Endpoint layer | Client export | Notes |
| --- | --- | --- | --- | --- |
| Hysteria2 | implemented | implemented | missing | fixed QUIC + fixed TLS; Salamander camouflage now implemented |
| TUIC | implemented | implemented | missing | fixed QUIC + fixed TLS; export adapters still missing |

### 1.6 Tunnel protocols

| Protocol/profile | Server | Endpoint layer | Client export | Notes |
| --- | --- | --- | --- | --- |
| WireGuard tunnel service | implemented | implemented | partial | mihomo/sing-box-family export implemented; xray export intentionally unsupported |

### 1.7 Local proxy / gateway protocols

| Protocol/profile | Server | Endpoint layer | Client export | Notes |
| --- | --- | --- | --- | --- |
| Mixed SOCKS4/4A + SOCKS5 + HTTP proxy | implemented | implemented | missing | modeled as a peer protocol for diagnostics; not a remote client export target |

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
| salamander | implemented | Hysteria2 | per-packet QUIC UDP obfuscation |
| gecko | missing | Hysteria2 | upstream Hysteria obfuscation variant; next direct follow-up after Salamander |

### 5.2 Ingress

| Component class | Status | Notes |
| --- | --- | --- |
| fallback destinations / plaintext relays | partial | implemented ad hoc in several inbounds, not yet normalized in the endpoint layer |
| reverse-proxy / CDN deployment components | missing | deployment patterns exist, but no normalized endpoint component model yet |

### 5.3 Performance

| Component class | Status | Notes |
| --- | --- | --- |
| KCP tuning | implemented | mtu/tti/seed modeled in config/export |
| QUIC relay toggles | partial | per-protocol toggles exist; not yet normalized as shared performance components |
| TUIC congestion control | implemented | server behavior wired; endpoint layer metadata still minimal |
| Hysteria bandwidth hints | partial | `down_mbps` and `ignore_client_bandwidth` are wired; `up_mbps` is still not consumed |

### 5.4 Network

| Component class | Status | Notes |
| --- | --- | --- |
| low-level socket / routing controls | missing | endpoint layer has a `network` bucket, but no server-facing network components are normalized yet |
| full-tunnel WireGuard routing/NAT | partial | current WireGuard mode is service-forwarding oriented, not a full routed tunnel stack |

## 6. Current Constraint Obstacles

These are the main remaining obstacles to fully satisfying
`docs/design_constraint.md`:

1. The endpoint layer now models more of the implemented server protocols, but
   client export adapters still cover only VLESS, VMess, and WireGuard.

2. Ingress/deployment features such as fallback destinations, CDN-facing
   settings, and reverse-proxy coexistence are still implemented per-handler
   instead of as normalized `components.ingress`.

3. Performance-related options for Hysteria2, TUIC, QUIC, and KCP are still
   protocol-specific config fields rather than shared endpoint-layer component
   descriptors.

4. Some config fields are parsed but not fully consumed:
   - `hysteria2.up_mbps`
   - `tuic.zero_rtt_handshake`

## 7. Priority Queue For Missing Popular Components

This queue is ordered by a mix of upstream popularity, architectural fit with
the endpoint model, and implementation size.

1. `Hysteria2 Gecko obfuscation`
   - Same upstream component family as Salamander.
   - Reuses the new QUIC obfuscation layer.
   - Popular enough upstream to justify being the next camouflage slice.

2. `Hysteria2/TUIC/Trojan/Shadowsocks export adapters`
   - Server support exists.
   - Endpoint diagnostics now recognize these protocols.
   - Export parity is the main missing user-facing gap.

3. `Normalize ingress components`
   - Convert fallback destinations and similar deployment features into
     `components.ingress` instead of handler-local knobs.

4. `Full routed WireGuard mode`
   - Expand from fixed service forwarding to fuller tunnel routing/NAT behavior.

5. `Naive inbound`
   - Popular in sing-box and adjacent ecosystems, but a larger protocol slice
     than the Hysteria2 component follow-ups.

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
