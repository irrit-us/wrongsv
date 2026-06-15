# xray-core canonical server configs

Canonical xray server configs equivalent to `wrongsv/configs/{name}.toml`.
Same UUIDs/passwords/REALITY keys so the **client side** does not change between cells.

Port assignments: 18443 (TCP/TLS protocols), 18388 (Shadowsocks). The matrix runs
one server at a time, so port reuse across servers is intentional.

## Supported

| wrongsv config | xray config |
|----------------|-------------|
| `reality-vision.toml` | `reality-vision.json` |
| `tls-vision.toml`     | `tls-vision.json` (needs `/tmp/wrongsv-bench-cert.pem`) |
| `vmess.toml`          | `vmess.json` |
| `trojan-tls.toml`     | `trojan-tls.json` (needs `/tmp/wrongsv-bench-cert.pem`) |
| `shadowsocks-2022.toml` | `shadowsocks-2022.json` |

## Not yet shipped (xray supports but no canonical config here)

`ws-tcp.toml`, `httpupgrade.toml`, `grpc.toml`, `kcp.toml`, `quic.toml`,
`shadowsocks-aead.toml`, `hysteria2.toml`, `tuic.toml`, `xhttp.toml`.

Add by following the existing patterns; matrix.sh auto-discovers anything matching
`configs/{name}.toml` ↔ `server-configs/xray/{name}.json`.

## Unsupported by xray-core

- `anytls-*` — AnyTLS is sing-box / mihomo only.
- `meek.toml`, `gdocsviewer.toml` — wrongsv-specific transports.
- `webtransport.toml` — xray does not support WebTransport server-side.
- `wireguard.toml` — not a proxy server in the comparable sense.
- `mixed-proxy.toml` — wrongsv-specific aggregated inbound.
