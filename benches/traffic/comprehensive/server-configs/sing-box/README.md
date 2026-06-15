# sing-box canonical server configs

Same UUIDs/passwords/REALITY keys as the equivalent `wrongsv/configs/{name}.toml`.
The matrix substitutes a per-protocol listen port (18443 or 18388) so client traffic
generators don't need to be reconfigured per cell.

## Supported

| wrongsv config | sing-box config |
|----------------|-----------------|
| `reality-vision.toml` | `reality-vision.json` |
| `tls-vision.toml`     | `tls-vision.json` (needs `/tmp/wrongsv-bench-cert.pem`) |
| `vmess.toml`          | `vmess.json` |
| `trojan-tls.toml`     | `trojan-tls.json` (needs `/tmp/wrongsv-bench-cert.pem`) |
| `shadowsocks-2022.toml` | `shadowsocks-2022.json` |

## Not yet shipped (sing-box supports but no canonical config here)

`ws-tcp.toml`, `httpupgrade.toml`, `anytls-*`, `hysteria2.toml`, `tuic.toml`,
`shadowsocks-aead.toml`, `shadowtls.toml`.

## Unsupported by sing-box server

- `meek.toml`, `gdocsviewer.toml`, `xhttp.toml`, `mixed-proxy.toml` — wrongsv-specific.
- `grpc.toml` (server-side gRPC inbound is incomplete in sing-box).
