# mihomo canonical server configs

Mihomo is primarily a **client / rule-based router**. Its server-side listener
support is limited compared with xray / sing-box. The matrix exercises mihomo
only for protocols it can serve.

## Supported

| wrongsv config | mihomo config |
|----------------|---------------|
| `vmess.toml`            | `vmess.yaml` |
| `trojan-tls.toml`       | `trojan-tls.yaml` (needs `/tmp/wrongsv-bench-cert.pem`) |
| `shadowsocks-2022.toml` | `shadowsocks-2022.yaml` |

## Unsupported by mihomo server

- VLESS server (mihomo is VLESS client only — no inbound listener).
- REALITY server (xray-specific).
- AnyTLS server.
- gRPC, WebSocket, HTTPUpgrade server-side proxy inbound (limited / experimental).

This is not a defect — mihomo's design point is rule-based outbound routing.
For protocols mihomo doesn't serve, matrix.sh records `unsupported` and the
report renders an em-dash.
