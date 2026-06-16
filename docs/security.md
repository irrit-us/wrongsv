# Security Notes

Generated main configs, client configs, and manifests contain credentials such
as UUIDs, REALITY private keys, short IDs, AnyTLS passwords, Shadowsocks keys,
Trojan passwords, Hysteria2 passwords, and TUIC credentials.

On Unix-like systems, `wrongsv generate-main-config`,
`scripts/generate-client-configs.js`, and `scripts/deploy-remote.sh` write these
secret-bearing files with mode `0600` where they control file creation. Keep
generated output directories private and avoid pasting manifests or client files
into logs, issue trackers, or chat.

The JSON manifest intentionally includes generated values so deployment and
client generation can be reproduced from one directory. Treat it like the main
TOML config.
