# TLS / REALITY + VLESS Vision Deployment Guide

All operations run locally. The remote server only needs to run the binary — no Rust toolchain or compilation required.

Choose your transport: **Plain TLS** (simplest, sing-box/mihomo compatible) or **REALITY** (ECDH auth, requires keypair generation).

## Plain TLS Deployment

### 1. Local: Prepare Config

Save as `config.toml`:

```toml
listen = "0.0.0.0:15005"

[[users]]
id = "af51fda9-e147-4431-8b58-063560206ebd"
email = "user@example.com"
flow = "xtls-rprx-vision"

[tls]
```

### 2. Download and Upload Binary

```bash
curl -L -o wrongsv.xz https://github.com/irrit-us/wrongsv/releases/download/v0.2.2/wrongsv-linux-x86_64-musl.xz
xz -d wrongsv.xz && chmod +x wrongsv
scp wrongsv config.toml root@YOUR_SERVER_IP:/opt/wrongsv/
```

### 3. Remote: Install Service

```bash
ssh root@YOUR_SERVER_IP
sudo firewall-cmd --add-port=15005/tcp --permanent && sudo firewall-cmd --reload

sudo tee /etc/systemd/system/wrongsv.service << 'EOF'
[Unit]
Description=wrongsv VLESS proxy
After=network.target

[Service]
Type=simple
ExecStart=/opt/wrongsv/wrongsv --config /opt/wrongsv/config.toml
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now wrongsv
```

### 4. Local: Generate Client Config

```bash
# sing-box format
./wrongsv --config config.toml --print-client-config \
  --server-host YOUR_SERVER_IP --servername cloudfront.net --format sing-box

# mihomo/FlClash format
./wrongsv --config config.toml --print-client-config \
  --server-host YOUR_SERVER_IP --servername cloudfront.net
```

---

## REALITY Deployment

### 1. Local: Generate X25519 Keypair

```bash
python3 -c "
import os, base64

sk = os.urandom(32)
sk_hex = sk.hex()
print(f'Private key: {sk_hex}')

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
pk = X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw()
pk_b64 = base64.urlsafe_b64encode(pk).rstrip(b'=').decode()
print(f'Public key: {pk_b64}')
"
```

If `cryptography` is missing: `pip install cryptography`

### 2. Local: Prepare Config

Replace `PRIVATE_KEY_HEX` with the private key from step 1:

```toml
listen = "0.0.0.0:15005"

[[users]]
id = "af51fda9-e147-4431-8b58-063560206ebd"
email = "user@example.com"
flow = "xtls-rprx-vision"

[reality]
private_key = "PRIVATE_KEY_HEX"
short_ids = ["09561058"]
max_time_diff = 300
dest = "download-porter.hoyoverse.com:443"
```

### 3-5. Same as Plain TLS: Download, Upload, Install Service

### 6. Local: Generate Client Config

```bash
./wrongsv --config config.toml --print-client-config \
  --server-host YOUR_SERVER_IP --servername download-porter.hoyoverse.com --client-name "My Node"
```

Output:

```json
{
  "name": "My Node",
  "type": "vless",
  "server": "YOUR_SERVER_IP",
  "port": 15005,
  "uuid": "af51fda9-e147-4431-8b58-063560206ebd",
  "encryption": "none",
  "flow": "xtls-rprx-vision",
  "udp": true,
  "tls": true,
  "client-fingerprint": "chrome",
  "servername": "download-porter.hoyoverse.com",
  "reality-opts": {
    "public-key": "YOUR_PUBLIC_KEY",
    "short-id": "09561058"
  }
}
```

Replace `server` and `public-key` with actual values, then import into your client.

---

## Verify

```bash
ssh root@YOUR_SERVER_IP journalctl -u wrongsv -f
```

Plain TLS: look for `TLS enabled` and `TLS handshake complete`. REALITY: look for `REALITY raw_pubkey`. When a client connects, the log shows `TCP <email> -> <target>:<port>`.
