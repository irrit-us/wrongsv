# REALITY + VLESS Vision Deployment Guide

All operations run locally. The remote server only needs to run the binary — no Rust toolchain or compilation required.

## 1. Local: Generate X25519 Keypair

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

## 2. Local: Prepare Config

Replace `PRIVATE_KEY_HEX` with the private key from step 1, save as `config.toml`:

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

## 3. Local: Download Binary

Grab the musl static binary from GitHub Releases (no glibc dependency):

```bash
curl -L -o wrongsv.xz https://github.com/irrit-us/wrongsv/releases/download/v0.2.2/wrongsv-linux-x86_64-musl.xz
xz -d wrongsv.xz
chmod +x wrongsv
```

## 4. Upload to Remote Server

```bash
scp wrongsv config.toml root@YOUR_SERVER_IP:/opt/wrongsv/
```

## 5. Remote: Install and Run

```bash
ssh root@YOUR_SERVER_IP
```

```bash
# Open the port
sudo firewall-cmd --add-port=15005/tcp --permanent && sudo firewall-cmd --reload

# systemd service
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
systemctl status wrongsv
```

## 6. Local: Generate Client Config

```bash
./wrongsv \
  --config config.toml \
  --print-client-config \
  --server-host YOUR_SERVER_IP \
  --servername download-porter.hoyoverse.com \
  --client-name "My Node"
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
  "fingerprint": "chrome",
  "servername": "download-porter.hoyoverse.com",
  "reality-opts": {
    "publicKey": "YOUR_PUBLIC_KEY",
    "shortId": "09561058"
  }
}
```

Replace `server` and `publicKey` with actual values, then import into your client.

## Verify

```bash
ssh root@YOUR_SERVER_IP journalctl -u wrongsv -f
```

Look for `REALITY raw_pubkey` and `VLESS server listening on 0.0.0.0:15005`. When a client connects, the log will show `REALITY auth OK`.
