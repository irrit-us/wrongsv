#!/usr/bin/env python3
"""AnyTLS client test — verify AnyTLS auth + VLESS relay end-to-end.

Protocol (after TCP connect):
  1. TLS 1.3 handshake (self-signed cert, no verification)
  2. Client sends: SHA256(password)[32B] || padding_len(u16 BE)[2B] || random_padding[N B]
  3. If auth OK, server proceeds to VLESS — client sends VLESS request header
  4. Server sends VLESS response header, then relays to target
  5. Client sends HTTP request, reads HTTP response

Usage:
  ./scripts/anytls-test.py [server_host] [port]
"""

import hashlib
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

SERVER = sys.argv[1] if len(sys.argv) > 1 else "<YOUR_SERVER_IP>"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443
PASSWORD = "wrongsv-test-secret"
UUID_HEX = "f3fd9d7e805b4a0a97695419ebc56d25"  # no dashes
TARGET_HOST = "httpbin.org"
TARGET_PORT = 80
TIMEOUT = 30

PASS = 0
FAIL = 0
OUTPUT_DIR = Path("/tmp/wrongsv-anytls-test")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def ok(msg):
    global PASS
    PASS += 1
    print(f"  \033[32mOK\033[0m {msg}")


def bad(msg):
    global FAIL
    FAIL += 1
    print(f"  \033[31mFAIL\033[0m {msg}")


def build_vless_header(uuid_hex, host, port):
    """Build VLESS TCP request header for addressing host:port."""
    header = bytearray()

    # Version (1 byte)
    header.append(0x00)

    # User ID (16 bytes)
    uuid_bytes = bytes.fromhex(uuid_hex)
    assert len(uuid_bytes) == 16
    header.extend(uuid_bytes)

    # Addons: empty (1 byte length = 0)
    header.append(0x00)

    # Command: 1 = TCP
    header.append(0x01)

    # Port (2 bytes BE, port-first VLESS convention)
    header.append((port >> 8) & 0xFF)
    header.append(port & 0xFF)

    # Address type: 2 = domain
    header.append(0x02)

    # Domain length + domain
    domain_bytes = host.encode()
    header.append(len(domain_bytes))
    header.extend(domain_bytes)

    return bytes(header)


def build_http_request(host, path="/get"):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()


# ── 1. TCP connect ────────────────────────────────────────────────────────

print(f"=== AnyTLS client test ===")
print(f"Server: {SERVER}:{PORT}")
print(f"Password: {PASSWORD}")

t0 = time.time()
print(f"\n[1/5] TCP connect to {SERVER}:{PORT} ...")
sock = socket.create_connection((SERVER, PORT), timeout=TIMEOUT)
ok(f"Connected ({(time.time()-t0)*1000:.0f}ms)")

try:
    # ── 2. TLS handshake ───────────────────────────────────────────────────

    print(f"[2/5] TLS handshake ...")
    t0 = time.time()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # self-signed cert
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    tls = ctx.wrap_socket(sock, server_hostname="cloudfront.net")
    elapsed = time.time() - t0
    ok(f"TLS handshake complete ({elapsed*1000:.0f}ms)")
    print(f"  TLS version: {tls.version()}")

    # ── 3. AnyTLS auth frame ───────────────────────────────────────────────

    print(f"[3/5] Sending AnyTLS auth frame ...")
    t0 = time.time()

    password_hash = hashlib.sha256(PASSWORD.encode()).digest()
    assert len(password_hash) == 32

    # Auth frame: SHA256(password)[32B] || padding_len(0)[2B]
    auth_frame = password_hash + b'\x00\x00'
    tls.sendall(auth_frame)
    ok(f"Auth frame sent (SHA256(password) + zero padding)")

    # Brief pause to let server process auth
    time.sleep(0.3)

    # Try to read — if auth failed, server closes connection immediately.
    # If auth succeeded, the connection stays open and we can proceed to VLESS.
    tls.setblocking(False)
    try:
        data = tls.read(1)
        if data == b'':
            bad("Auth rejected — server closed connection")
            raise SystemExit(1)
        else:
            # Server sent something — this shouldn't happen before VLESS header
            print(f"  Unexpected early data: {data.hex()}")
    except ssl.SSLWantReadError:
        # Expected — no data yet, connection is still alive
        pass
    except BlockingIOError:
        pass
    tls.setblocking(True)

    ok(f"AnyTLS auth accepted — connection alive")

    # ── 4. VLESS header + HTTP request ─────────────────────────────────────

    print(f"[4/5] Sending VLESS header + HTTP request ...")

    vless_header = build_vless_header(UUID_HEX, TARGET_HOST, TARGET_PORT)
    http_request = build_http_request(TARGET_HOST)

    print(f"  VLESS header: {len(vless_header)}B")
    print(f"  Target: {TARGET_HOST}:{TARGET_PORT}")
    print(f"  HTTP request: {http_request.decode().strip().replace(chr(13)+chr(10), ' | ')}")

    tls.sendall(vless_header + http_request)
    ok("VLESS header + HTTP request sent")

    # ── 5. Read response ───────────────────────────────────────────────────

    print(f"[5/5] Reading response ...")
    t0 = time.time()

    # Read VLESS response header: version(1) + addons_len(1) + [addons(N)]
    # For empty addons: 2 bytes total
    resp_header = b''
    while len(resp_header) < 2:
        chunk = tls.read(2 - len(resp_header))
        if not chunk:
            bad("Connection closed before response header")
            raise SystemExit(1)
        resp_header += chunk

    resp_version = resp_header[0]
    addons_len = resp_header[1]
    if addons_len > 0:
        addons_data = tls.read(addons_len)
    else:
        addons_data = b''

    ok(f"VLESS response: version={resp_version}, addons_len={addons_len}")

    # Read HTTP response
    response = b''
    try:
        tls.settimeout(10)
        while True:
            chunk = tls.read(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    except ssl.SSLWantReadError:
        pass

    elapsed = time.time() - t0

    # Save response
    resp_path = OUTPUT_DIR / "response.txt"
    resp_path.write_bytes(response)
    ok(f"Response: {len(response)}B ({elapsed:.1f}s)")

    # Parse HTTP response
    if response:
        try:
            header_end = response.index(b'\r\n\r\n')
            status_line = response[:response.index(b'\r\n')].decode()
            body = response[header_end + 4:]
            print(f"\n  Status: {status_line}")
            print(f"  Body ({len(body)}B):")
            print(f"  {body.decode()[:500]}")
        except (ValueError, UnicodeDecodeError):
            print(f"\n  Raw response ({len(response)}B):")
            print(f"  {response[:300]}")

    # Verify
    if b'200' in response[:30] or b'HTTP' in response[:20]:
        ok("Got valid HTTP response through AnyTLS + VLESS")
    elif b'httpbin' in response or b'"headers"' in response:
        ok("Got httpbin response (no status line)")
    elif len(response) > 100:
        ok(f"Got data ({len(response)}B) through AnyTLS tunnel")
    else:
        bad(f"Unexpected response: {response[:200]}")

except Exception as e:
    bad(f"Error: {e}")
    raise

finally:
    try:
        tls.close()
    except Exception:
        pass

# ── Summary ─────────────────────────────────────────────────────────────────

print(f"\nResults: {PASS} ok, {FAIL} failed")
if FAIL == 0:
    print("OVERALL: PASS — AnyTLS auth + VLESS relay works")
else:
    print(f"OVERALL: {FAIL} FAILURE(S)")
    sys.exit(1)
