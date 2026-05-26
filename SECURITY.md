# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities by emailing:

**[johnsilver.dc1998@gmail.com](mailto:johnsilver.dc1998@gmail.com)**

Do not open public issues for security vulnerabilities.

You should receive a response within 48 hours. If the vulnerability is confirmed, we will release a fix as soon as possible.

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (main) | yes |

## Scope

Security-sensitive areas include:

- TLS handshake handling (REALITY, AnyTLS)
- Authentication bypass (UUID validation, password auth, ECDH)
- Traffic analysis resistance (XTLS Vision padding)
- Post-quantum key exchange (ML-KEM-512)
- Memory safety (unsafe code, buffer handling)
- Denial of service (connection exhaustion, resource leaks)
