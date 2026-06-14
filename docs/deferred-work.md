# Deferred Work

Features that are intentionally out of scope for the current implementation
of an otherwise landed feature. Each entry records the *what*, the *why it
was deferred*, and what would unblock it later.

Treat this as a working ledger: once an item is implemented, remove it from
this file and update [protocol-hierarchy-status.md](./protocol-hierarchy-status.md)
to reflect the new state.

## Naive inbound

### RST_STREAM obfuscation

- **Status:** deferred.
- **What:** the reference naive client/server, on top of the padded
  CONNECT scheme, also prepends a fake `END_STREAM` DATA frame with a
  random length in `[48, 72]` before any HTTP/2 `RST_STREAM` frame. This
  is intended to keep long-lived sessions from showing a distinctive
  burst of RSTs to a passive observer.
- **Why deferred:** the `h2` crate the v1 server is built on is a
  high-level HTTP/2 implementation. It does not expose a path for the
  application to inject a raw `DATA` frame ahead of a `RST_STREAM` that
  the library itself emits. Replicating the obfuscation cleanly would
  require either (a) a fork of `h2`, (b) a hand-rolled HTTP/2 framer
  beneath `rustls`, or (c) a translation layer that intercepts outgoing
  frames. All three are larger than the rest of v1 combined.
- **Tradeoff while deferred:** sessions with many resets become slightly
  more fingerprintable than the reference implementation. Per the
  project's `GFW remote-only failures are acceptable` standing rule,
  this is a posture choice rather than a correctness defect.
- **Future unblock:** a raw HTTP/2 framer would also unlock other
  protocols that currently lean on `h2`'s defaults (e.g. xhttp's
  fingerprint shaping). The fork option is the least invasive but still
  large; it has not been scoped.

### HTTP/3 (QUIC) variant

- **Status:** deferred.
- **What:** naive defines a parallel HTTP/3 variant of the same padded
  CONNECT scheme, riding QUIC instead of TLS+TCP+h2. It is the variant
  most commonly used in newer sing-box deployments.
- **Why deferred:** the existing QUIC server stack (Hysteria2, TUIC) is
  built directly on `quinn` with protocol-specific framing. There is no
  shared HTTP/3 server surface in the project today. Adding one would
  essentially be a parallel implementation of the naive server rather
  than a reuse of v1's `h2`-based path.
- **Future unblock:** would land naturally if/when an HTTP/3 transport
  is introduced for any other protocol (for example a hypothetical
  VLESS+HTTP/3 carrier), at which point the naive HTTP/3 variant can
  share that transport.

## WireGuard full routed mode

The `wireguard.outbound = true` mode routes both TCP and UDP destinations
through the gvisor stack. ICMP remains out of scope.

### ICMP outbound routing

- **Status:** deferred.
- **What:** allow ICMP echo (ping) from peers to terminate at the
  bridge and be issued from the host on behalf of the peer.
- **Why deferred:** ICMP from userspace generally requires a raw
  socket or a host-side ping helper, both of which are platform- and
  privilege-sensitive. It is not blocking for the headline routed-tunnel
  use case (TCP browsing through the WG peer).
- **Future unblock:** decide between a raw-socket helper and a
  privileged ping shim; only then wire an ICMP handler on the gvisor
  stack (the protocol numbers are already registered).
