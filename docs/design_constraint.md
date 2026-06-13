# Proxy Endpoint Configuration Model

**Status:** Design Constraint Specification  
**Version:** 1.0  
**Audience:** architects, schema designers, UI designers, adapter authors, and reviewers  
**Purpose:** define a precise, comprehensible, and implementable model for configuring proxy and tunnel endpoints without exposing redundant or misleading protocol-stack choices.

---

## 1. Purpose

This document defines the canonical configuration model for proxy and tunnel endpoints.

The model MUST satisfy two goals simultaneously:

1. preserve an accurate representation of the effective protocol stack; and

2. expose only meaningful user choices as configuration options.

A theoretically complete network-layer diagram is not automatically a good configuration interface. In particular, the base carrier is often fixed by the selected protocol or by an optional transport method. Requiring users to select it again introduces redundancy and can permit impossible combinations.

The configuration model therefore separates:

- **user-configurable fields**, which represent actual decisions;

- **conditional fields**, which appear only when supported and relevant; and

- **derived fields**, which are resolved automatically and shown for explanation, diagnostics, and export.

---

## 2. Requirements Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as normative requirement levels.

---

## 3. Scope

This document applies to endpoint configuration for proxy and tunnel protocols, including implementations that support combinations such as:

- a proxy protocol over a selectable transport method;

- a proxy protocol with built-in cryptography;

- a proxy protocol with an optional outer security layer;

- a protocol with a fixed carrier such as QUIC over UDP;

- optional traffic camouflage, ingress sharing, performance tuning, or low-level socket behavior.

This document defines a semantic model. It does not require every backend engine to expose identical native fields. Backend-specific adapters MAY map the semantic model to engine-specific configuration formats.

This document does not define a threat model, recommend specific protocols, or rank circumvention techniques.

---

## 4. Core Design Principle

### 4.1 Conceptual stack and configuration form are different artifacts

A conceptual stack MAY contain all of the following layers:

```text
proxied payload
    -> proxy or tunnel protocol
    -> optional transport method
    -> optional outer transport security
    -> resolved base carrier
```

Cross-cutting optional components MAY additionally affect camouflage, ingress handling, performance, or low-level network behavior.

The user-facing configuration MUST NOT mirror this diagram mechanically. A field SHOULD be exposed only when the user can make a meaningful choice.

### 4.2 Base carrier is normally derived

The base carrier describes the lowest transport used between peers, such as TCP, UDP, or another implementation-defined carrier.

`base_carrier` MUST be treated as a derived field by default.

It MUST NOT appear as a mandatory top-level user choice when its value is already determined by the selected protocol, transport method, or backend implementation.

Examples:

```text
VLESS -> WebSocket -> TLS -> TCP
Hysteria2 -> QUIC with TLS -> UDP
```

In the first example, TCP is implied by the WebSocket and TLS stack. In the second example, QUIC and UDP are intrinsic to the selected protocol profile. Asking the user to select TCP or UDP again would be redundant or incorrect.

### 4.3 Avoid the ambiguous term `network`

A generic field named `network` MUST NOT be used in the normalized schema.

Existing implementations often use `network: tcp|udp` to describe the kinds of proxied payload traffic that are enabled. This is not the same thing as the endpoint's base carrier.

The normalized model MUST use explicit names:

- `payload_networks` for traffic accepted or forwarded through the proxy; and

- `base_carrier` for the derived peer-to-peer carrier.

---

## 5. Canonical Terminology

### 5.1 Proxy or tunnel protocol

The **proxy or tunnel protocol** defines the primary peer-to-peer semantics of an endpoint. It commonly determines authentication, session establishment, framing, address representation, and relay behavior.

Examples include VLESS, Shadowsocks 2022, Trojan, Hysteria2, TUIC, and WireGuard.

Canonical key:

```text
protocol
```

### 5.2 Payload networks

**Payload networks** are the types of traffic carried on behalf of the user or application.

Typical values are:

```text
tcp
udp
ip
```

The supported values MUST be registry-driven because not every protocol exposes the same payload semantics.

Canonical key:

```text
payload_networks
```

This field MUST NOT be interpreted as the base carrier.

### 5.3 Transport method

A **transport method** is an optional peer-to-peer carrying or encapsulation method applied below the proxy protocol.

Typical examples include:

```text
raw
websocket
grpc
xhttp
httpupgrade
```

A transport method MAY be selectable, fixed, unavailable, or backend-specific.

Canonical key:

```text
transport
```

`raw` means that no additional carrying layer is applied beyond the proxy protocol's direct stream or datagram representation. It does not mean that the user must manually select TCP.

### 5.4 Protocol-internal cryptography

**Protocol-internal cryptography** is cryptographic protection defined as part of the protocol itself. It is not an optional outer wrapper.

Examples include the AEAD protection defined by Shadowsocks 2022 and the cryptographic construction intrinsic to WireGuard.

Canonical derived key:

```text
protocol_internal_security
```

This information SHOULD normally be shown as read-only metadata or protocol-specific configuration. It MUST NOT be conflated with `outer_security`.

### 5.5 Outer transport security

**Outer transport security** is a security mechanism applied around the peer transport stack or exposed as a distinct transport-security profile.

Typical examples include:

```text
none
tls
reality
```

Canonical key:

```text
outer_security
```

The precise placement of a mechanism MAY depend on the underlying protocol. For example, QUIC incorporates a TLS handshake rather than behaving exactly like an arbitrary application protocol wrapped by a standalone TLS layer. A resolver MUST produce an accurate human-readable stack description instead of forcing every protocol into an identical visual pattern.

### 5.6 Camouflage and obfuscation

**Camouflage** or **obfuscation** components primarily alter externally observable traffic characteristics or server behavior.

Examples MAY include packet-shape obfuscation, ordinary-service masquerading, padding, or active-probe resistance mechanisms.

Canonical namespace:

```text
components.camouflage
```

A camouflage component MUST NOT automatically be described as encryption. A component MAY provide camouflage without providing confidentiality or integrity.

### 5.7 Ingress-sharing and deployment components

**Ingress-sharing** components control how the proxy endpoint coexists with ordinary services or intermediaries.

Examples MAY include fallback routing, reverse-proxy integration, CDN-facing deployment, port sharing, and service dispatch rules.

Canonical namespace:

```text
components.ingress
```

Ingress sharing MUST NOT be conflated with camouflage. A reverse proxy can change deployment topology without changing cryptographic protection or traffic shape.

### 5.8 Performance components

**Performance components** alter throughput, latency, multiplexing, congestion control, relay strategy, or packet handling.

Examples MAY include multiplexing, congestion-control profiles, UDP relay modes, and packet encodings.

Canonical namespace:

```text
components.performance
```

Performance components MUST NOT be placed under camouflage merely because they alter wire behavior.

### 5.9 Low-level network components

**Low-level network components** alter socket behavior, interface binding, routing marks, TCP options, UDP options, or operating-system-specific behavior.

Canonical namespace:

```text
components.network
```

### 5.10 Resolved stack

The **resolved stack** is a derived representation of the effective endpoint stack after defaults, fixed protocol properties, selected options, and backend mappings have been applied.

Canonical key:

```text
resolved_stack
```

The resolved stack is informational but REQUIRED. It enables diagnostics, review, import/export inspection, and reproducible testing.

---

## 6. Normalized Configuration Shape

The canonical normalized representation SHOULD use the following structure:

```yaml
endpoint:
  protocol:
    type: <protocol-id>
    options: {}

  payload_networks:
    - <payload-network-id>

  transport:
    type: <transport-id>
    options: {}

  outer_security:
    type: <security-profile-id>
    options: {}

  components:
    camouflage: []
    ingress: []
    performance: []
    network: []

  extensions: {}
```

Only `endpoint.protocol.type` is universally required.

All other user-facing fields are conditional:

- `payload_networks` MAY be omitted when protocol defaults apply;

- `transport` MUST be omitted when transport is fixed or unavailable;

- `outer_security` MAY be omitted when disabled by default, but MUST be supplied when required and not safely defaultable;

- each `components` subsection MAY be omitted when empty;

- `extensions` MAY carry backend-specific options that do not yet have a normalized semantic representation.

The normalized schema MUST NOT require users to configure `base_carrier`.

---

## 7. Derived Representation

Every normalized endpoint MUST resolve to a derived representation similar to the following:

```yaml
resolved:
  protocol: vless
  payload_networks:
    - tcp
    - udp
  protocol_internal_security: null
  transport:
    type: websocket
  outer_security:
    type: tls
  base_carrier:
    - tcp
  active_components:
    camouflage: []
    ingress: []
    performance: []
    network: []
  stack_summary: "Payload TCP/UDP -> VLESS -> WebSocket -> TLS -> TCP"
```

The derived representation MUST:

1. include defaults applied by the system;

2. include fixed protocol properties;

3. distinguish built-in cryptography from outer security;

4. disclose the resolved base carrier;

5. identify active optional components by category;

6. generate a readable stack summary;

7. preserve enough information for deterministic validation and diagnostics.

---

## 8. Capability Registry

### 8.1 Registry requirement

Protocol capabilities MUST be declared in a machine-readable registry. UI code MUST NOT hard-code protocol-specific branching logic in scattered components.

Each supported protocol MUST have a descriptor.

### 8.2 Protocol descriptor

A protocol descriptor SHOULD contain:

```yaml
protocols:
  <protocol-id>:
    display_name: <human-readable-name>

    payload_networks:
      supported: []
      default: []
      user_configurable: <true|false>

    transport:
      mode: <selectable|fixed|forbidden|backend-defined>
      supported: []
      default: <transport-id|null>
      fixed_value: <transport-id|null>

    outer_security:
      mode: <selectable|required|optional|fixed|forbidden|backend-defined>
      supported: []
      default: <security-profile-id|null>
      fixed_value: <security-profile-id|null>

    protocol_internal_security:
      present: <true|false>
      description: <string|null>

    components:
      camouflage: []
      ingress: []
      performance: []
      network: []

    compatibility_rules: []
    resolver: <resolver-id>
    adapter: <adapter-id>
```

### 8.3 Layer modes

The following layer modes have normative meanings:

| Mode              | Meaning                                             | UI behavior                                                       |
| ----------------- | --------------------------------------------------- | ----------------------------------------------------------------- |
| `selectable`      | The user can choose among supported values.         | Show a selector.                                                  |
| `required`        | A value must be present.                            | Show a required selector or required form.                        |
| `optional`        | The user may enable and configure the layer.        | Show an optional control.                                         |
| `fixed`           | The protocol determines the value.                  | Hide the selector; show read-only resolved metadata.              |
| `forbidden`       | The layer is not valid for this protocol profile.   | Hide the control and reject imported values.                      |
| `backend-defined` | The backend adapter determines the effective value. | Hide by default; show resolved metadata and advanced diagnostics. |

### 8.4 Registry examples

The following examples illustrate the intended model. They are not an exhaustive protocol database.

```yaml
protocols:
  vless:
    payload_networks:
      supported: [tcp, udp]
      default: [tcp, udp]
      user_configurable: true
    transport:
      mode: selectable
      supported: [raw, websocket, grpc, xhttp]
      default: raw
    outer_security:
      mode: selectable
      supported: [none, tls, reality]
      default: none
    protocol_internal_security:
      present: false
    resolver: vless-stack

  hysteria2:
    payload_networks:
      supported: [tcp, udp]
      default: [tcp, udp]
      user_configurable: true
    transport:
      mode: fixed
      fixed_value: quic
    outer_security:
      mode: required
      supported: [tls]
      fixed_value: tls
    protocol_internal_security:
      present: false
    resolver: hysteria2-stack

  shadowsocks-2022:
    payload_networks:
      supported: [tcp, udp]
      default: [tcp, udp]
      user_configurable: true
    transport:
      mode: backend-defined
    outer_security:
      mode: backend-defined
    protocol_internal_security:
      present: true
      description: "AEAD protection defined by the protocol"
    resolver: shadowsocks-2022-stack
```

A backend adapter MAY expose a protocol in more than one profile when the backend supports materially different compositions. For example, an implementation may expose a Hysteria-related mechanism either as an independent proxy protocol or as a selectable carrying method beneath another proxy protocol. The registry MUST represent those profiles distinctly rather than forcing them into one ambiguous entry.

---

## 9. User Interface Rules

### 9.1 Default form

The default UI SHOULD show a compact form:

```text
Protocol
Payload networks          only when configurable
Transport                 only when selectable
Security                  only when optional, selectable, or required
Optional components       grouped by purpose
Resolved stack            always visible as read-only metadata
```

### 9.2 Dynamic exposure

The form MUST update after the protocol selection changes.

Examples:

- selecting VLESS MAY reveal a transport selector and an outer-security selector;

- selecting Hysteria2 SHOULD hide the transport selector because QUIC is fixed;

- selecting a protocol with built-in AEAD SHOULD show that fact as protocol metadata rather than as an optional TLS-like selector;

- enabling an ingress-sharing component SHOULD reveal only its own deployment fields.

### 9.3 Advanced view

An advanced view MAY expose:

- the resolved base carrier;

- defaults inserted by the system;

- backend-native field mappings;

- adapter warnings;

- compatibility constraints;

- low-level socket and network options.

The advanced view MUST distinguish editable fields from read-only derived fields.

### 9.4 Naming in user interfaces

User-facing labels SHOULD use:

| Canonical key            | Recommended label              |
| ------------------------ | ------------------------------ |
| `protocol`               | Protocol                       |
| `payload_networks`       | Proxied traffic types          |
| `transport`              | Transport method               |
| `outer_security`         | Transport security             |
| `components.camouflage`  | Camouflage and obfuscation     |
| `components.ingress`     | Ingress sharing and deployment |
| `components.performance` | Performance tuning             |
| `components.network`     | Advanced network settings      |
| `resolved_stack`         | Effective protocol stack       |
| `base_carrier`           | Resolved base carrier          |

The label `Encryption` SHOULD NOT be used as a replacement for `Transport security`, because it obscures the distinction between built-in cryptography, authentication, integrity protection, and optional outer wrappers.

---

## 10. Validation Rules

Validation MUST be deterministic and layered.

### 10.1 Schema validation

The validator MUST reject malformed values, unknown required fields, invalid enum values, and structurally invalid component options.

### 10.2 Capability validation

The validator MUST reject values not allowed by the selected protocol descriptor.

Examples:

- a transport value MUST be rejected when the protocol marks transport as `forbidden` or `fixed`;

- an unsupported outer-security profile MUST be rejected;

- unsupported payload networks MUST be rejected;

- unsupported optional components MUST be rejected.

### 10.3 Cross-field validation

The validator MUST evaluate compatibility rules across layers.

Examples:

- a security profile MAY support only a subset of transport methods;

- two optional components MAY conflict;

- a flow-control option MAY require a particular security profile;

- a port-hopping option MAY conflict with a fixed single-port deployment mode.

### 10.4 Peer compatibility validation

When a field requires peer agreement, the validator SHOULD mark it as peer-sensitive.

A UI SHOULD communicate that both sides normally require compatible values for peer-negotiated transport methods and related settings.

### 10.5 Adapter validation

Before export, the backend adapter MUST verify that the normalized configuration can be represented faithfully in the target engine.

When exact representation is impossible, the adapter MUST fail with an actionable error. It MUST NOT silently discard security-relevant or connectivity-relevant options.

### 10.6 Derived-stack validation

Every valid endpoint MUST produce a resolved stack. Failure to resolve the stack MUST be treated as a configuration error.

---

## 11. Example Configurations

### 11.1 Selectable transport and outer security

Normalized configuration:

```yaml
endpoint:
  protocol:
    type: vless
    options:
      uuid: "<redacted>"
  payload_networks: [tcp, udp]
  transport:
    type: websocket
    options:
      path: /api
  outer_security:
    type: tls
    options:
      server_name: example.com
```

Resolved summary:

```text
Payload TCP/UDP -> VLESS -> WebSocket -> TLS -> TCP
```

The user selects the transport and outer security. The base carrier is derived.

### 11.2 Direct transport profile

Normalized configuration:

```yaml
endpoint:
  protocol:
    type: vless
    options:
      uuid: "<redacted>"
  transport:
    type: raw
  outer_security:
    type: reality
    options: {}
```

Resolved summary:

```text
Payload TCP/UDP -> VLESS -> RAW -> REALITY -> resolved carrier
```

The resolver determines the final carrier according to the selected protocol profile, flow, and backend rules. `raw` does not require a redundant carrier selector.

### 11.3 Protocol with fixed QUIC carrier

Normalized configuration:

```yaml
endpoint:
  protocol:
    type: hysteria2
    options:
      password: "<redacted>"
  payload_networks: [tcp, udp]
  outer_security:
    type: tls
    options:
      server_name: example.com
  components:
    camouflage:
      - type: salamander
        options:
          password: "<redacted>"
```

Resolved summary:

```text
Payload TCP/UDP -> Hysteria2 -> QUIC with TLS -> UDP
Camouflage: salamander
```

The UI MUST NOT ask the user to select QUIC or UDP again.

### 11.4 Protocol with built-in cryptography

Normalized configuration:

```yaml
endpoint:
  protocol:
    type: shadowsocks-2022
    options:
      method: 2022-blake3-aes-128-gcm
      key: "<redacted>"
  payload_networks: [tcp, udp]
```

Resolved summary:

```text
Payload TCP/UDP -> Shadowsocks 2022 with built-in AEAD -> resolved carrier
```

The built-in AEAD mechanism MUST be shown as protocol-internal security. It MUST NOT be presented as an optional outer TLS-like wrapper.

---

## 12. Import and Export Rules

### 12.1 Import

An importer MUST:

1. parse the backend-native format;

2. map known fields to the normalized semantic model;

3. retain backend-specific values under `extensions` when safe and necessary;

4. resolve the effective stack;

5. report ambiguous or lossy mappings;

6. avoid guessing when two interpretations would materially differ.

### 12.2 Export

An exporter MUST:

1. validate the normalized model;

2. apply defaults explicitly or according to adapter policy;

3. map semantic fields to backend-native fields;

4. preserve required backend-specific extensions;

5. fail on unsupported combinations;

6. emit a resolved-stack report for diagnostics.

### 12.3 Round-trip behavior

Import followed by export SHOULD preserve the effective behavior of the endpoint.

A round trip MAY normalize formatting and defaults, but MUST NOT silently alter connectivity, authentication, security, or peer negotiation semantics.

---

## 13. Extension Rules

A new protocol, transport method, security profile, or component MUST NOT be added by inserting ad hoc UI logic alone.

Each extension MUST provide:

1. a stable identifier;

2. a human-readable name;

3. a machine-readable descriptor;

4. supported and default payload networks;

5. layer mode declarations;

6. compatibility rules;

7. a stack resolver;

8. a backend adapter or adapter capability declaration;

9. validation tests;

10. at least one resolved-stack example.

New optional features MUST be categorized by their primary purpose:

- confidentiality, integrity, or transport authentication -> `outer_security`;

- protocol-defined cryptography -> `protocol_internal_security`;

- observable traffic disguise or probe resistance -> `components.camouflage`;

- service coexistence or entry routing -> `components.ingress`;

- throughput, latency, relay behavior, or congestion behavior -> `components.performance`;

- socket, interface, routing, or operating-system behavior -> `components.network`.

When a feature has multiple effects, the primary category MUST reflect its main operational role. Secondary effects SHOULD be documented as metadata rather than used to duplicate the feature across categories.

---

## 14. Anti-Patterns

The following designs are prohibited or strongly discouraged.

### 14.1 Mandatory protocol plus mandatory base carrier

Bad:

```yaml
protocol: hysteria2
base_transport: udp
```

Reason: UDP is already implied. The second field adds no valid user decision.

### 14.2 Ambiguous `network` key

Bad:

```yaml
network: tcp
```

Reason: the reader cannot determine whether this means payload support, peer carrier, or transport method.

Use:

```yaml
payload_networks: [tcp]
```

### 14.3 Conflating built-in and outer cryptography

Bad:

```yaml
encryption: tls
```

Reason: this fails to distinguish protocol-internal AEAD from an outer transport-security profile.

Use distinct fields and derived metadata.

### 14.4 Putting all wire-affecting options under camouflage

Bad:

```yaml
camouflage:
  multiplex: true
```

Reason: multiplexing is primarily a performance and session-management feature.

### 14.5 Inferring security from the port number

Bad assumption:

```text
port 443 means TLS
```

Reason: a service port is deployment metadata, not proof of a negotiated security profile.

### 14.6 Hiding derived behavior completely

Bad design:

```text
Protocol: Hysteria2
```

with no resolved explanation.

Reason: simplification must not eliminate inspectability. The UI SHOULD still show:

```text
Effective protocol stack: Hysteria2 -> QUIC with TLS -> UDP
```

---

## 15. Implementation Sequence

An implementation SHOULD proceed in the following order:

1. define normalized schema types;

2. implement the capability registry;

3. implement protocol and transport descriptors;

4. implement stack resolvers;

5. implement layered validation;

6. implement backend adapters;

7. implement dynamic UI rendering from descriptors;

8. implement import/export round-trip tests;

9. implement resolved-stack snapshots;

10. add extension registration tests.

UI logic SHOULD consume registry metadata. It SHOULD NOT become the primary source of protocol capability truth.

---

## 16. Acceptance Checklist

A design conforms to this specification only if all of the following are true:

- `protocol` is the only universally required layer-selection field.

- `payload_networks` is distinct from the peer-to-peer carrier.

- the normalized schema does not use an ambiguous top-level `network` field.

- `transport` is exposed only when selectable or meaningfully configurable.

- `base_carrier` is derived by default.

- built-in cryptography is distinct from outer transport security.

- camouflage, ingress sharing, performance, and low-level network options are categorized separately.

- every valid endpoint produces a resolved stack.

- dynamic forms are driven by a capability registry.

- unsupported combinations are rejected before export.

- peer-sensitive options are identified.

- import/export adapters report lossy or ambiguous mappings.

- protocol extensions include descriptors, validators, resolvers, adapters, and tests.

---

## 17. Informative Source Basis

This model is intentionally implementation-neutral, but its terminology is aligned with patterns visible in current protocol implementations and documentation, including:

- Project X / Xray transport configuration: transport methods, transport security, and additional low-level configuration;

- Project X / Xray RAW transport documentation: RAW as a renamed direct transport method rather than an ambiguous “TCP transport” label;

- sing-box VLESS configuration: separate fields for enabled payload networks, TLS configuration, and V2Ray transport configuration;

- sing-box Hysteria2 configuration: required TLS settings, QUIC-related fields, and optional traffic obfuscation;

- Shadowsocks SIP022: protocol-internal AEAD protection in Shadowsocks 2022;

- BCP 14 requirement-level terminology as defined by RFC 2119 and RFC 8174.

These sources inform examples and terminology. The capability registry remains the authoritative source for the concrete set of features supported by a particular implementation version.
