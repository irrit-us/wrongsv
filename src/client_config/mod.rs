mod diagnostics;
mod profile;

pub(crate) use diagnostics::*;
pub(crate) use profile::*;

use serde::Serialize;

use crate::ClientFormat;
use crate::endpoint::{
    Component, ComponentDescriptorSet, EndpointComponents, LayerMode, OuterSecurity, ProxyProtocol,
    TransportMethod, protocol_descriptor, resolve_endpoint,
};

const WEBTRANSPORT_XRAY_EXPORT_DISABLED: &str =
    "WebTransport export is disabled pending an updated xray/v2ray-compatible client config shape";
const HIDDIFY_ANYTLS_PACKAGED_CORE_REASON: &str = "packaged Hiddify core rejected the generated AnyTLS outbound and never exposed the local mixed proxy port";

#[derive(Debug, Clone)]
pub(crate) struct ClientExportSupportError {
    pub code: &'static str,
    pub message: String,
}

impl ClientExportSupportError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn hiddify_anytls_export_disabled() -> String {
    format!(
        "Hiddify AnyTLS export is disabled: {}; use --format mihomo for FlClash or --format sing-box",
        HIDDIFY_ANYTLS_PACKAGED_CORE_REASON
    )
}

// ---------------------------------------------------------------------------
// Client config generation — outputs sing-box or mihomo JSON for connecting
// clients. Separated from CLI parsing so main.rs stays focused on server
// lifecycle.
// ---------------------------------------------------------------------------

pub(crate) fn generate_client_config(
    format: ClientFormat,
    server_host: &str,
    client_name: &str,
    vals: &ClientConfigValues,
) -> Result<String, String> {
    validate_client_format_support(format, vals).map_err(|error| error.message)?;
    Ok(match format {
        ClientFormat::Mihomo => mihomo_format(server_host, client_name, vals),
        ClientFormat::SingBox => singbox_format(server_host, client_name, vals),
        ClientFormat::Xray => xray_format(server_host, client_name, vals),
        ClientFormat::Hiddify => hiddify_format(server_host, client_name, vals),
    })
}

fn validate_client_format_support(
    format: ClientFormat,
    vals: &ClientConfigValues,
) -> Result<(), ClientExportSupportError> {
    let descriptor = protocol_descriptor(vals.protocol());
    let resolved = resolve_endpoint(&vals.endpoint);

    if descriptor.transport.mode == LayerMode::Forbidden && resolved.transport.is_some() {
        return Err(ClientExportSupportError::new(
            "transport_forbidden_in_endpoint_model",
            format!(
                "{} does not allow an explicit transport method in the normalized endpoint model",
                descriptor.display_name
            ),
        ));
    }
    if descriptor.outer_security.mode == LayerMode::Forbidden && resolved.outer_security.is_some() {
        return Err(ClientExportSupportError::new(
            "outer_security_forbidden_in_endpoint_model",
            format!(
                "{} does not allow outer transport security in the normalized endpoint model",
                descriptor.display_name
            ),
        ));
    }
    validate_component_support(
        descriptor.display_name,
        &resolved.active_components,
        descriptor.components,
    )?;

    match resolved.protocol {
        ProxyProtocol::Vless => {
            if matches!(
                resolved.transport,
                Some(TransportMethod::Meek | TransportMethod::GdocsViewer)
            ) && format != ClientFormat::Xray
            {
                return Err(ClientExportSupportError::new(
                    "transport_requires_xray_family",
                    format!(
                        "{:?} transport is only available through the Xray/V2Ray family adapters",
                        resolved.transport.unwrap()
                    ),
                ));
            }
            if resolved.transport == Some(TransportMethod::WebTransport) {
                return Err(ClientExportSupportError::new(
                    "webtransport_xray_family_export_disabled",
                    WEBTRANSPORT_XRAY_EXPORT_DISABLED,
                ));
            }
            if vals.has_component(Component::AnyTls) && matches!(format, ClientFormat::Hiddify) {
                return Err(ClientExportSupportError::new(
                    "hiddify_anytls_packaged_core_gap",
                    hiddify_anytls_export_disabled(),
                ));
            }
            if vals.has_component(Component::AnyTls)
                && !matches!(format, ClientFormat::Mihomo | ClientFormat::SingBox)
            {
                return Err(ClientExportSupportError::new(
                    "anytls_format_unsupported",
                    "AnyTLS export is only implemented for mihomo/FlClash and sing-box configs",
                ));
            }
        }
        ProxyProtocol::WireGuard => {
            if format == ClientFormat::Xray {
                return Err(ClientExportSupportError::new(
                    "wireguard_xray_export_unimplemented",
                    "WireGuard export is not implemented for xray format",
                ));
            }
        }
        ProxyProtocol::Vmess => {}
        ProxyProtocol::Shadowsocks | ProxyProtocol::Trojan => {}
        ProxyProtocol::Hysteria2 | ProxyProtocol::Tuic => {
            if matches!(format, ClientFormat::Xray) {
                return Err(ClientExportSupportError::new(
                    "xray_protocol_unsupported",
                    format!(
                        "{} export is not implemented for xray format (xray does not natively support {})",
                        descriptor.display_name,
                        match resolved.protocol {
                            ProxyProtocol::Hysteria2 => "hysteria2",
                            ProxyProtocol::Tuic => "tuic",
                            _ => "this protocol",
                        }
                    ),
                ));
            }
        }
        ProxyProtocol::Mixed | ProxyProtocol::Naive | ProxyProtocol::Snell => {
            return Err(ClientExportSupportError::new(
                "protocol_export_unimplemented",
                format!(
                    "{} export is not implemented for {} format",
                    descriptor.display_name,
                    match format {
                        ClientFormat::Mihomo => "mihomo",
                        ClientFormat::SingBox => "sing-box",
                        ClientFormat::Xray => "xray",
                        ClientFormat::Hiddify => "hiddify",
                    }
                ),
            ));
        }
    }
    Ok(())
}

fn validate_component_support(
    display_name: &str,
    active: &EndpointComponents,
    declared: ComponentDescriptorSet,
) -> Result<(), ClientExportSupportError> {
    validate_component_bucket(
        display_name,
        "camouflage",
        &active.camouflage,
        declared.camouflage,
    )?;
    validate_component_bucket(display_name, "ingress", &active.ingress, declared.ingress)?;
    validate_component_bucket(
        display_name,
        "performance",
        &active.performance,
        declared.performance,
    )?;
    validate_component_bucket(display_name, "network", &active.network, declared.network)?;
    Ok(())
}

fn validate_component_bucket(
    display_name: &str,
    bucket: &str,
    active: &[Component],
    supported: &[Component],
) -> Result<(), ClientExportSupportError> {
    for component in active {
        if !supported.contains(component) {
            return Err(ClientExportSupportError::new(
                "unsupported_endpoint_component",
                format!(
                    "{} does not declare {:?} as a supported {} component",
                    display_name, component, bucket
                ),
            ));
        }
    }
    Ok(())
}

impl ClientConfigValues {
    fn singbox_tls(&self) -> Option<SingBoxTls<'_>> {
        match self.outer_security() {
            Some(OuterSecurity::Reality) => Some(SingBoxTls {
                enabled: true,
                server_name: &self.servername,
                insecure: None,
                utls: Some(SingBoxUtls {
                    enabled: true,
                    fingerprint: "chrome",
                }),
                reality: Some(SingBoxReality {
                    enabled: true,
                    public_key: &self.x25519_pk,
                    short_id: &self.short_id,
                }),
            }),
            Some(OuterSecurity::Tls) => Some(SingBoxTls {
                enabled: true,
                server_name: &self.servername,
                insecure: Some(true),
                utls: Some(SingBoxUtls {
                    enabled: true,
                    fingerprint: "chrome",
                }),
                reality: None,
            }),
            None => None,
        }
    }
}

// ── mihomo / FlClash / v2rayN format ──────────────────────────────────────

#[derive(Serialize)]
struct MihomoConfig<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    proxy_type: &'a str,
    server: &'a str,
    port: u16,
    uuid: &'a str,
    encryption: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    flow: &'a str,
    udp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "client-fingerprint")]
    client_fingerprint: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    servername: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "skip-cert-verify")]
    skip_cert_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "reality-opts")]
    reality_opts: Option<RealityOpts<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ws-opts")]
    ws_opts: Option<WsOpts<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "grpc-opts")]
    grpc_opts: Option<GrpcOpts<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "mkcp-opts")]
    mkcp_opts: Option<MkcpOpts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "quic-opts")]
    quic_opts: Option<QuicOpts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "xhttp-opts")]
    xhttp_opts: Option<XhttpOpts<'a>>,
}

#[derive(Serialize)]
struct RealityOpts<'a> {
    #[serde(rename = "public-key")]
    public_key: &'a str,
    #[serde(rename = "short-id")]
    short_id: &'a str,
}

#[derive(Serialize)]
struct WsOpts<'a> {
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "v2ray-http-upgrade")]
    v2ray_http_upgrade: Option<bool>,
}

#[derive(Serialize)]
struct GrpcOpts<'a> {
    #[serde(rename = "grpc-service-name")]
    grpc_service_name: &'a str,
}

#[derive(Serialize)]
struct MkcpOpts {
    seed: String,
    mtu: u16,
    tti: u16,
}

#[derive(Serialize)]
struct QuicOpts {}

#[derive(Serialize)]
struct XhttpOpts<'a> {
    path: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    host: &'a str,
    mode: &'a str,
}

#[derive(Serialize)]
struct VmessMihomoConfig<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    proxy_type: &'a str,
    server: &'a str,
    port: u16,
    uuid: &'a str,
    cipher: &'a str,
    #[serde(rename = "alterId")]
    alter_id: u8,
    udp: bool,
}

#[derive(Serialize)]
struct WireGuardMihomoConfig<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    proxy_type: &'a str,
    server: &'a str,
    port: u16,
    ip: &'a str,
    #[serde(rename = "private-key")]
    private_key: &'a str,
    #[serde(rename = "public-key")]
    public_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "pre-shared-key")]
    pre_shared_key: Option<&'a str>,
    #[serde(rename = "allowed-ips")]
    allowed_ips: &'a [String],
    mtu: u32,
    udp: bool,
}

fn mihomo_format(server_host: &str, client_name: &str, vals: &ClientConfigValues) -> String {
    let port: u16 = vals.port.parse().unwrap_or(443);

    // VMess is a separate protocol type
    if vals.protocol() == ProxyProtocol::Vmess {
        let config = VmessMihomoConfig {
            name: client_name,
            proxy_type: "vmess",
            server: server_host,
            port,
            uuid: &vals.uuid,
            cipher: "auto",
            alter_id: 0,
            udp: true,
        };
        return serde_json::to_string_pretty(&config).expect("VmessMihomoConfig should serialize");
    }
    if vals.protocol() == ProxyProtocol::WireGuard {
        let config = WireGuardMihomoConfig {
            name: client_name,
            proxy_type: "wireguard",
            server: server_host,
            port,
            ip: &vals.wireguard_client_ip,
            private_key: &vals.wireguard_private_key,
            public_key: &vals.wireguard_public_key,
            pre_shared_key: vals.wireguard_preshared_key.as_deref(),
            allowed_ips: &vals.wireguard_allowed_ips,
            mtu: vals.wireguard_mtu,
            udp: true,
        };
        return serde_json::to_string_pretty(&config)
            .expect("WireGuardMihomoConfig should serialize");
    }
    if vals.protocol() == ProxyProtocol::Shadowsocks {
        let config = serde_json::json!({
            "name": client_name,
            "type": "ss",
            "server": server_host,
            "port": port,
            "cipher": vals.shadowsocks_method,
            "password": vals.shadowsocks_password,
            "udp": true,
        });
        return serde_json::to_string_pretty(&config).expect("ss mihomo config should serialize");
    }
    if vals.protocol() == ProxyProtocol::Trojan {
        let config = serde_json::json!({
            "name": client_name,
            "type": "trojan",
            "server": server_host,
            "port": port,
            "password": vals.trojan_password,
            "sni": vals.servername,
            "skip-cert-verify": true,
            "udp": true,
        });
        return serde_json::to_string_pretty(&config)
            .expect("trojan mihomo config should serialize");
    }
    if vals.protocol() == ProxyProtocol::Hysteria2 {
        let mut config = serde_json::json!({
            "name": client_name,
            "type": "hysteria2",
            "server": server_host,
            "port": port,
            "password": vals.hysteria2_password,
            "sni": vals.servername,
            "skip-cert-verify": true,
        });
        if let Some(up) = vals.hysteria2_up_mbps {
            config["up"] = serde_json::Value::from(up);
        }
        if let Some(down) = vals.hysteria2_down_mbps {
            config["down"] = serde_json::Value::from(down);
        }
        return serde_json::to_string_pretty(&config)
            .expect("hysteria2 mihomo config should serialize");
    }
    if vals.protocol() == ProxyProtocol::Tuic {
        let config = serde_json::json!({
            "name": client_name,
            "type": "tuic",
            "server": server_host,
            "port": port,
            "uuid": vals.tuic_uuid,
            "password": vals.tuic_password,
            "sni": vals.servername,
            "congestion-controller": vals.tuic_congestion,
            "udp-relay-mode": "native",
            "skip-cert-verify": true,
        });
        return serde_json::to_string_pretty(&config).expect("tuic mihomo config should serialize");
    }
    if vals.has_component(Component::AnyTls) {
        let config = serde_json::json!({
            "name": client_name,
            "type": "anytls",
            "server": server_host,
            "port": port,
            "password": vals.anytls_password,
            "sni": vals.servername,
            "client-fingerprint": "chrome",
            "skip-cert-verify": true,
            "udp": true,
        });
        return serde_json::to_string_pretty(&config)
            .expect("anytls mihomo config should serialize");
    }

    let (tls, client_fingerprint, servername, skip_cert_verify, reality_opts) =
        match vals.outer_security() {
            Some(OuterSecurity::Reality) => (
                Some(true),
                Some("chrome"),
                Some(vals.servername.as_str()),
                None,
                Some(RealityOpts {
                    public_key: &vals.x25519_pk,
                    short_id: &vals.short_id,
                }),
            ),
            Some(OuterSecurity::Tls) => (
                Some(true),
                Some("chrome"),
                Some(vals.servername.as_str()),
                Some(true),
                None,
            ),
            _ => (None, None, None, None, None),
        };

    // If a stream transport is used, TLS comes from the transport, not separately
    let (network, ws_opts, grpc_opts, mkcp_opts, quic_opts, xhttp_opts) = match vals
        .transport_method()
    {
        Some(TransportMethod::WebSocket) => (
            Some("ws"),
            Some(WsOpts {
                path: &vals.ws_path,
                v2ray_http_upgrade: None,
            }),
            None,
            None,
            None,
            None,
        ),
        Some(TransportMethod::HttpUpgrade) => (
            Some("ws"),
            Some(WsOpts {
                path: &vals.ws_path,
                v2ray_http_upgrade: Some(true),
            }),
            None,
            None,
            None,
            None,
        ),
        Some(TransportMethod::Grpc) => (
            Some("grpc"),
            None,
            Some(GrpcOpts {
                grpc_service_name: &vals.grpc_service_name,
            }),
            None,
            None,
            None,
        ),
        Some(TransportMethod::Kcp) => (
            Some("mkcp"),
            None,
            None,
            Some(MkcpOpts {
                seed: vals.kcp_seed.clone(),
                mtu: vals.kcp_mtu,
                tti: vals.kcp_tti,
            }),
            None,
            None,
        ),
        Some(TransportMethod::Quic) => (Some("quic"), None, None, None, Some(QuicOpts {}), None),
        Some(TransportMethod::WebTransport) => {
            (Some("quic"), None, None, None, Some(QuicOpts {}), None)
        }
        Some(TransportMethod::Xhttp) => (
            Some("xhttp"),
            None,
            None,
            None,
            None,
            Some(XhttpOpts {
                path: &vals.xhttp_path,
                host: &vals.xhttp_host,
                mode: "stream-one",
            }),
        ),
        _ => (None, None, None, None, None, None),
    };

    let config = MihomoConfig {
        name: client_name,
        proxy_type: "vless",
        server: server_host,
        port,
        uuid: &vals.uuid,
        encryption: "none",
        flow: &vals.flow,
        udp: true,
        tls,
        client_fingerprint,
        servername,
        skip_cert_verify,
        reality_opts,
        network,
        ws_opts,
        grpc_opts,
        mkcp_opts,
        quic_opts,
        xhttp_opts,
    };

    serde_json::to_string_pretty(&config).expect("MihomoConfig should serialize")
}

// ── sing-box format ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct SingBoxConfig {
    inbounds: Vec<SingBoxInbound>,
    outbounds: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct SingBoxInbound {
    #[serde(rename = "type")]
    inbound_type: String,
    tag: String,
    listen: String,
    listen_port: u16,
}

#[derive(Serialize)]
struct SingBoxVlessOutbound<'a> {
    #[serde(rename = "type")]
    outbound_type: &'a str,
    tag: &'a str,
    server: &'a str,
    server_port: u16,
    uuid: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    flow: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    packet_encoding: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detour: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<SingBoxTls<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct SingBoxTls<'a> {
    enabled: bool,
    server_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    insecure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    utls: Option<SingBoxUtls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reality: Option<SingBoxReality<'a>>,
}

#[derive(Serialize)]
struct SingBoxUtls {
    enabled: bool,
    fingerprint: &'static str,
}

#[derive(Serialize)]
struct SingBoxReality<'a> {
    enabled: bool,
    public_key: &'a str,
    short_id: &'a str,
}

#[derive(Serialize)]
struct SingBoxWsTransport<'a> {
    #[serde(rename = "type")]
    transport_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
}

#[derive(Serialize)]
struct SingBoxGrpcTransport<'a> {
    #[serde(rename = "type")]
    transport_type: &'a str,
    service_name: &'a str,
}

#[derive(Serialize)]
struct SingBoxHttpTransport<'a> {
    #[serde(rename = "type")]
    transport_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    host: Vec<&'a str>,
}

#[derive(Serialize)]
struct SingBoxWireGuardOutbound<'a> {
    #[serde(rename = "type")]
    outbound_type: &'a str,
    tag: &'a str,
    server: &'a str,
    server_port: u16,
    system_interface: bool,
    gso: bool,
    local_address: Vec<&'a str>,
    private_key: &'a str,
    peer_public_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_shared_key: Option<&'a str>,
    mtu: u32,
}

fn singbox_simple_outbound(
    server_host: &str,
    client_name: &str,
    port: u16,
    vals: &ClientConfigValues,
) -> serde_json::Value {
    match vals.protocol() {
        ProxyProtocol::Shadowsocks => serde_json::json!({
            "type": "shadowsocks",
            "tag": client_name,
            "server": server_host,
            "server_port": port,
            "method": vals.shadowsocks_method,
            "password": vals.shadowsocks_password,
        }),
        ProxyProtocol::Trojan => serde_json::json!({
            "type": "trojan",
            "tag": client_name,
            "server": server_host,
            "server_port": port,
            "password": vals.trojan_password,
            "tls": {
                "enabled": true,
                "server_name": vals.servername,
                "insecure": true,
            },
        }),
        ProxyProtocol::Hysteria2 => {
            let mut value = serde_json::json!({
                "type": "hysteria2",
                "tag": client_name,
                "server": server_host,
                "server_port": port,
                "password": vals.hysteria2_password,
                "tls": {
                    "enabled": true,
                    "server_name": vals.servername,
                    "insecure": true,
                    "alpn": ["h3"],
                },
            });
            if let Some(up) = vals.hysteria2_up_mbps {
                value["up_mbps"] = serde_json::Value::from(up);
            }
            if let Some(down) = vals.hysteria2_down_mbps {
                value["down_mbps"] = serde_json::Value::from(down);
            }
            value
        }
        ProxyProtocol::Tuic => serde_json::json!({
            "type": "tuic",
            "tag": client_name,
            "server": server_host,
            "server_port": port,
            "uuid": vals.tuic_uuid,
            "password": vals.tuic_password,
            "congestion_control": vals.tuic_congestion,
            "udp_relay_mode": "native",
            "tls": {
                "enabled": true,
                "server_name": vals.servername,
                "insecure": true,
                "alpn": ["h3"],
            },
        }),
        _ => unreachable!("singbox_simple_outbound only handles SS/Trojan/Hysteria2/TUIC"),
    }
}

fn singbox_anytls_outbound(
    server_host: &str,
    client_name: &str,
    port: u16,
    vals: &ClientConfigValues,
) -> serde_json::Value {
    serde_json::json!({
        "type": "anytls",
        "tag": client_name,
        "server": server_host,
        "server_port": port,
        "password": vals.anytls_password,
        "tls": {
            "enabled": true,
            "server_name": vals.servername,
            "insecure": true,
            "utls": {
                "enabled": true,
                "fingerprint": "chrome",
            },
        },
    })
}

fn singbox_format(server_host: &str, client_name: &str, vals: &ClientConfigValues) -> String {
    let port: u16 = vals.port.parse().unwrap_or(443);

    if vals.protocol() == ProxyProtocol::Vmess {
        let vmess_outbound = serde_json::json!({
            "type": "vmess",
            "tag": client_name,
            "server": server_host,
            "server_port": port,
            "uuid": vals.uuid,
            "security": "auto",
            "alter_id": 0,
        });
        let direct_outbound = serde_json::json!({"type": "direct", "tag": "direct"});
        let config = SingBoxConfig {
            inbounds: vec![SingBoxInbound {
                inbound_type: "mixed".into(),
                tag: "mixed-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: 10809,
            }],
            outbounds: vec![vmess_outbound, direct_outbound],
        };
        return serde_json::to_string_pretty(&config).expect("SingBoxConfig should serialize");
    }
    if vals.protocol() == ProxyProtocol::WireGuard {
        let wireguard_outbound = serde_json::to_value(SingBoxWireGuardOutbound {
            outbound_type: "wireguard",
            tag: client_name,
            server: server_host,
            server_port: port,
            system_interface: false,
            gso: false,
            local_address: vec![vals.wireguard_client_ip.as_str()],
            private_key: &vals.wireguard_private_key,
            peer_public_key: &vals.wireguard_public_key,
            pre_shared_key: vals.wireguard_preshared_key.as_deref(),
            mtu: vals.wireguard_mtu,
        })
        .expect("SingBoxWireGuardOutbound should serialize");
        let direct_outbound = serde_json::json!({"type": "direct", "tag": "direct"});
        let config = SingBoxConfig {
            inbounds: vec![SingBoxInbound {
                inbound_type: "mixed".into(),
                tag: "mixed-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: 10809,
            }],
            outbounds: vec![wireguard_outbound, direct_outbound],
        };
        return serde_json::to_string_pretty(&config).expect("SingBoxConfig should serialize");
    }
    if matches!(
        vals.protocol(),
        ProxyProtocol::Shadowsocks
            | ProxyProtocol::Trojan
            | ProxyProtocol::Hysteria2
            | ProxyProtocol::Tuic
    ) {
        let outbound = singbox_simple_outbound(server_host, client_name, port, vals);
        let direct_outbound = serde_json::json!({"type": "direct", "tag": "direct"});
        let config = SingBoxConfig {
            inbounds: vec![SingBoxInbound {
                inbound_type: "mixed".into(),
                tag: "mixed-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: 10809,
            }],
            outbounds: vec![outbound, direct_outbound],
        };
        return serde_json::to_string_pretty(&config).expect("SingBoxConfig should serialize");
    }
    if vals.has_component(Component::AnyTls) {
        let outbound = singbox_anytls_outbound(server_host, client_name, port, vals);
        let direct_outbound = serde_json::json!({"type": "direct", "tag": "direct"});
        let config = SingBoxConfig {
            inbounds: vec![SingBoxInbound {
                inbound_type: "mixed".into(),
                tag: "mixed-in".into(),
                listen: "127.0.0.1".into(),
                listen_port: 10809,
            }],
            outbounds: vec![outbound, direct_outbound],
        };
        return serde_json::to_string_pretty(&config).expect("SingBoxConfig should serialize");
    }

    let tls = vals.singbox_tls();

    let network = vals.enabled_payload_network_field();

    let packet_encoding = vals.udp_packet_encoding();

    let transport: Option<serde_json::Value> = match vals.transport_method() {
        Some(TransportMethod::WebSocket) => serde_json::to_value(SingBoxWsTransport {
            transport_type: "ws",
            path: Some(&vals.ws_path),
        })
        .ok(),
        Some(TransportMethod::HttpUpgrade) => serde_json::to_value(SingBoxWsTransport {
            transport_type: "httpupgrade",
            path: Some(&vals.ws_path),
        })
        .ok(),
        Some(TransportMethod::Grpc) => serde_json::to_value(SingBoxGrpcTransport {
            transport_type: "grpc",
            service_name: &vals.grpc_service_name,
        })
        .ok(),
        Some(TransportMethod::Quic) | Some(TransportMethod::WebTransport) => {
            serde_json::to_value(serde_json::json!({"type": "quic"})).ok()
        }
        Some(TransportMethod::Xhttp) => {
            let host = if vals.xhttp_host.is_empty() {
                vec![]
            } else {
                vec![vals.xhttp_host.as_str()]
            };
            serde_json::to_value(SingBoxHttpTransport {
                transport_type: "http",
                path: Some(&vals.xhttp_path),
                host,
            })
            .ok()
        }
        _ => None,
    };

    let shadowtls_detour = if vals.has_component(Component::ShadowTls) {
        Some(format!("{client_name}-shadowtls"))
    } else {
        None
    };

    let vless_outbound = serde_json::to_value(SingBoxVlessOutbound {
        outbound_type: "vless",
        tag: client_name,
        server: server_host,
        server_port: port,
        uuid: &vals.uuid,
        flow: &vals.flow,
        network,
        packet_encoding,
        detour: shadowtls_detour.as_deref(),
        tls: if vals.has_component(Component::ShadowTls) {
            None
        } else {
            tls
        },
        transport,
    })
    .expect("SingBoxVlessOutbound should serialize");

    let direct_outbound = serde_json::json!({"type": "direct", "tag": "direct"});
    let shadowtls_outbound = shadowtls_detour.as_ref().map(|tag| {
        serde_json::json!({
            "type": "shadowtls",
            "tag": tag,
            "server": server_host,
            "server_port": port,
            "version": 3,
            "password": vals.shadowtls_password,
            "tls": {
                "enabled": true,
                "server_name": vals.servername,
                "insecure": true
            }
        })
    });
    let mut outbounds = vec![vless_outbound];
    if let Some(shadowtls_outbound) = shadowtls_outbound {
        outbounds.push(shadowtls_outbound);
    }
    outbounds.push(direct_outbound);

    let config = SingBoxConfig {
        inbounds: vec![SingBoxInbound {
            inbound_type: "mixed".into(),
            tag: "mixed-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: 10809,
        }],
        outbounds,
    };

    serde_json::to_string_pretty(&config).expect("SingBoxConfig should serialize")
}

// ── Xray format ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct XrayConfig<'a> {
    outbounds: Vec<XrayOutbound<'a>>,
}

#[derive(Serialize)]
struct XrayOutbound<'a> {
    protocol: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    tag: &'a str,
    settings: XrayVlessSettings<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "streamSettings")]
    stream_settings: Option<XrayStreamSettings<'a>>,
}

#[derive(Serialize)]
struct XrayVlessSettings<'a> {
    vnext: Vec<XrayVnext<'a>>,
}

#[derive(Serialize)]
struct XrayVnext<'a> {
    address: &'a str,
    port: u16,
    users: Vec<XrayVlessUser<'a>>,
}

#[derive(Serialize)]
struct XrayVlessUser<'a> {
    id: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    flow: &'a str,
    encryption: &'a str,
}

#[derive(Serialize)]
struct XrayStreamSettings<'a> {
    network: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    security: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finalmask: Option<XrayFinalMask<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "realitySettings")]
    reality_settings: Option<XrayRealitySettings<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "tlsSettings")]
    tls_settings: Option<XrayTlsSettings<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "wsSettings")]
    ws_settings: Option<XrayWsSettings<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "grpcSettings")]
    grpc_settings: Option<XrayGrpcSettings<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "kcpSettings")]
    kcp_settings: Option<XrayKcpSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "quicSettings")]
    quic_settings: Option<XrayQuicSettings<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "httpupgradeSettings")]
    httpupgrade_settings: Option<XrayHttpUpgradeSettings<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "xhttpSettings")]
    xhttp_settings: Option<XrayXhttpSettings<'a>>,
}

#[derive(Serialize)]
struct XrayRealitySettings<'a> {
    #[serde(rename = "serverName")]
    server_name: &'a str,
    fingerprint: &'a str,
    #[serde(rename = "publicKey")]
    public_key: &'a str,
    #[serde(rename = "shortId")]
    short_id: &'a str,
}

#[derive(Serialize)]
struct XrayTlsSettings<'a> {
    #[serde(rename = "serverName")]
    server_name: &'a str,
    fingerprint: &'a str,
    #[serde(rename = "allowInsecure")]
    allow_insecure: bool,
}

#[derive(Serialize)]
struct XrayWsSettings<'a> {
    path: &'a str,
}

#[derive(Serialize)]
struct XrayGrpcSettings<'a> {
    #[serde(rename = "serviceName")]
    service_name: &'a str,
}

#[derive(Serialize)]
struct XrayKcpSettings {
    mtu: u16,
    tti: u16,
    #[serde(rename = "uplinkCapacity")]
    uplink_capacity: u16,
    #[serde(rename = "downlinkCapacity")]
    downlink_capacity: u16,
}

#[derive(Serialize)]
struct XrayFinalMask<'a> {
    udp: Vec<XrayFinalMaskEntry<'a>>,
}

#[derive(Serialize)]
struct XrayFinalMaskEntry<'a> {
    #[serde(rename = "type")]
    mask_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    settings: Option<XrayFinalMaskSettings<'a>>,
}

#[derive(Serialize)]
struct XrayFinalMaskSettings<'a> {
    password: &'a str,
}

#[derive(Serialize)]
struct XrayQuicSettings<'a> {
    security: &'a str,
    key: &'a str,
    header: XrayQuicHeader,
}

#[derive(Serialize)]
struct XrayQuicHeader {
    #[serde(rename = "type")]
    header_type: &'static str,
}

#[derive(Serialize)]
struct XrayHttpUpgradeSettings<'a> {
    path: &'a str,
}

#[derive(Serialize)]
struct XrayXhttpSettings<'a> {
    path: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    host: &'a str,
    mode: &'a str,
}

#[derive(Serialize)]
struct XrayVmessConfig<'a> {
    outbounds: Vec<XrayVmessOutbound<'a>>,
}

#[derive(Serialize)]
struct XrayVmessOutbound<'a> {
    protocol: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    tag: &'a str,
    settings: XrayVmessSettings<'a>,
}

#[derive(Serialize)]
struct XrayVmessSettings<'a> {
    vnext: Vec<XrayVmessVnext<'a>>,
}

#[derive(Serialize)]
struct XrayVmessVnext<'a> {
    address: &'a str,
    port: u16,
    users: Vec<XrayVmessUser<'a>>,
}

#[derive(Serialize)]
struct XrayVmessUser<'a> {
    id: &'a str,
    security: &'a str,
}

fn xray_format(server_host: &str, client_name: &str, vals: &ClientConfigValues) -> String {
    let port: u16 = vals.port.parse().unwrap_or(443);

    if vals.protocol() == ProxyProtocol::Vmess {
        let config = XrayVmessConfig {
            outbounds: vec![XrayVmessOutbound {
                protocol: "vmess",
                tag: client_name,
                settings: XrayVmessSettings {
                    vnext: vec![XrayVmessVnext {
                        address: server_host,
                        port,
                        users: vec![XrayVmessUser {
                            id: &vals.uuid,
                            security: "auto",
                        }],
                    }],
                },
            }],
        };
        return serde_json::to_string_pretty(&config).expect("XrayVmessConfig should serialize");
    }
    if vals.protocol() == ProxyProtocol::Shadowsocks {
        let config = serde_json::json!({
            "outbounds": [{
                "protocol": "shadowsocks",
                "tag": client_name,
                "settings": {
                    "servers": [{
                        "address": server_host,
                        "port": port,
                        "method": vals.shadowsocks_method,
                        "password": vals.shadowsocks_password,
                    }],
                },
            }],
        });
        return serde_json::to_string_pretty(&config).expect("ss xray config should serialize");
    }
    if vals.protocol() == ProxyProtocol::Trojan {
        let config = serde_json::json!({
            "outbounds": [{
                "protocol": "trojan",
                "tag": client_name,
                "settings": {
                    "servers": [{
                        "address": server_host,
                        "port": port,
                        "password": vals.trojan_password,
                    }],
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": vals.servername,
                        "fingerprint": "chrome",
                        "allowInsecure": true,
                    },
                },
            }],
        });
        return serde_json::to_string_pretty(&config).expect("trojan xray config should serialize");
    }

    // Network name mapping: wrongsv transport → Xray network string
    let xray_network: &str = match vals.transport_method() {
        Some(TransportMethod::WebSocket) => "ws",
        Some(TransportMethod::Grpc) => "grpc",
        Some(TransportMethod::HttpUpgrade) => "httpupgrade",
        Some(TransportMethod::Xhttp) => "xhttp",
        Some(TransportMethod::Quic) | Some(TransportMethod::WebTransport) => "quic",
        Some(TransportMethod::Kcp) => "mkcp",
        Some(TransportMethod::Meek)
        | Some(TransportMethod::GdocsViewer)
        | Some(TransportMethod::Raw)
        | Some(TransportMethod::H2Connect)
        | None => "tcp",
    };

    let security: Option<&str> = match vals.outer_security() {
        Some(OuterSecurity::Reality) => Some("reality"),
        Some(OuterSecurity::Tls) => Some("tls"),
        _ => None,
    };

    let reality_settings = match vals.outer_security() {
        Some(OuterSecurity::Reality) => Some(XrayRealitySettings {
            server_name: &vals.servername,
            fingerprint: "chrome",
            public_key: &vals.x25519_pk,
            short_id: &vals.short_id,
        }),
        _ => None,
    };

    let tls_settings = match vals.outer_security() {
        Some(OuterSecurity::Tls) => Some(XrayTlsSettings {
            server_name: &vals.servername,
            fingerprint: "chrome",
            allow_insecure: true,
        }),
        _ => None,
    };

    let ws_settings = match vals.transport_method() {
        Some(TransportMethod::WebSocket) => Some(XrayWsSettings {
            path: &vals.ws_path,
        }),
        _ => None,
    };

    let grpc_settings = match vals.transport_method() {
        Some(TransportMethod::Grpc) => Some(XrayGrpcSettings {
            service_name: &vals.grpc_service_name,
        }),
        _ => None,
    };

    let kcp_settings = match vals.transport_method() {
        Some(TransportMethod::Kcp) => Some(XrayKcpSettings {
            mtu: vals.kcp_mtu,
            tti: vals.kcp_tti,
            uplink_capacity: 5,
            downlink_capacity: 20,
        }),
        _ => None,
    };

    let finalmask = match vals.transport_method() {
        Some(TransportMethod::Kcp) => {
            let udp = if vals.kcp_seed.is_empty() {
                vec![XrayFinalMaskEntry {
                    mask_type: "mkcp-original",
                    settings: None,
                }]
            } else {
                vec![XrayFinalMaskEntry {
                    mask_type: "mkcp-aes128gcm",
                    settings: Some(XrayFinalMaskSettings {
                        password: &vals.kcp_seed,
                    }),
                }]
            };
            Some(XrayFinalMask { udp })
        }
        _ => None,
    };

    let quic_settings = match vals.transport_method() {
        Some(TransportMethod::Quic) | Some(TransportMethod::WebTransport) => {
            Some(XrayQuicSettings {
                security: "none",
                key: "",
                header: XrayQuicHeader {
                    header_type: "none",
                },
            })
        }
        _ => None,
    };

    let httpupgrade_settings = match vals.transport_method() {
        Some(TransportMethod::HttpUpgrade) => Some(XrayHttpUpgradeSettings {
            path: &vals.ws_path,
        }),
        _ => None,
    };

    let xhttp_settings = match vals.transport_method() {
        Some(TransportMethod::Xhttp) => Some(XrayXhttpSettings {
            path: &vals.xhttp_path,
            host: &vals.xhttp_host,
            mode: "stream-one",
        }),
        _ => None,
    };

    let stream_settings = XrayStreamSettings {
        network: xray_network,
        security,
        finalmask,
        reality_settings,
        tls_settings,
        ws_settings,
        grpc_settings,
        kcp_settings,
        quic_settings,
        httpupgrade_settings,
        xhttp_settings,
    };

    let config = XrayConfig {
        outbounds: vec![XrayOutbound {
            protocol: "vless",
            tag: client_name,
            settings: XrayVlessSettings {
                vnext: vec![XrayVnext {
                    address: server_host,
                    port,
                    users: vec![XrayVlessUser {
                        id: &vals.uuid,
                        flow: &vals.flow,
                        encryption: "none",
                    }],
                }],
            },
            stream_settings: Some(stream_settings),
        }],
    };

    serde_json::to_string_pretty(&config).expect("XrayConfig should serialize")
}

// ── Hiddify format ────────────────────────────────────────────────────────
// Hiddify-next uses sing-box as its core engine, so the outbound config is
// identical to sing-box format. We generate a Hiddify-compatible wrapper with
// metadata for subscription import.

#[derive(Serialize)]
struct HiddifyConfig {
    remarks: String,
    subscription: String,
    configs: Vec<serde_json::Value>,
}

fn hiddify_format(server_host: &str, client_name: &str, vals: &ClientConfigValues) -> String {
    let port: u16 = vals.port.parse().unwrap_or(443);

    if vals.protocol() == ProxyProtocol::Vmess {
        let vmess_outbound = serde_json::json!({
            "type": "vmess",
            "tag": client_name,
            "server": server_host,
            "server_port": port,
            "uuid": vals.uuid,
            "security": "auto",
            "alter_id": 0,
        });
        let direct_outbound = serde_json::json!({"type": "direct", "tag": "direct"});
        let config = HiddifyConfig {
            remarks: client_name.to_string(),
            subscription: String::new(),
            configs: vec![vmess_outbound, direct_outbound],
        };
        return serde_json::to_string_pretty(&config).expect("HiddifyConfig should serialize");
    }
    if vals.protocol() == ProxyProtocol::WireGuard {
        let wireguard_outbound = serde_json::to_value(SingBoxWireGuardOutbound {
            outbound_type: "wireguard",
            tag: client_name,
            server: server_host,
            server_port: port,
            system_interface: false,
            gso: false,
            local_address: vec![vals.wireguard_client_ip.as_str()],
            private_key: &vals.wireguard_private_key,
            peer_public_key: &vals.wireguard_public_key,
            pre_shared_key: vals.wireguard_preshared_key.as_deref(),
            mtu: vals.wireguard_mtu,
        })
        .expect("SingBoxWireGuardOutbound should serialize");
        let direct_outbound = serde_json::json!({"type": "direct", "tag": "direct"});
        let config = HiddifyConfig {
            remarks: client_name.to_string(),
            subscription: String::new(),
            configs: vec![wireguard_outbound, direct_outbound],
        };
        return serde_json::to_string_pretty(&config).expect("HiddifyConfig should serialize");
    }
    if matches!(
        vals.protocol(),
        ProxyProtocol::Shadowsocks
            | ProxyProtocol::Trojan
            | ProxyProtocol::Hysteria2
            | ProxyProtocol::Tuic
    ) {
        let outbound = singbox_simple_outbound(server_host, client_name, port, vals);
        let direct_outbound = serde_json::json!({"type": "direct", "tag": "direct"});
        let config = HiddifyConfig {
            remarks: client_name.to_string(),
            subscription: String::new(),
            configs: vec![outbound, direct_outbound],
        };
        return serde_json::to_string_pretty(&config).expect("HiddifyConfig should serialize");
    }
    if vals.has_component(Component::AnyTls) {
        let outbound = singbox_anytls_outbound(server_host, client_name, port, vals);
        let direct_outbound = serde_json::json!({"type": "direct", "tag": "direct"});
        let config = HiddifyConfig {
            remarks: client_name.to_string(),
            subscription: String::new(),
            configs: vec![outbound, direct_outbound],
        };
        return serde_json::to_string_pretty(&config).expect("HiddifyConfig should serialize");
    }

    if vals.transport_method() == Some(TransportMethod::Xhttp) {
        let xray_config: serde_json::Value =
            serde_json::from_str(&xray_format(server_host, client_name, vals))
                .expect("XrayConfig should parse as JSON");
        let xray_outbound = serde_json::json!({
            "type": "xray",
            "tag": client_name,
            "xconfig": {
                "outbounds": xray_config["outbounds"].clone()
            }
        });
        let direct_outbound = serde_json::json!({"type": "direct", "tag": "direct"});
        let config = HiddifyConfig {
            remarks: client_name.to_string(),
            subscription: String::new(),
            configs: vec![xray_outbound, direct_outbound],
        };
        return serde_json::to_string_pretty(&config).expect("HiddifyConfig should serialize");
    }

    let tls = vals.singbox_tls();

    let network = vals.enabled_payload_network_field();

    let packet_encoding = vals.udp_packet_encoding();

    let transport: Option<serde_json::Value> = match vals.transport_method() {
        Some(TransportMethod::WebSocket) => serde_json::to_value(SingBoxWsTransport {
            transport_type: "ws",
            path: Some(&vals.ws_path),
        })
        .ok(),
        Some(TransportMethod::HttpUpgrade) => serde_json::to_value(SingBoxWsTransport {
            transport_type: "httpupgrade",
            path: Some(&vals.ws_path),
        })
        .ok(),
        Some(TransportMethod::Grpc) => serde_json::to_value(SingBoxGrpcTransport {
            transport_type: "grpc",
            service_name: &vals.grpc_service_name,
        })
        .ok(),
        Some(TransportMethod::Quic) | Some(TransportMethod::WebTransport) => {
            serde_json::to_value(serde_json::json!({"type": "quic"})).ok()
        }
        Some(TransportMethod::Xhttp) => {
            let host = if vals.xhttp_host.is_empty() {
                vec![]
            } else {
                vec![vals.xhttp_host.as_str()]
            };
            serde_json::to_value(SingBoxHttpTransport {
                transport_type: "http",
                path: Some(&vals.xhttp_path),
                host,
            })
            .ok()
        }
        _ => None,
    };

    let shadowtls_detour = if vals.has_component(Component::ShadowTls) {
        Some(format!("{client_name}-shadowtls"))
    } else {
        None
    };

    let vless_outbound = serde_json::to_value(SingBoxVlessOutbound {
        outbound_type: "vless",
        tag: client_name,
        server: server_host,
        server_port: port,
        uuid: &vals.uuid,
        flow: &vals.flow,
        network,
        packet_encoding,
        detour: shadowtls_detour.as_deref(),
        tls: if vals.has_component(Component::ShadowTls) {
            None
        } else {
            tls
        },
        transport,
    })
    .expect("SingBoxVlessOutbound should serialize");

    let direct_outbound = serde_json::json!({"type": "direct", "tag": "direct"});
    let shadowtls_outbound = shadowtls_detour.as_ref().map(|tag| {
        serde_json::json!({
            "type": "shadowtls",
            "tag": tag,
            "server": server_host,
            "server_port": port,
            "version": 3,
            "password": vals.shadowtls_password,
            "tls": {
                "enabled": true,
                "server_name": vals.servername,
                "insecure": true
            }
        })
    });
    let mut configs = vec![vless_outbound];
    if let Some(shadowtls_outbound) = shadowtls_outbound {
        configs.push(shadowtls_outbound);
    }
    configs.push(direct_outbound);

    let config = HiddifyConfig {
        remarks: client_name.to_string(),
        subscription: String::new(),
        configs,
    };

    serde_json::to_string_pretty(&config).expect("HiddifyConfig should serialize")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Transport;
    use crate::endpoint::EndpointModel;
    use std::path::Path;

    fn test_vals(transport: Transport) -> ClientConfigValues {
        let outer_security = match transport {
            Transport::Reality => Some(OuterSecurity::Reality),
            Transport::AnyTls
            | Transport::Tls
            | Transport::Quic
            | Transport::WebTransport
            | Transport::ShadowTls => Some(OuterSecurity::Tls),
            Transport::Raw
            | Transport::WebSocket
            | Transport::HttpUpgrade
            | Transport::Grpc
            | Transport::Xhttp
            | Transport::Meek
            | Transport::GdocsViewer
            | Transport::Kcp
            | Transport::Vmess
            | Transport::Shadowsocks
            | Transport::Snell
            | Transport::Mixed
            | Transport::WireGuard => None,
            Transport::Trojan | Transport::Hysteria2 | Transport::Tuic | Transport::Naive => {
                Some(OuterSecurity::Tls)
            }
        };
        ClientConfigValues {
            endpoint: EndpointModel::from_profile(transport, outer_security, "xtls-rprx-vision"),
            uuid: "test-uuid-1234".into(),
            flow: "xtls-rprx-vision".into(),
            port: "443".into(),
            short_id: "abcd1234".into(),
            x25519_pk: "test-pubkey-base64".into(),
            servername: "example.com".into(),
            ws_path: "/ws-path".into(),
            grpc_service_name: "TestService".into(),
            kcp_seed: "test-seed".into(),
            kcp_mtu: 1350,
            kcp_tti: 50,
            xhttp_path: "/xhttp-path".into(),
            xhttp_host: "xhost.example.com".into(),
            shadowtls_password: "shadow-pass".into(),
            anytls_password: "anytls-pass".into(),
            wireguard_private_key: "wireguard-private-key".into(),
            wireguard_public_key: "wireguard-public-key".into(),
            wireguard_preshared_key: Some("wireguard-preshared-key".into()),
            wireguard_client_ip: "10.66.66.2/32".into(),
            wireguard_allowed_ips: vec!["10.66.66.1/32".into()],
            wireguard_mtu: 1400,
            shadowsocks_method: "2022-blake3-aes-128-gcm".into(),
            shadowsocks_password: "ss-test-password".into(),
            trojan_password: "trojan-test-password".into(),
            hysteria2_password: "hy2-test-password".into(),
            hysteria2_up_mbps: Some(50),
            hysteria2_down_mbps: Some(100),
            tuic_uuid: "12345678-1234-1234-1234-123456789abc".into(),
            tuic_password: "tuic-test-password".into(),
            tuic_congestion: "bbr".into(),
        }
    }

    fn fixture(path: &str) -> String {
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
            .unwrap_or_else(|err| panic!("failed to read fixture {path}: {err}"))
    }

    fn checked_in_config(path: &str) -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(path)
            .display()
            .to_string()
    }

    #[test]
    fn mihomo_reality_has_required_fields() {
        let json = mihomo_format("1.2.3.4", "test", &test_vals(Transport::Reality));
        assert!(json.contains(r#""name": "test""#));
        assert!(json.contains(r#""type": "vless""#));
        assert!(json.contains(r#""tls": true"#));
        assert!(json.contains(r#""reality-opts""#));
        assert!(json.contains(r#""public-key": "test-pubkey-base64""#));
        assert!(json.contains(r#""short-id": "abcd1234""#));
    }

    #[test]
    fn mihomo_ws_has_network_field() {
        let json = mihomo_format("1.2.3.4", "test", &test_vals(Transport::WebSocket));
        assert!(json.contains(r#""network": "ws""#));
        assert!(json.contains(r#""ws-opts""#));
        assert!(json.contains(r#""path": "/ws-path""#));
        // Raw ws should not have tls
        assert!(!json.contains(r#""tls": true"#));
    }

    #[test]
    fn mihomo_httpupgrade_has_v2ray_flag() {
        let json = mihomo_format("1.2.3.4", "test", &test_vals(Transport::HttpUpgrade));
        assert!(json.contains(r#""v2ray-http-upgrade": true"#));
    }

    #[test]
    fn singbox_reality_has_nested_tls() {
        let json = singbox_format("1.2.3.4", "test", &test_vals(Transport::Reality));
        assert!(json.contains(r#""type": "vless""#));
        assert!(json.contains(r#""reality""#));
        assert!(json.contains(r#""public_key": "test-pubkey-base64""#));
    }

    #[test]
    fn singbox_tls_has_insecure_flag() {
        let json = singbox_format("1.2.3.4", "test", &test_vals(Transport::Tls));
        assert!(json.contains(r#""insecure": true"#));
        assert!(!json.contains("reality"));
    }

    #[test]
    fn singbox_ws_has_transport_block() {
        let json = singbox_format("1.2.3.4", "test", &test_vals(Transport::WebSocket));
        assert!(json.contains(r#""type": "ws""#));
    }

    #[test]
    fn singbox_httpupgrade_uses_correct_transport_type() {
        let json = singbox_format("1.2.3.4", "test", &test_vals(Transport::HttpUpgrade));
        assert!(json.contains(r#""type": "httpupgrade""#));
    }

    #[test]
    fn singbox_direct_outbound_is_minimal() {
        let json = singbox_format("1.2.3.4", "test", &test_vals(Transport::Raw));
        // Direct outbound should only have type + tag
        assert!(json.contains(r#""type": "direct""#));
        assert!(json.contains(r#""tag": "direct""#));
        // Should NOT have server/uuid/flow in direct outbound
        let direct_pos = json.rfind(r#""type": "direct""#).unwrap();
        let after_direct = &json[direct_pos..];
        assert!(!after_direct.contains(r#""server":""#));
    }

    #[test]
    fn singbox_grpc_has_service_name() {
        let json = singbox_format("1.2.3.4", "test", &test_vals(Transport::Grpc));
        assert!(json.contains(r#""type": "grpc""#));
        assert!(json.contains(r#""service_name": "TestService""#));
    }

    #[test]
    fn singbox_quic_has_transport() {
        let json = singbox_format("1.2.3.4", "test", &test_vals(Transport::Quic));
        assert!(json.contains(r#""type": "quic""#));
    }

    #[test]
    fn singbox_shadowtls_uses_detour_outbound() {
        let json = singbox_format("1.2.3.4", "test", &test_vals(Transport::ShadowTls));
        assert!(json.contains(r#""type": "shadowtls""#));
        assert!(json.contains(r#""detour": "test-shadowtls""#));
        assert!(json.contains(r#""password": "shadow-pass""#));
    }

    #[test]
    fn mihomo_anytls_renders_anytls_proxy_entry() {
        let json = mihomo_format("1.2.3.4", "test", &test_vals(Transport::AnyTls));
        assert!(json.contains(r#""type": "anytls""#));
        assert!(json.contains(r#""password": "anytls-pass""#));
        assert!(json.contains(r#""sni": "example.com""#));
        assert!(json.contains(r#""client-fingerprint": "chrome""#));
        assert!(!json.contains(r#""type": "vless""#));
    }

    #[test]
    fn singbox_anytls_renders_anytls_outbound() {
        let json = singbox_format("1.2.3.4", "test", &test_vals(Transport::AnyTls));
        assert!(json.contains(r#""type": "anytls""#));
        assert!(json.contains(r#""password": "anytls-pass""#));
        assert!(json.contains(r#""server_name": "example.com""#));
        assert!(json.contains(r#""fingerprint": "chrome""#));
        assert!(!json.contains(r#""type": "vless""#));
    }

    #[test]
    fn singbox_has_packet_encoding() {
        let mut vals = test_vals(Transport::Raw);
        vals.flow.clear();
        vals.endpoint = EndpointModel::from_profile(Transport::Raw, None, "");
        let json = singbox_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""packet_encoding": "packetaddr""#));
    }

    #[test]
    fn singbox_omits_packet_encoding_when_udp_payload_is_disabled() {
        let json = singbox_format("1.2.3.4", "test", &test_vals(Transport::Reality));
        assert!(!json.contains(r#""packet_encoding": "packetaddr""#));
    }

    // ── Mihomo new transport tests ──────────────────────────────────────

    #[test]
    fn mihomo_grpc_has_grpc_opts() {
        let json = mihomo_format("1.2.3.4", "test", &test_vals(Transport::Grpc));
        assert!(json.contains(r#""network": "grpc""#));
        assert!(json.contains(r#""grpc-opts""#));
        assert!(json.contains(r#""grpc-service-name": "TestService""#));
    }

    #[test]
    fn mihomo_kcp_has_mkcp_opts() {
        let json = mihomo_format("1.2.3.4", "test", &test_vals(Transport::Kcp));
        assert!(json.contains(r#""network": "mkcp""#));
        assert!(json.contains(r#""mkcp-opts""#));
        assert!(json.contains(r#""seed": "test-seed""#));
        assert!(json.contains(r#""mtu": 1350"#));
        assert!(json.contains(r#""tti": 50"#));
    }

    #[test]
    fn mihomo_xhttp_has_xhttp_opts() {
        let json = mihomo_format("1.2.3.4", "test", &test_vals(Transport::Xhttp));
        assert!(json.contains(r#""network": "xhttp""#));
        assert!(json.contains(r#""xhttp-opts""#));
        assert!(json.contains(r#""path": "/xhttp-path""#));
        assert!(json.contains(r#""mode": "stream-one""#));
    }

    #[test]
    fn mihomo_wireguard_uses_normalized_protocol_model() {
        let mut vals = test_vals(Transport::WireGuard);
        vals.endpoint = EndpointModel::from_profile(Transport::WireGuard, None, "");
        let json = mihomo_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "wireguard""#));
        assert!(json.contains(r#""private-key": "wireguard-private-key""#));
        assert!(json.contains(r#""public-key": "wireguard-public-key""#));
        assert!(json.contains(r#""allowed-ips""#));
    }

    #[test]
    fn singbox_wireguard_uses_normalized_protocol_model() {
        let mut vals = test_vals(Transport::WireGuard);
        vals.endpoint = EndpointModel::from_profile(Transport::WireGuard, None, "");
        let json = singbox_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "wireguard""#));
        assert!(json.contains(r#""local_address""#));
        assert!(json.contains(r#""peer_public_key": "wireguard-public-key""#));
    }

    #[test]
    fn xray_wireguard_export_fails_cleanly() {
        let mut vals = test_vals(Transport::WireGuard);
        vals.endpoint = EndpointModel::from_profile(Transport::WireGuard, None, "");
        let err = generate_client_config(ClientFormat::Xray, "1.2.3.4", "test", &vals)
            .expect_err("wireguard xray export should fail");
        assert!(err.contains("WireGuard export is not implemented"));
    }

    #[test]
    fn xray_anytls_export_fails_cleanly() {
        let vals = test_vals(Transport::AnyTls);
        let err = generate_client_config(ClientFormat::Xray, "1.2.3.4", "test", &vals)
            .expect_err("anytls xray export should fail");
        assert!(err.contains("AnyTLS export"));
    }

    #[test]
    fn mihomo_shadowsocks_renders_ss_proxy_entry() {
        let mut vals = test_vals(Transport::Shadowsocks);
        vals.endpoint = EndpointModel::from_profile(Transport::Shadowsocks, None, "");
        let json = mihomo_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "ss""#));
        assert!(json.contains(r#""cipher": "2022-blake3-aes-128-gcm""#));
        assert!(json.contains(r#""password": "ss-test-password""#));
    }

    #[test]
    fn singbox_shadowsocks_renders_outbound() {
        let mut vals = test_vals(Transport::Shadowsocks);
        vals.endpoint = EndpointModel::from_profile(Transport::Shadowsocks, None, "");
        let json = singbox_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "shadowsocks""#));
        assert!(json.contains(r#""method": "2022-blake3-aes-128-gcm""#));
        assert!(json.contains(r#""password": "ss-test-password""#));
    }

    #[test]
    fn xray_shadowsocks_renders_outbound() {
        let mut vals = test_vals(Transport::Shadowsocks);
        vals.endpoint = EndpointModel::from_profile(Transport::Shadowsocks, None, "");
        let json = xray_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""protocol": "shadowsocks""#));
        assert!(json.contains(r#""method": "2022-blake3-aes-128-gcm""#));
        assert!(json.contains(r#""password": "ss-test-password""#));
    }

    #[test]
    fn hiddify_shadowsocks_wraps_singbox_outbound() {
        let mut vals = test_vals(Transport::Shadowsocks);
        vals.endpoint = EndpointModel::from_profile(Transport::Shadowsocks, None, "");
        let json = hiddify_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "shadowsocks""#));
        assert!(json.contains(r#""method": "2022-blake3-aes-128-gcm""#));
    }

    #[test]
    fn mihomo_trojan_renders_trojan_proxy_entry() {
        let mut vals = test_vals(Transport::Trojan);
        vals.endpoint =
            EndpointModel::from_profile(Transport::Trojan, Some(OuterSecurity::Tls), "");
        let json = mihomo_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "trojan""#));
        assert!(json.contains(r#""password": "trojan-test-password""#));
        assert!(json.contains(r#""sni": "example.com""#));
    }

    #[test]
    fn singbox_trojan_includes_tls_block() {
        let mut vals = test_vals(Transport::Trojan);
        vals.endpoint =
            EndpointModel::from_profile(Transport::Trojan, Some(OuterSecurity::Tls), "");
        let json = singbox_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "trojan""#));
        assert!(json.contains(r#""password": "trojan-test-password""#));
        assert!(json.contains(r#""server_name": "example.com""#));
    }

    #[test]
    fn xray_trojan_includes_tls_stream_settings() {
        let mut vals = test_vals(Transport::Trojan);
        vals.endpoint =
            EndpointModel::from_profile(Transport::Trojan, Some(OuterSecurity::Tls), "");
        let json = xray_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""protocol": "trojan""#));
        assert!(json.contains(r#""password": "trojan-test-password""#));
        assert!(json.contains(r#""security": "tls""#));
    }

    #[test]
    fn hiddify_trojan_wraps_singbox_outbound() {
        let mut vals = test_vals(Transport::Trojan);
        vals.endpoint =
            EndpointModel::from_profile(Transport::Trojan, Some(OuterSecurity::Tls), "");
        let json = hiddify_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "trojan""#));
        assert!(json.contains(r#""password": "trojan-test-password""#));
    }

    #[test]
    fn mihomo_hysteria2_emits_bandwidth_when_set() {
        let mut vals = test_vals(Transport::Hysteria2);
        vals.endpoint =
            EndpointModel::from_profile(Transport::Hysteria2, Some(OuterSecurity::Tls), "");
        let json = mihomo_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "hysteria2""#));
        assert!(json.contains(r#""password": "hy2-test-password""#));
        assert!(json.contains(r#""up": 50"#));
        assert!(json.contains(r#""down": 100"#));
    }

    #[test]
    fn mihomo_hysteria2_omits_bandwidth_when_unset() {
        let mut vals = test_vals(Transport::Hysteria2);
        vals.endpoint =
            EndpointModel::from_profile(Transport::Hysteria2, Some(OuterSecurity::Tls), "");
        vals.hysteria2_up_mbps = None;
        vals.hysteria2_down_mbps = None;
        let json = mihomo_format("1.2.3.4", "test", &vals);
        assert!(!json.contains(r#""up""#));
        assert!(!json.contains(r#""down""#));
    }

    #[test]
    fn singbox_hysteria2_includes_h3_alpn() {
        let mut vals = test_vals(Transport::Hysteria2);
        vals.endpoint =
            EndpointModel::from_profile(Transport::Hysteria2, Some(OuterSecurity::Tls), "");
        let json = singbox_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "hysteria2""#));
        assert!(json.contains(r#""up_mbps": 50"#));
        assert!(json.contains(r#""down_mbps": 100"#));
        assert!(json.contains(r#""h3""#));
    }

    #[test]
    fn xray_hysteria2_export_fails_cleanly() {
        let mut vals = test_vals(Transport::Hysteria2);
        vals.endpoint =
            EndpointModel::from_profile(Transport::Hysteria2, Some(OuterSecurity::Tls), "");
        let err = generate_client_config(ClientFormat::Xray, "1.2.3.4", "test", &vals)
            .expect_err("hysteria2 xray export should fail");
        assert!(err.contains("hysteria2"));
    }

    #[test]
    fn hiddify_hysteria2_wraps_singbox_outbound() {
        let mut vals = test_vals(Transport::Hysteria2);
        vals.endpoint =
            EndpointModel::from_profile(Transport::Hysteria2, Some(OuterSecurity::Tls), "");
        let json = hiddify_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "hysteria2""#));
        assert!(json.contains(r#""password": "hy2-test-password""#));
    }

    #[test]
    fn mihomo_tuic_renders_tuic_proxy_entry() {
        let mut vals = test_vals(Transport::Tuic);
        vals.endpoint = EndpointModel::from_profile(Transport::Tuic, Some(OuterSecurity::Tls), "");
        let json = mihomo_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "tuic""#));
        assert!(json.contains(r#""uuid": "12345678-1234-1234-1234-123456789abc""#));
        assert!(json.contains(r#""password": "tuic-test-password""#));
        assert!(json.contains(r#""congestion-controller": "bbr""#));
    }

    #[test]
    fn singbox_tuic_renders_outbound() {
        let mut vals = test_vals(Transport::Tuic);
        vals.endpoint = EndpointModel::from_profile(Transport::Tuic, Some(OuterSecurity::Tls), "");
        let json = singbox_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "tuic""#));
        assert!(json.contains(r#""uuid": "12345678-1234-1234-1234-123456789abc""#));
        assert!(json.contains(r#""congestion_control": "bbr""#));
    }

    #[test]
    fn xray_tuic_export_fails_cleanly() {
        let mut vals = test_vals(Transport::Tuic);
        vals.endpoint = EndpointModel::from_profile(Transport::Tuic, Some(OuterSecurity::Tls), "");
        let err = generate_client_config(ClientFormat::Xray, "1.2.3.4", "test", &vals)
            .expect_err("tuic xray export should fail");
        assert!(err.contains("tuic"));
    }

    #[test]
    fn hiddify_tuic_wraps_singbox_outbound() {
        let mut vals = test_vals(Transport::Tuic);
        vals.endpoint = EndpointModel::from_profile(Transport::Tuic, Some(OuterSecurity::Tls), "");
        let json = hiddify_format("1.2.3.4", "test", &vals);
        assert!(json.contains(r#""type": "tuic""#));
        assert!(json.contains(r#""uuid": "12345678-1234-1234-1234-123456789abc""#));
    }

    #[test]
    fn hiddify_anytls_export_fails_until_direct_e2e_passes() {
        let err = generate_client_config(
            ClientFormat::Hiddify,
            "1.2.3.4",
            "test",
            &test_vals(Transport::AnyTls),
        )
        .expect_err("hiddify anytls export should be gated by direct E2E capability");
        assert!(err.contains(HIDDIFY_ANYTLS_PACKAGED_CORE_REASON));
    }

    #[test]
    fn xray_webtransport_export_is_disabled_until_client_shape_is_updated() {
        let vals = test_vals(Transport::WebTransport);
        let err = generate_client_config(ClientFormat::Xray, "1.2.3.4", "test", &vals)
            .expect_err("webtransport xray export should be gated");
        assert!(err.contains(WEBTRANSPORT_XRAY_EXPORT_DISABLED));
    }

    #[test]
    fn unsupported_component_bucket_fails_validation() {
        let mut vals = test_vals(Transport::Raw);
        vals.endpoint.components.network.push(Component::Vision);
        let err = generate_client_config(ClientFormat::Mihomo, "1.2.3.4", "test", &vals)
            .expect_err("unsupported component category should fail");
        assert!(err.contains("supported network component"));
    }

    #[test]
    fn singbox_omits_network_when_both_payload_networks_are_enabled() {
        let mut vals = test_vals(Transport::Raw);
        vals.flow.clear();
        vals.endpoint = EndpointModel::from_profile(Transport::Raw, None, "");
        let json = singbox_format("1.2.3.4", "test", &vals);
        assert!(!json.contains(r#""network": "tcp""#));
    }

    #[test]
    fn diagnostics_include_resolved_stack_and_export_support() {
        let vals = test_vals(Transport::Reality);
        let diagnostics = build_endpoint_diagnostics(&vals, Some(ClientFormat::Mihomo));
        assert_eq!(diagnostics.descriptor.display_name, "VLESS");
        assert!(diagnostics.resolved.stack_summary.contains("REALITY"));
        assert_eq!(
            diagnostics.export.as_ref().map(|item| item.supported),
            Some(true)
        );
        assert_eq!(
            diagnostics.export.as_ref().and_then(|item| item.error_code),
            None
        );
        let json = serde_json::to_value(&diagnostics).expect("diagnostics should serialize");
        assert_eq!(json["descriptor"]["id"], "vless");
        assert_eq!(json["resolved"]["outer_security"], "reality");
    }

    #[test]
    fn diagnostics_report_export_failure() {
        let mut vals = test_vals(Transport::WireGuard);
        vals.endpoint = EndpointModel::from_profile(Transport::WireGuard, None, "");
        let diagnostics = build_endpoint_diagnostics(&vals, Some(ClientFormat::Xray));
        let export = diagnostics
            .export
            .expect("export diagnostics should be present");
        assert!(!export.supported);
        assert_eq!(
            export.error_code,
            Some("wireguard_xray_export_unimplemented")
        );
        assert!(
            export
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("WireGuard export is not implemented")
        );
    }

    #[test]
    fn diagnostics_report_webtransport_export_failure() {
        let vals = test_vals(Transport::WebTransport);
        let diagnostics = build_endpoint_diagnostics(&vals, Some(ClientFormat::Xray));
        let export = diagnostics
            .export
            .expect("export diagnostics should be present");
        assert!(!export.supported);
        assert_eq!(
            export.error_code,
            Some("webtransport_xray_family_export_disabled")
        );
        assert!(
            export
                .error
                .as_deref()
                .unwrap_or_default()
                .contains(WEBTRANSPORT_XRAY_EXPORT_DISABLED)
        );
    }

    #[test]
    fn diagnostics_report_hiddify_anytls_export_failure() {
        let vals = test_vals(Transport::AnyTls);
        let diagnostics = build_endpoint_diagnostics(&vals, Some(ClientFormat::Hiddify));
        let export = diagnostics
            .export
            .expect("export diagnostics should be present");
        assert!(!export.supported);
        assert_eq!(export.error_code, Some("hiddify_anytls_packaged_core_gap"));
        assert!(
            export
                .error
                .as_deref()
                .unwrap_or_default()
                .contains(HIDDIFY_ANYTLS_PACKAGED_CORE_REASON)
        );
    }

    #[test]
    fn diagnostics_detect_hysteria2_salamander_with_supported_export() {
        let unique = format!(
            "wrongsv-hysteria2-salamander-{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::write(
            &path,
            r#"
listen = "0.0.0.0:443"

[hysteria2]
password = "secret"

[hysteria2.obfs]
type = "salamander"
password = "obfs-secret"
"#,
        )
        .expect("test config should write");
        let vals = resolve_client_values(path.to_str(), None, "example.com");
        std::fs::remove_file(&path).ok();
        let diagnostics = build_endpoint_diagnostics(&vals, Some(ClientFormat::Mihomo));
        assert_eq!(diagnostics.descriptor.display_name, "Hysteria2");
        assert!(
            diagnostics
                .resolved
                .active_components
                .camouflage
                .contains(&Component::HysteriaSalamander)
        );
        let export = diagnostics
            .export
            .expect("export diagnostics should be present");
        assert!(export.supported);
    }

    #[test]
    fn diagnostics_detect_hysteria2_gecko_with_supported_export() {
        let unique = format!(
            "wrongsv-hysteria2-gecko-{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::write(
            &path,
            r#"
listen = "0.0.0.0:443"

[hysteria2]
password = "secret"

[hysteria2.obfs]
type = "gecko"
password = "obfs-secret"
"#,
        )
        .expect("test config should write");
        let vals = resolve_client_values(path.to_str(), None, "example.com");
        std::fs::remove_file(&path).ok();
        let diagnostics = build_endpoint_diagnostics(&vals, Some(ClientFormat::Mihomo));
        assert!(
            diagnostics
                .resolved
                .active_components
                .camouflage
                .contains(&Component::HysteriaGecko)
        );
        assert!(
            diagnostics
                .export
                .expect("export diagnostics should exist")
                .supported
        );
    }

    #[test]
    fn resolve_client_values_detects_meek_tls_outer_security() {
        let unique = format!(
            "wrongsv-meek-{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::write(
            &path,
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"
flow = ""

[meek]
path = "/meek"

[meek.tls]
certificate = "cert"
key = "key"
"#,
        )
        .expect("test config should write");
        let vals = resolve_client_values(path.to_str(), Some(Transport::Meek), "example.com");
        std::fs::remove_file(&path).ok();
        assert_eq!(vals.transport_method(), Some(TransportMethod::Meek));
        assert_eq!(vals.outer_security(), Some(OuterSecurity::Tls));
    }

    #[test]
    fn mihomo_flow_omitted_when_empty() {
        let mut vals = test_vals(Transport::Raw);
        vals.flow = String::new();
        let json = mihomo_format("1.2.3.4", "test", &vals);
        assert!(!json.contains(r#""flow""#));
    }

    // ── Xray format tests ───────────────────────────────────────────────

    #[test]
    fn xray_has_protocol_and_settings() {
        let json = xray_format("1.2.3.4", "test", &test_vals(Transport::Reality));
        assert!(json.contains(r#""protocol": "vless""#));
        assert!(json.contains(r#""settings""#));
        assert!(json.contains(r#""vnext""#));
        assert!(json.contains(r#""id": "test-uuid-1234""#));
        assert!(json.contains(r#""encryption": "none""#));
    }

    #[test]
    fn hiddify_shadowtls_uses_detour_outbound() {
        let json = hiddify_format("1.2.3.4", "test", &test_vals(Transport::ShadowTls));
        assert!(json.contains(r#""type": "shadowtls""#));
        assert!(json.contains(r#""detour": "test-shadowtls""#));
        assert!(json.contains(r#""password": "shadow-pass""#));
    }

    #[test]
    fn xray_reality_has_stream_settings() {
        let json = xray_format("1.2.3.4", "test", &test_vals(Transport::Reality));
        assert!(json.contains(r#""network": "tcp""#));
        assert!(json.contains(r#""security": "reality""#));
        assert!(json.contains(r#""realitySettings""#));
        assert!(json.contains(r#""publicKey": "test-pubkey-base64""#));
        assert!(json.contains(r#""shortId": "abcd1234""#));
        assert!(json.contains(r#""fingerprint": "chrome""#));
        assert!(json.contains(r#""serverName": "example.com""#));
    }

    #[test]
    fn xray_tls_has_tls_settings() {
        let json = xray_format("1.2.3.4", "test", &test_vals(Transport::Tls));
        assert!(json.contains(r#""security": "tls""#));
        assert!(json.contains(r#""tlsSettings""#));
        assert!(json.contains(r#""allowInsecure": true"#));
    }

    #[test]
    fn xray_ws_has_ws_settings() {
        let json = xray_format("1.2.3.4", "test", &test_vals(Transport::WebSocket));
        assert!(json.contains(r#""network": "ws""#));
        assert!(json.contains(r#""wsSettings""#));
        assert!(json.contains(r#""path": "/ws-path""#));
    }

    #[test]
    fn xray_grpc_has_grpc_settings() {
        let json = xray_format("1.2.3.4", "test", &test_vals(Transport::Grpc));
        assert!(json.contains(r#""network": "grpc""#));
        assert!(json.contains(r#""grpcSettings""#));
        assert!(json.contains(r#""serviceName": "TestService""#));
    }

    #[test]
    fn xray_kcp_has_kcp_settings() {
        let json = xray_format("1.2.3.4", "test", &test_vals(Transport::Kcp));
        assert!(json.contains(r#""network": "mkcp""#));
        assert!(json.contains(r#""kcpSettings""#));
        assert!(json.contains(r#""mtu": 1350"#));
        assert!(json.contains(r#""tti": 50"#));
        assert!(json.contains(r#""finalmask""#));
        assert!(json.contains(r#""type": "mkcp-aes128gcm""#));
        assert!(json.contains(r#""password": "test-seed""#));
    }

    #[test]
    fn xray_xhttp_has_xhttp_settings() {
        let json = xray_format("1.2.3.4", "test", &test_vals(Transport::Xhttp));
        assert!(json.contains(r#""network": "xhttp""#));
        assert!(json.contains(r#""xhttpSettings""#));
        assert!(json.contains(r#""mode": "stream-one""#));
    }

    #[test]
    fn resolve_client_values_prefers_vmess_user_uuid() {
        let path = format!("/tmp/client-config-vmess-{}.toml", std::process::id());
        std::fs::write(
            &path,
            r#"
listen = "127.0.0.1:50443"

[vmess]

[[vmess.users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"
"#,
        )
        .unwrap();

        let vals = resolve_client_values(Some(&path), Some(Transport::Vmess), "YOUR_SNI");
        assert_eq!(vals.uuid, "12345678-1234-1234-1234-123456789abc");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn xray_quic_has_quic_settings() {
        let json = xray_format("1.2.3.4", "test", &test_vals(Transport::Quic));
        assert!(json.contains(r#""network": "quic""#));
        assert!(json.contains(r#""quicSettings""#));
    }

    // ── Hiddify format tests ────────────────────────────────────────────

    #[test]
    fn hiddify_has_wrapper_structure() {
        let json = hiddify_format("1.2.3.4", "test", &test_vals(Transport::Reality));
        assert!(json.contains(r#""remarks": "test""#));
        assert!(json.contains(r#""configs""#));
        assert!(json.contains(r#""type": "vless""#));
        assert!(json.contains(r#""type": "direct""#));
    }

    #[test]
    fn hiddify_has_reality_fields() {
        let json = hiddify_format("1.2.3.4", "test", &test_vals(Transport::Reality));
        assert!(json.contains(r#""reality""#));
        assert!(json.contains(r#""public_key": "test-pubkey-base64""#));
    }

    #[test]
    fn hiddify_grpc_has_service_name() {
        let json = hiddify_format("1.2.3.4", "test", &test_vals(Transport::Grpc));
        assert!(json.contains(r#""type": "grpc""#));
        assert!(json.contains(r#""service_name": "TestService""#));
    }

    #[test]
    fn hiddify_xhttp_uses_xray_wrapper() {
        let json = hiddify_format("1.2.3.4", "test", &test_vals(Transport::Xhttp));
        assert!(json.contains(r#""type": "xray""#));
        assert!(json.contains(r#""network": "xhttp""#));
        assert!(json.contains(r#""xhttpSettings""#));
        assert!(json.contains(r#""mode": "stream-one""#));
    }

    #[test]
    fn client_config_snapshots_match_fixtures() {
        for (config_path, format, fixture_path) in [
            (
                "configs/reality-vision.toml",
                ClientFormat::Mihomo,
                "tests/snapshots/client-configs/mihomo-reality.json",
            ),
            (
                "configs/anytls-vision.toml",
                ClientFormat::Mihomo,
                "tests/snapshots/client-configs/mihomo-anytls.json",
            ),
            (
                "configs/anytls-vision.toml",
                ClientFormat::SingBox,
                "tests/snapshots/client-configs/singbox-anytls.json",
            ),
            (
                "configs/reality-vision.toml",
                ClientFormat::Xray,
                "tests/snapshots/client-configs/xray-reality.json",
            ),
            (
                "configs/shadowtls.toml",
                ClientFormat::Hiddify,
                "tests/snapshots/client-configs/hiddify-shadowtls.json",
            ),
            (
                "configs/xhttp.toml",
                ClientFormat::Hiddify,
                "tests/snapshots/client-configs/hiddify-xhttp.json",
            ),
        ] {
            let config_path = checked_in_config(config_path);
            let vals = resolve_client_values(Some(&config_path), None, "example.com");
            let actual = generate_client_config(format, "1.2.3.4", "snapshot", &vals)
                .expect("snapshot config should generate")
                + "\n";
            let expected = fixture(fixture_path);
            assert_eq!(actual, expected, "{fixture_path} snapshot mismatch");
        }
    }
}
