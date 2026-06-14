mod diagnostics;
mod profile;

pub(crate) use diagnostics::*;
pub(crate) use profile::*;

use serde::Serialize;

use crate::endpoint::{
    protocol_descriptor, resolve_endpoint, Component, ComponentDescriptorSet, EndpointComponents,
    LayerMode, OuterSecurity, ProxyProtocol, TransportMethod,
};
use crate::ClientFormat;

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
    validate_client_format_support(format, vals)?;
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
) -> Result<(), String> {
    let descriptor = protocol_descriptor(vals.protocol());
    let resolved = resolve_endpoint(&vals.endpoint);

    if descriptor.transport.mode == LayerMode::Forbidden && resolved.transport.is_some() {
        return Err(format!(
            "{} does not allow an explicit transport method in the normalized endpoint model",
            descriptor.display_name
        ));
    }
    if descriptor.outer_security.mode == LayerMode::Forbidden && resolved.outer_security.is_some() {
        return Err(format!(
            "{} does not allow outer transport security in the normalized endpoint model",
            descriptor.display_name
        ));
    }
    validate_component_support(descriptor.display_name, &resolved.active_components, descriptor.components)?;

    match resolved.protocol {
        ProxyProtocol::Vless => {
            if matches!(
                resolved.transport,
                Some(TransportMethod::Meek | TransportMethod::GdocsViewer)
            ) && format != ClientFormat::Xray
            {
                return Err(format!(
                    "{:?} transport is only available through the Xray/V2Ray family adapters",
                    resolved.transport.unwrap()
                ));
            }
            if resolved.transport == Some(TransportMethod::WebTransport)
                && !matches!(format, ClientFormat::Xray)
            {
                return Err("WebTransport export is only implemented for xray-family configs".into());
            }
            if vals.has_component(Component::AnyTls)
                && !matches!(format, ClientFormat::SingBox | ClientFormat::Hiddify)
            {
                return Err("AnyTLS export is only implemented for sing-box-family configs".into());
            }
        }
        ProxyProtocol::WireGuard => {
            if format == ClientFormat::Xray {
                return Err("WireGuard export is not implemented for xray format".into());
            }
        }
        ProxyProtocol::Vmess => {}
        ProxyProtocol::Shadowsocks
        | ProxyProtocol::Trojan
        | ProxyProtocol::Hysteria2
        | ProxyProtocol::Tuic
        | ProxyProtocol::Mixed => {
            return Err(format!(
                "{} export is not implemented for {} format",
                descriptor.display_name,
                match format {
                    ClientFormat::Mihomo => "mihomo",
                    ClientFormat::SingBox => "sing-box",
                    ClientFormat::Xray => "xray",
                    ClientFormat::Hiddify => "hiddify",
                }
            ));
        }
    }
    Ok(())
}

fn validate_component_support(
    display_name: &str,
    active: &EndpointComponents,
    declared: ComponentDescriptorSet,
) -> Result<(), String> {
    validate_component_bucket(display_name, "camouflage", &active.camouflage, declared.camouflage)?;
    validate_component_bucket(display_name, "ingress", &active.ingress, declared.ingress)?;
    validate_component_bucket(display_name, "performance", &active.performance, declared.performance)?;
    validate_component_bucket(display_name, "network", &active.network, declared.network)?;
    Ok(())
}

fn validate_component_bucket(
    display_name: &str,
    bucket: &str,
    active: &[Component],
    supported: &[Component],
) -> Result<(), String> {
    for component in active {
        if !supported.contains(component) {
            return Err(format!(
                "{} does not declare {:?} as a supported {} component",
                display_name, component, bucket
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

    let (tls, client_fingerprint, servername, skip_cert_verify, reality_opts) = match vals
        .outer_security()
    {
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
    use crate::endpoint::EndpointModel;
    use crate::Transport;

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
            | Transport::Mixed
            | Transport::WireGuard => None,
            Transport::Trojan | Transport::Hysteria2 | Transport::Tuic => {
                Some(OuterSecurity::Tls)
            }
        };
        ClientConfigValues {
            endpoint: EndpointModel::from_profile(
                transport,
                outer_security,
                "xtls-rprx-vision",
            ),
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
            wireguard_private_key: "wireguard-private-key".into(),
            wireguard_public_key: "wireguard-public-key".into(),
            wireguard_preshared_key: Some("wireguard-preshared-key".into()),
            wireguard_client_ip: "10.66.66.2/32".into(),
            wireguard_allowed_ips: vec!["10.66.66.1/32".into()],
            wireguard_mtu: 1400,
        }
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
        assert_eq!(diagnostics.export.as_ref().map(|item| item.supported), Some(true));
        let json = serde_json::to_value(&diagnostics).expect("diagnostics should serialize");
        assert_eq!(json["descriptor"]["id"], "vless");
        assert_eq!(json["resolved"]["outer_security"], "reality");
    }

    #[test]
    fn diagnostics_report_export_failure() {
        let mut vals = test_vals(Transport::WireGuard);
        vals.endpoint = EndpointModel::from_profile(Transport::WireGuard, None, "");
        let diagnostics = build_endpoint_diagnostics(&vals, Some(ClientFormat::Xray));
        let export = diagnostics.export.expect("export diagnostics should be present");
        assert!(!export.supported);
        assert!(export
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("WireGuard export is not implemented"));
    }

    #[test]
    fn diagnostics_detect_hysteria2_salamander_and_unsupported_export() {
        let unique = format!(
            "wrongsv-hysteria2-{}.toml",
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
        assert!(diagnostics
            .resolved
            .active_components
            .camouflage
            .contains(&Component::Salamander));
        let export = diagnostics.export.expect("export diagnostics should be present");
        assert!(!export.supported);
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
}
