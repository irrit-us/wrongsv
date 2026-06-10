use serde::Serialize;

use crate::{ClientFormat, Transport};

// ---------------------------------------------------------------------------
// Client config generation — outputs sing-box or mihomo JSON for connecting
// clients. Separated from CLI parsing so main.rs stays focused on server
// lifecycle.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct ClientConfigValues {
    pub uuid: String,
    pub flow: String,
    pub port: String,
    pub short_id: String,
    pub x25519_pk: String,
    pub servername: String,
    pub transport: Transport,
    pub has_tls: bool,
    pub ws_path: String,
    pub grpc_service_name: String,
    pub kcp_seed: String,
    pub kcp_mtu: u16,
    pub kcp_tti: u16,
    pub xhttp_path: String,
    pub xhttp_host: String,
}

/// Resolve values for the generated client config from TOML config or defaults.
pub(crate) fn resolve_client_values(
    cli_config: Option<&str>,
    transport_override: Option<Transport>,
    servername_override: &str,
) -> ClientConfigValues {
    let build_uuid = || option_env!("BUILD_UUID").unwrap_or("00000000-0000-4000-8000-000000000000");
    let build_port = || option_env!("BUILD_PORT").unwrap_or("443");
    let build_sid = || option_env!("BUILD_SHORT_ID").unwrap_or("00000000");
    let build_pk =
        || option_env!("BUILD_X25519_PK").unwrap_or("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    let toml_config = cli_config.and_then(|path| {
        let content = std::fs::read_to_string(path).ok()?;
        toml::from_str::<wrongsv_server::Config>(&content).ok()
    });

    // Determine transport: explicit --transport flag, or detect from config
    let transport = transport_override.unwrap_or_else(|| match &toml_config {
        Some(cfg) if cfg.reality.is_some() => Transport::Reality,
        Some(cfg) if cfg.anytls.is_some() => Transport::AnyTls,
        Some(cfg) if cfg.websocket.is_some() => Transport::WebSocket,
        Some(cfg) if cfg.httpupgrade.is_some() => Transport::HttpUpgrade,
        Some(cfg) if cfg.grpc.is_some() => Transport::Grpc,
        Some(cfg) if cfg.xhttp.is_some() => Transport::Xhttp,
        Some(cfg) if cfg.quic.is_some() => Transport::Quic,
        Some(cfg) if cfg.kcp.is_some() => Transport::Kcp,
        Some(cfg) if cfg.tls.is_some() => Transport::Tls,
        _ => Transport::Raw,
    });

    match toml_config {
        Some(ref cfg) => {
            let uuid = cfg
                .users
                .first()
                .map(|u| u.id.as_str())
                .unwrap_or(build_uuid());
            let flow = cfg
                .users
                .first()
                .and_then(|u| (!u.flow.is_empty()).then_some(u.flow.as_str()))
                .or(cfg.flow.as_deref())
                .unwrap_or("");
            let port = cfg.listen.rsplit(':').next().unwrap_or(build_port());
            let (pk, sid) = match &cfg.reality {
                Some(rc) => {
                    let pk = wrongsv_reality::private_key_hex_to_public_b64(&rc.private_key)
                        .unwrap_or_else(|_| build_pk().to_string());
                    let sid = rc
                        .short_ids
                        .first()
                        .cloned()
                        .unwrap_or_else(|| build_sid().to_string());
                    (pk, sid)
                }
                None => (build_pk().to_string(), build_sid().to_string()),
            };
            let servername = if servername_override == "YOUR_SNI" {
                cfg.reality
                    .as_ref()
                    .and_then(|rc| rc.dest.as_ref())
                    .and_then(|d| d.split(':').next())
                    .unwrap_or(servername_override)
                    .to_string()
            } else {
                servername_override.to_string()
            };
            let ws_path = cfg
                .websocket
                .as_ref()
                .map(|w| normalize_path(&w.path))
                .or_else(|| cfg.httpupgrade.as_ref().map(|h| normalize_path(&h.path)))
                .unwrap_or_else(|| "/".to_string());
            let grpc_service_name = cfg
                .grpc
                .as_ref()
                .and_then(|g| g.service_name.clone())
                .unwrap_or_else(|| "GunService".to_string());
            let kcp_seed = cfg
                .kcp
                .as_ref()
                .and_then(|k| k.seed.clone())
                .unwrap_or_default();
            let kcp_mtu = cfg.kcp.as_ref().and_then(|k| k.mtu).unwrap_or(1350) as u16;
            let kcp_tti = cfg.kcp.as_ref().and_then(|k| k.tti).unwrap_or(50) as u16;
            let xhttp_path = cfg
                .xhttp
                .as_ref()
                .and_then(|x| x.path.clone())
                .map(|p| normalize_path(&p))
                .unwrap_or_else(|| "/xhttp".to_string());
            let xhttp_host = cfg
                .xhttp
                .as_ref()
                .and_then(|x| x.host.clone())
                .unwrap_or_default();
            // Detect TLS: true for TLS-layer transports, true for stream
            // transports that have a tls sub-config, true for QUIC (built-in).
            let has_tls = match transport {
                Transport::Reality | Transport::AnyTls | Transport::Tls | Transport::Quic => true,
                Transport::WebSocket => cfg
                    .websocket
                    .as_ref()
                    .and_then(|w| w.tls.as_ref())
                    .is_some(),
                Transport::HttpUpgrade => cfg
                    .httpupgrade
                    .as_ref()
                    .and_then(|h| h.tls.as_ref())
                    .is_some(),
                Transport::Grpc => cfg.grpc.as_ref().and_then(|g| g.tls.as_ref()).is_some(),
                Transport::Xhttp => cfg.xhttp.as_ref().and_then(|x| x.tls.as_ref()).is_some(),
                Transport::Kcp | Transport::Raw => false,
            };

            ClientConfigValues {
                uuid: uuid.to_string(),
                flow: flow.to_string(),
                port: port.to_string(),
                short_id: sid,
                x25519_pk: pk,
                servername,
                transport,
                has_tls,
                ws_path,
                grpc_service_name,
                kcp_seed,
                kcp_mtu,
                kcp_tti,
                xhttp_path,
                xhttp_host,
            }
        }
        None => ClientConfigValues {
            uuid: build_uuid().to_string(),
            flow: "xtls-rprx-vision".to_string(),
            port: build_port().to_string(),
            short_id: build_sid().to_string(),
            x25519_pk: build_pk().to_string(),
            servername: servername_override.to_string(),
            transport,
            has_tls: matches!(
                transport,
                Transport::Reality | Transport::AnyTls | Transport::Tls | Transport::Quic
            ),
            ws_path: "/".to_string(),
            grpc_service_name: "GunService".to_string(),
            kcp_seed: String::new(),
            kcp_mtu: 1350,
            kcp_tti: 50,
            xhttp_path: "/xhttp".to_string(),
            xhttp_host: String::new(),
        },
    }
}

fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

pub(crate) fn generate_client_config(
    format: ClientFormat,
    server_host: &str,
    client_name: &str,
    vals: &ClientConfigValues,
) -> String {
    match format {
        ClientFormat::Mihomo => mihomo_format(server_host, client_name, vals),
        ClientFormat::SingBox => singbox_format(server_host, client_name, vals),
        ClientFormat::Xray => xray_format(server_host, client_name, vals),
        ClientFormat::Hiddify => hiddify_format(server_host, client_name, vals),
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
}

fn mihomo_format(server_host: &str, client_name: &str, vals: &ClientConfigValues) -> String {
    let port: u16 = vals.port.parse().unwrap_or(443);

    let (tls, client_fingerprint, servername, skip_cert_verify, reality_opts) = match vals.transport
    {
        Transport::Reality => (
            Some(true),
            Some("chrome"),
            Some(vals.servername.as_str()),
            None,
            Some(RealityOpts {
                public_key: &vals.x25519_pk,
                short_id: &vals.short_id,
            }),
        ),
        Transport::AnyTls | Transport::Tls => (
            Some(true),
            Some("chrome"),
            Some(vals.servername.as_str()),
            Some(true),
            None,
        ),
        _ if vals.has_tls => (
            Some(true),
            Some("chrome"),
            Some(vals.servername.as_str()),
            Some(true),
            None,
        ),
        _ => (None, None, None, None, None),
    };

    // If a stream transport is used, TLS comes from the transport, not separately
    let (network, ws_opts, grpc_opts, mkcp_opts, quic_opts, xhttp_opts) = match vals.transport {
        Transport::WebSocket => (
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
        Transport::HttpUpgrade => (
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
        Transport::Grpc => (
            Some("grpc"),
            None,
            Some(GrpcOpts {
                grpc_service_name: &vals.grpc_service_name,
            }),
            None,
            None,
            None,
        ),
        Transport::Kcp => (
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
        Transport::Quic => (Some("quic"), None, None, None, Some(QuicOpts {}), None),
        Transport::Xhttp => (
            Some("xhttp"),
            None,
            None,
            None,
            None,
            Some(XhttpOpts {
                path: &vals.xhttp_path,
                host: &vals.xhttp_host,
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

fn singbox_format(server_host: &str, client_name: &str, vals: &ClientConfigValues) -> String {
    let port: u16 = vals.port.parse().unwrap_or(443);

    let tls = if vals.has_tls {
        match vals.transport {
            Transport::Reality => Some(SingBoxTls {
                enabled: true,
                server_name: &vals.servername,
                insecure: None,
                utls: Some(SingBoxUtls {
                    enabled: true,
                    fingerprint: "chrome",
                }),
                reality: Some(SingBoxReality {
                    enabled: true,
                    public_key: &vals.x25519_pk,
                    short_id: &vals.short_id,
                }),
            }),
            _ => Some(SingBoxTls {
                enabled: true,
                server_name: &vals.servername,
                insecure: Some(true),
                utls: Some(SingBoxUtls {
                    enabled: true,
                    fingerprint: "chrome",
                }),
                reality: None,
            }),
        }
    } else {
        None
    };

    let network: Option<&str> = match vals.transport {
        Transport::Quic | Transport::Kcp => None, // QUIC/KCP don't use tcp/udp network
        _ => Some(match vals.transport {
            Transport::Kcp => "udp",
            _ => "tcp",
        }),
    };

    let packet_encoding: Option<&str> = Some("packetaddr");

    let transport: Option<serde_json::Value> = match vals.transport {
        Transport::WebSocket => serde_json::to_value(SingBoxWsTransport {
            transport_type: "ws",
            path: Some(&vals.ws_path),
        })
        .ok(),
        Transport::HttpUpgrade => serde_json::to_value(SingBoxWsTransport {
            transport_type: "httpupgrade",
            path: Some(&vals.ws_path),
        })
        .ok(),
        Transport::Grpc => serde_json::to_value(SingBoxGrpcTransport {
            transport_type: "grpc",
            service_name: &vals.grpc_service_name,
        })
        .ok(),
        Transport::Quic => serde_json::to_value(serde_json::json!({"type": "quic"})).ok(),
        Transport::Xhttp => {
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

    let vless_outbound = serde_json::to_value(SingBoxVlessOutbound {
        outbound_type: "vless",
        tag: client_name,
        server: server_host,
        server_port: port,
        uuid: &vals.uuid,
        flow: &vals.flow,
        network,
        packet_encoding,
        tls,
        transport,
    })
    .expect("SingBoxVlessOutbound should serialize");

    let direct_outbound = serde_json::json!({"type": "direct", "tag": "direct"});

    let config = SingBoxConfig {
        inbounds: vec![SingBoxInbound {
            inbound_type: "mixed".into(),
            tag: "mixed-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: 10809,
        }],
        outbounds: vec![vless_outbound, direct_outbound],
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
    #[serde(skip_serializing_if = "str::is_empty")]
    seed: String,
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

fn xray_format(server_host: &str, client_name: &str, vals: &ClientConfigValues) -> String {
    let port: u16 = vals.port.parse().unwrap_or(443);

    // Network name mapping: wrongsv transport → Xray network string
    let xray_network: &str = match vals.transport {
        Transport::Raw | Transport::Tls | Transport::AnyTls | Transport::Reality => "tcp",
        Transport::WebSocket => "ws",
        Transport::Grpc => "grpc",
        Transport::HttpUpgrade => "httpupgrade",
        Transport::Xhttp => "xhttp",
        Transport::Quic => "quic",
        Transport::Kcp => "mkcp",
    };

    let security: Option<&str> = match vals.transport {
        Transport::Reality => Some("reality"),
        Transport::Tls | Transport::AnyTls => Some("tls"),
        _ if vals.has_tls => Some("tls"),
        _ => None,
    };

    let reality_settings = match vals.transport {
        Transport::Reality => Some(XrayRealitySettings {
            server_name: &vals.servername,
            fingerprint: "chrome",
            public_key: &vals.x25519_pk,
            short_id: &vals.short_id,
        }),
        _ => None,
    };

    let tls_settings = match vals.transport {
        Transport::Tls | Transport::AnyTls => Some(XrayTlsSettings {
            server_name: &vals.servername,
            fingerprint: "chrome",
            allow_insecure: true,
        }),
        _ if vals.has_tls && vals.transport != Transport::Reality => Some(XrayTlsSettings {
            server_name: &vals.servername,
            fingerprint: "chrome",
            allow_insecure: true,
        }),
        _ => None,
    };

    let ws_settings = match vals.transport {
        Transport::WebSocket => Some(XrayWsSettings {
            path: &vals.ws_path,
        }),
        _ => None,
    };

    let grpc_settings = match vals.transport {
        Transport::Grpc => Some(XrayGrpcSettings {
            service_name: &vals.grpc_service_name,
        }),
        _ => None,
    };

    let kcp_settings = match vals.transport {
        Transport::Kcp => Some(XrayKcpSettings {
            mtu: vals.kcp_mtu,
            tti: vals.kcp_tti,
            uplink_capacity: 5,
            downlink_capacity: 20,
            seed: vals.kcp_seed.clone(),
        }),
        _ => None,
    };

    let quic_settings = match vals.transport {
        Transport::Quic => Some(XrayQuicSettings {
            security: "none",
            key: "",
            header: XrayQuicHeader {
                header_type: "none",
            },
        }),
        _ => None,
    };

    let httpupgrade_settings = match vals.transport {
        Transport::HttpUpgrade => Some(XrayHttpUpgradeSettings {
            path: &vals.ws_path,
        }),
        _ => None,
    };

    let xhttp_settings = match vals.transport {
        Transport::Xhttp => Some(XrayXhttpSettings {
            path: &vals.xhttp_path,
            host: &vals.xhttp_host,
            mode: "auto",
        }),
        _ => None,
    };

    let stream_settings = XrayStreamSettings {
        network: xray_network,
        security,
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

    let tls = if vals.has_tls {
        match vals.transport {
            Transport::Reality => Some(SingBoxTls {
                enabled: true,
                server_name: &vals.servername,
                insecure: None,
                utls: Some(SingBoxUtls {
                    enabled: true,
                    fingerprint: "chrome",
                }),
                reality: Some(SingBoxReality {
                    enabled: true,
                    public_key: &vals.x25519_pk,
                    short_id: &vals.short_id,
                }),
            }),
            _ => Some(SingBoxTls {
                enabled: true,
                server_name: &vals.servername,
                insecure: Some(true),
                utls: Some(SingBoxUtls {
                    enabled: true,
                    fingerprint: "chrome",
                }),
                reality: None,
            }),
        }
    } else {
        None
    };

    let network: Option<&str> = match vals.transport {
        Transport::Quic | Transport::Kcp => None,
        _ => Some(match vals.transport {
            Transport::Kcp => "udp",
            _ => "tcp",
        }),
    };

    let packet_encoding: Option<&str> = Some("packetaddr");

    let transport: Option<serde_json::Value> = match vals.transport {
        Transport::WebSocket => serde_json::to_value(SingBoxWsTransport {
            transport_type: "ws",
            path: Some(&vals.ws_path),
        })
        .ok(),
        Transport::HttpUpgrade => serde_json::to_value(SingBoxWsTransport {
            transport_type: "httpupgrade",
            path: Some(&vals.ws_path),
        })
        .ok(),
        Transport::Grpc => serde_json::to_value(SingBoxGrpcTransport {
            transport_type: "grpc",
            service_name: &vals.grpc_service_name,
        })
        .ok(),
        Transport::Quic => serde_json::to_value(serde_json::json!({"type": "quic"})).ok(),
        Transport::Xhttp => {
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

    let vless_outbound = serde_json::to_value(SingBoxVlessOutbound {
        outbound_type: "vless",
        tag: client_name,
        server: server_host,
        server_port: port,
        uuid: &vals.uuid,
        flow: &vals.flow,
        network,
        packet_encoding,
        tls,
        transport,
    })
    .expect("SingBoxVlessOutbound should serialize");

    let direct_outbound = serde_json::json!({"type": "direct", "tag": "direct"});

    let config = HiddifyConfig {
        remarks: client_name.to_string(),
        subscription: String::new(),
        configs: vec![vless_outbound, direct_outbound],
    };

    serde_json::to_string_pretty(&config).expect("HiddifyConfig should serialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vals(transport: Transport) -> ClientConfigValues {
        ClientConfigValues {
            uuid: "test-uuid-1234".into(),
            flow: "xtls-rprx-vision".into(),
            port: "443".into(),
            short_id: "abcd1234".into(),
            x25519_pk: "test-pubkey-base64".into(),
            servername: "example.com".into(),
            transport,
            has_tls: matches!(
                transport,
                Transport::Reality | Transport::AnyTls | Transport::Tls | Transport::Quic
            ),
            ws_path: "/ws-path".into(),
            grpc_service_name: "TestService".into(),
            kcp_seed: "test-seed".into(),
            kcp_mtu: 1350,
            kcp_tti: 50,
            xhttp_path: "/xhttp-path".into(),
            xhttp_host: "xhost.example.com".into(),
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
    fn singbox_has_packet_encoding() {
        let json = singbox_format("1.2.3.4", "test", &test_vals(Transport::Reality));
        assert!(json.contains(r#""packet_encoding": "packetaddr""#));
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
        assert!(json.contains(r#""seed": "test-seed""#));
    }

    #[test]
    fn xray_xhttp_has_xhttp_settings() {
        let json = xray_format("1.2.3.4", "test", &test_vals(Transport::Xhttp));
        assert!(json.contains(r#""network": "xhttp""#));
        assert!(json.contains(r#""xhttpSettings""#));
        assert!(json.contains(r#""mode": "auto""#));
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
}
