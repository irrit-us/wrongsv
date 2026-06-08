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
    pub ws_path: String,
}

/// Resolve values for the generated client config from TOML config or defaults.
pub(crate) fn resolve_client_values(
    cli_config: Option<&str>,
    transport_override: Option<Transport>,
    servername_override: &str,
) -> ClientConfigValues {
    let build_uuid =
        || option_env!("BUILD_UUID").unwrap_or("00000000-0000-4000-8000-000000000000");
    let build_port = || option_env!("BUILD_PORT").unwrap_or("443");
    let build_sid = || option_env!("BUILD_SHORT_ID").unwrap_or("00000000");
    let build_pk = || {
        option_env!("BUILD_X25519_PK")
            .unwrap_or("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    };

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
                .or_else(|| {
                    cfg.httpupgrade
                        .as_ref()
                        .map(|h| normalize_path(&h.path))
                })
                .unwrap_or_else(|| "/".to_string());

            ClientConfigValues {
                uuid: uuid.to_string(),
                flow: flow.to_string(),
                port: port.to_string(),
                short_id: sid,
                x25519_pk: pk,
                servername,
                transport,
                ws_path,
            }
        }
        None => ClientConfigValues {
            uuid: build_uuid().to_string(),
            flow: "xtls-rprx-vision".to_string(),
            port: build_port().to_string(),
            short_id: build_sid().to_string(),
            x25519_pk: build_pk().to_string(),
            servername: servername_override.to_string(),
            ws_path: "/".to_string(),
            transport,
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
    #[serde(rename = "reality-opts")]
    reality_opts: Option<RealityOpts<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ws-opts")]
    ws_opts: Option<WsOpts<'a>>,
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

fn mihomo_format(server_host: &str, client_name: &str, vals: &ClientConfigValues) -> String {
    let port: u16 = vals.port.parse().unwrap_or(443);

    let (tls, client_fingerprint, servername, reality_opts) = match vals.transport {
        Transport::Reality => (
            Some(true),
            Some("chrome"),
            Some(vals.servername.as_str()),
            Some(RealityOpts {
                public_key: &vals.x25519_pk,
                short_id: &vals.short_id,
            }),
        ),
        Transport::AnyTls | Transport::Tls => (
            Some(true),
            Some("chrome"),
            Some(vals.servername.as_str()),
            None,
        ),
        _ => (None, None, None, None),
    };

    let (network, ws_opts) = match vals.transport {
        Transport::WebSocket => (
            Some("ws"),
            Some(WsOpts {
                path: &vals.ws_path,
                v2ray_http_upgrade: None,
            }),
        ),
        Transport::HttpUpgrade => (
            Some("ws"),
            Some(WsOpts {
                path: &vals.ws_path,
                v2ray_http_upgrade: Some(true),
            }),
        ),
        _ => (None, None),
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
        reality_opts,
        network,
        ws_opts,
    };

    serde_json::to_string_pretty(&config).expect("MihomoConfig should serialize")
}

// ── sing-box format ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct SingBoxConfig<'a> {
    inbounds: Vec<SingBoxInbound>,
    outbounds: Vec<SingBoxOutbound<'a>>,
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
struct SingBoxOutbound<'a> {
    #[serde(rename = "type")]
    outbound_type: &'a str,
    tag: &'a str,
    server: &'a str,
    server_port: u16,
    uuid: &'a str,
    flow: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<SingBoxTls<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<SingBoxTransport<'a>>,
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
struct SingBoxTransport<'a> {
    #[serde(rename = "type")]
    transport_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
}

fn singbox_format(server_host: &str, client_name: &str, vals: &ClientConfigValues) -> String {
    let port: u16 = vals.port.parse().unwrap_or(443);

    let tls = match vals.transport {
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
        Transport::Tls | Transport::AnyTls => Some(SingBoxTls {
            enabled: true,
            server_name: &vals.servername,
            insecure: Some(true),
            utls: Some(SingBoxUtls {
                enabled: true,
                fingerprint: "chrome",
            }),
            reality: None,
        }),
        _ => None,
    };

    let transport = match vals.transport {
        Transport::WebSocket => Some(SingBoxTransport {
            transport_type: "ws",
            path: Some(&vals.ws_path),
        }),
        Transport::HttpUpgrade => Some(SingBoxTransport {
            transport_type: "httpupgrade",
            path: Some(&vals.ws_path),
        }),
        _ => None,
    };

    let config = SingBoxConfig {
        inbounds: vec![SingBoxInbound {
            inbound_type: "mixed".into(),
            tag: "mixed-in".into(),
            listen: "127.0.0.1".into(),
            listen_port: 10809,
        }],
        outbounds: vec![
            SingBoxOutbound {
                outbound_type: "vless",
                tag: client_name,
                server: server_host,
                server_port: port,
                uuid: &vals.uuid,
                flow: &vals.flow,
                tls,
                transport,
            },
            SingBoxOutbound {
                outbound_type: "direct",
                tag: "direct",
                server: "",
                server_port: 0,
                uuid: "",
                flow: "",
                tls: None,
                transport: None,
            },
        ],
    };

    serde_json::to_string_pretty(&config).expect("SingBoxConfig should serialize")
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
            ws_path: "/ws-path".into(),
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
}
