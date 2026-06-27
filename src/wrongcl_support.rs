use crate::PayloadNetworkId;
use crate::import_config::{
    ImportConfig, ImportResolutionHint, WrongclClientConfigDocument,
    build_wrongcl_client_config_document, build_wrongcl_import_spec,
};
use serde::Serialize;

const KNOWN_WRONGCL_PROFILES: &[(&str, &str)] = &[
    ("raw", "VLESS raw TCP"),
    ("tls", "VLESS raw TCP over TLS"),
    ("reality", "VLESS REALITY"),
    ("anytls", "VLESS AnyTLS"),
    ("websocket", "VLESS WebSocket"),
    ("httpupgrade", "VLESS HTTPUpgrade"),
    ("grpc", "VLESS gRPC"),
    ("xhttp", "VLESS XHTTP"),
    ("meek", "VLESS Meek"),
    ("gdocsviewer", "VLESS Google Docs Viewer"),
    ("quic", "VLESS QUIC"),
    ("kcp", "VLESS mKCP"),
    ("webtransport", "VLESS WebTransport"),
    ("shadowtls", "VLESS ShadowTLS"),
    ("vmess", "VMess AEAD"),
    ("shadowsocks", "Shadowsocks AEAD/2022"),
    ("trojan", "Trojan TLS"),
    ("hysteria2", "Hysteria2"),
    ("tuic", "TUIC"),
    ("mixed", "Mixed SOCKS/HTTP proxy inbound"),
    ("wireguard", "WireGuard"),
    ("naive", "Naive"),
    ("snell", "Snell"),
    ("lua", "Lua"),
    ("masque", "Masque"),
    ("trusttunnel", "TrustTunnel"),
    ("brook", "Brook"),
    ("vlite", "Vlite"),
    ("tor", "Tor"),
    ("ssh", "SSH"),
    ("juicity", "Juicity"),
    ("mieru", "Mieru"),
    ("sudoku", "Sudoku"),
    ("vless-encryption", "VLESS-Encryption"),
    ("shadowquic", "ShadowQUIC"),
    ("anytls-reality", "AnyTLS-Reality"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WrongclSupportLevel {
    Supported,
    Partial,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WrongclMissingField {
    pub field: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WrongclProfileView {
    pub profile: String,
    pub display_name: String,
    pub implemented: bool,
    pub support: WrongclSupportLevel,
    pub active: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrongclCapabilityView {
    pub active_support: WrongclSupportLevel,
    pub active_reason: String,
    pub missing_fields: Vec<WrongclMissingField>,
    pub profiles: Vec<WrongclProfileView>,
    pub config_adaptable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WrongclInspection {
    pub listen: String,
    pub listen_port: u16,
    pub active_profile: String,
    pub payload_networks: Vec<PayloadNetworkId>,
    pub base_carriers: Vec<crate::BaseCarrierId>,
    pub active_support: WrongclSupportLevel,
    pub active_reason: String,
    pub missing_fields: Vec<WrongclMissingField>,
    pub profiles: Vec<WrongclProfileView>,
    #[serde(skip_serializing)]
    pub config_adaptable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrongclAdaptPlan {
    pub inspection: WrongclInspection,
    pub draft_config: Option<WrongclClientConfigDocument>,
    pub strict_config: Option<WrongclClientConfigDocument>,
}

pub fn build_wrongcl_capability_view(
    config: &ImportConfig,
    resolution: &ImportResolutionHint,
) -> WrongclCapabilityView {
    let active_profile = resolution.active_profile.as_str();
    let active_implemented = wrongcl_profile_implemented(active_profile);
    if !active_implemented {
        let reason = "recognized wrongsv server capability; client transport not implemented yet"
            .to_string();
        return WrongclCapabilityView {
            active_support: WrongclSupportLevel::Unsupported,
            active_reason: reason.clone(),
            missing_fields: Vec::new(),
            profiles: KNOWN_WRONGCL_PROFILES
                .iter()
                .map(|(profile, display_name)| {
                    let implemented = wrongcl_profile_implemented(profile);
                    let support = wrongcl_profile_support_level(profile);
                    let active = *profile == active_profile;
                    WrongclProfileView {
                        profile: (*profile).to_string(),
                        display_name: (*display_name).to_string(),
                        implemented,
                        support: if active {
                            WrongclSupportLevel::Unsupported
                        } else {
                            support
                        },
                        active,
                        reason: if active {
                            reason.clone()
                        } else {
                            wrongcl_support_reason(profile, support)
                        },
                    }
                })
                .collect(),
            config_adaptable: false,
        };
    }

    let missing_fields = wrongcl_missing_fields(config, active_profile);
    let mut blockers = Vec::new();
    let mut config_adaptable = missing_fields.is_empty();

    if !missing_fields.is_empty() {
        blockers.push(missing_fields_summary(&missing_fields));
        config_adaptable = false;
    }

    if let Some(reason) =
        wrongcl_local_runtime_gap_reason(config, active_profile, &resolution.payload_networks)
    {
        blockers.push(reason);
        config_adaptable = false;
    }

    let active_support = if blockers.is_empty() {
        WrongclSupportLevel::Supported
    } else {
        WrongclSupportLevel::Partial
    };
    let active_reason = if blockers.is_empty() {
        let proxy_mode = if resolution.payload_networks.contains(&PayloadNetworkId::Udp) {
            "TCP/UDP"
        } else {
            "TCP"
        };
        format!(
            "{}; local wrongcl {proxy_mode} proxying is available for this config",
            wrongcl_stack_label(active_profile)
        )
    } else {
        blockers.join("; ")
    };

    WrongclCapabilityView {
        active_support,
        active_reason: active_reason.clone(),
        missing_fields,
        profiles: KNOWN_WRONGCL_PROFILES
            .iter()
            .map(|(profile, display_name)| {
                let implemented = wrongcl_profile_implemented(profile);
                let support = if *profile == active_profile {
                    active_support
                } else {
                    wrongcl_profile_support_level(profile)
                };
                let active = *profile == active_profile;
                WrongclProfileView {
                    profile: (*profile).to_string(),
                    display_name: (*display_name).to_string(),
                    implemented,
                    support,
                    active,
                    reason: if active {
                        active_reason.clone()
                    } else {
                        wrongcl_support_reason(profile, support)
                    },
                }
            })
            .collect(),
        config_adaptable,
    }
}

pub fn build_wrongcl_inspection(
    config: &ImportConfig,
    resolution: &ImportResolutionHint,
) -> WrongclInspection {
    let view = build_wrongcl_capability_view(config, resolution);
    WrongclInspection {
        listen: config.listen.clone(),
        listen_port: parse_listen_port(&config.listen).unwrap_or(0),
        active_profile: resolution.active_profile.clone(),
        payload_networks: resolution.payload_networks.clone(),
        base_carriers: resolution.base_carriers.clone(),
        active_support: view.active_support,
        active_reason: view.active_reason,
        missing_fields: view.missing_fields,
        profiles: view.profiles,
        config_adaptable: view.config_adaptable,
    }
}

pub fn build_wrongcl_adapt_plan(
    config: &ImportConfig,
    resolution: &ImportResolutionHint,
    server_host: &str,
    listen_host: &str,
    listen_port: u16,
) -> Result<WrongclAdaptPlan, String> {
    let inspection = build_wrongcl_inspection(config, resolution);
    let active_profile_implemented = inspection
        .profiles
        .iter()
        .any(|profile| profile.active && profile.implemented);
    let draft_config = if active_profile_implemented {
        build_wrongcl_import_spec(config, &resolution.active_profile, server_host, true)
            .ok()
            .map(|spec| {
                build_wrongcl_client_config_document(&spec, server_host, listen_host, listen_port)
            })
    } else {
        None
    };
    let strict_config = if inspection.config_adaptable {
        Some(build_wrongcl_client_config_document(
            &build_wrongcl_import_spec(config, &resolution.active_profile, server_host, false)?,
            server_host,
            listen_host,
            listen_port,
        ))
    } else {
        None
    };
    Ok(WrongclAdaptPlan {
        inspection,
        draft_config,
        strict_config,
    })
}

fn wrongcl_profile_implemented(profile: &str) -> bool {
    matches!(
        profile,
        "raw"
            | "tls"
            | "reality"
            | "anytls"
            | "shadowtls"
            | "hysteria2"
            | "tuic"
            | "quic"
            | "kcp"
            | "meek"
            | "gdocsviewer"
            | "webtransport"
            | "websocket"
            | "httpupgrade"
            | "xhttp"
            | "grpc"
            | "trojan"
            | "mixed"
            | "shadowsocks"
            | "wireguard"
            | "naive"
            | "snell"
            | "lua"
            | "masque"
            | "trusttunnel"
            | "brook"
            | "vlite"
            | "tor"
            | "ssh"
            | "juicity"
            | "mieru"
            | "sudoku"
            | "vless-encryption"
            | "shadowquic"
            | "anytls-reality"
    )
}

fn wrongcl_profile_support_level(profile: &str) -> WrongclSupportLevel {
    match profile {
        "raw" | "tls" | "reality" | "anytls" | "shadowtls" | "hysteria2" | "tuic" | "quic"
        | "kcp" | "meek" | "gdocsviewer" | "webtransport" | "websocket" | "httpupgrade"
        | "xhttp" | "grpc" | "trojan" | "mixed" | "shadowsocks" | "wireguard" | "naive"
        | "snell" | "lua" | "masque" | "trusttunnel" | "brook" | "vlite" | "tor" | "ssh"
        | "juicity" | "mieru" | "sudoku" | "vless-encryption" | "shadowquic" | "anytls-reality" => {
            WrongclSupportLevel::Supported
        }
        _ => WrongclSupportLevel::Unsupported,
    }
}

fn wrongcl_support_reason(profile: &str, support: WrongclSupportLevel) -> String {
    if matches!(support, WrongclSupportLevel::Unsupported) {
        return "recognized wrongsv server capability; client transport not implemented yet".into();
    }
    match profile {
        "raw" => "VLESS over raw TCP; full support when the active config is TCP-only".into(),
        "tls" => {
            "VLESS over raw TCP wrapped by TLS; full support when the active config is TCP-only"
                .into()
        }
        "reality" => "VLESS over REALITY; full support when the client public-key is supplied or derivable from the server private-key".into(),
        "anytls" => {
            "VLESS over AnyTLS; full support when the active config is TCP-only and not using Vision"
                .into()
        }
        "shadowtls" => "VLESS over ShadowTLS with TCP and UDP".into(),
        "hysteria2" => "Hysteria2 over QUIC/TLS with TCP and UDP".into(),
        "tuic" => "TUIC over QUIC/TLS with TCP and UDP".into(),
        "quic" => "VLESS over QUIC with TCP and UDP".into(),
        "kcp" => "VLESS over KCP; full support when the active config is TCP-only".into(),
        "meek" => "VLESS over Meek with TCP and UDP".into(),
        "gdocsviewer" => "VLESS over Google Docs Viewer with TCP and UDP".into(),
        "webtransport" => "VLESS over WebTransport with TCP and UDP".into(),
        "naive" => "Naive over HTTP/2 CONNECT over TLS with TCP".into(),
        "snell" => "Snell v1 TCP CONNECT over raw TCP".into(),
        "wireguard" => "WireGuard tunnel service; full support when the client peer private-key is supplied".into(),
        "websocket" => {
            "VLESS over WebSocket; full support when the active config is TCP-only and not using Vision"
                .into()
        }
        "httpupgrade" => "VLESS over HTTPUpgrade with TCP and UDP".into(),
        "xhttp" => "VLESS over XHTTP with TCP and UDP".into(),
        "grpc" => "VLESS over gRPC with TCP and UDP".into(),
        "trojan" => "Trojan over TLS with TCP and UDP".into(),
        "mixed" => "remote SOCKS5 or HTTP CONNECT proxy over raw TCP".into(),
        "shadowsocks" => "Shadowsocks over raw TCP with TCP and UDP".into(),
        "lua" => "Lua configuration scripting over TCP".into(),
        "masque" => "Masque TCP/UDP tunneling over QUIC/TLS".into(),
        "trusttunnel" => "TrustTunnel secure TCP tunneling".into(),
        "brook" => "Brook TCP/UDP proxying over raw TCP".into(),
        "vlite" => "Vlite TCP/UDP proxying over raw TCP".into(),
        "tor" => "Tor obfs4/meek bridge proxy entry over TCP".into(),
        "ssh" => "SSH tunneling over raw TCP".into(),
        "juicity" => "Juicity TCP/UDP tunneling over QUIC/TLS".into(),
        "mieru" => "Mieru TCP/UDP proxying over raw TCP".into(),
        "sudoku" => "Sudoku obfuscated TCP proxying".into(),
        "vless-encryption" => "VLESS-Encryption secure TCP proxying".into(),
        "shadowquic" => "ShadowQUIC TCP/UDP tunneling over QUIC/TLS".into(),
        "anytls-reality" => "AnyTLS-Reality TCP proxying over REALITY/TLS".into(),
        _ => "implemented in part, but not yet available as a complete wrongcl local-proxy stack"
            .into(),
    }
}

fn wrongcl_missing_fields(config: &ImportConfig, profile: &str) -> Vec<WrongclMissingField> {
    match profile {
        "reality" => {
            let missing_public_key = config.reality.as_ref().is_none_or(|reality| {
                let has_public_key = reality
                    .public_key
                    .as_ref()
                    .is_some_and(|key| !key.trim().is_empty());
                let has_private_key = reality
                    .private_key
                    .as_ref()
                    .is_some_and(|key| !key.trim().is_empty());
                !has_public_key && !has_private_key
            });
            if missing_public_key {
                vec![WrongclMissingField {
                    field: "reality.public-key".into(),
                    reason: "wrongcl needs a REALITY public-key, or a server private-key it can derive one from".into(),
                }]
            } else {
                Vec::new()
            }
        }
        "wireguard" => {
            let missing_private_key = config
                .wireguard
                .as_ref()
                .and_then(|wireguard| wireguard.peers.first())
                .and_then(|peer| peer.private_key.as_ref())
                .is_none_or(|key| key.trim().is_empty());
            if missing_private_key {
                vec![WrongclMissingField {
                    field: "wireguard.peers.private-key".into(),
                    reason: "wrongcl needs the WireGuard client peer private-key".into(),
                }]
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

fn missing_fields_summary(fields: &[WrongclMissingField]) -> String {
    let names = fields
        .iter()
        .map(|field| field.field.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    format!("missing client-side fields: {names}")
}

fn wrongcl_local_runtime_gap_reason(
    config: &ImportConfig,
    profile: &str,
    payload_networks: &[PayloadNetworkId],
) -> Option<String> {
    if profile == "hysteria2"
        && config
            .hysteria2
            .as_ref()
            .and_then(|hysteria2| hysteria2.obfs.as_ref())
            .is_some()
    {
        return Some(
            "wrongcl Hysteria2 packet obfuscation variants are not implemented yet".into(),
        );
    }

    if payload_networks.contains(&PayloadNetworkId::Udp) {
        match profile {
            "raw" | "tls" | "anytls" | "shadowtls" | "reality" | "hysteria2" | "tuic" | "quic"
            | "meek" | "gdocsviewer" | "webtransport" | "websocket" | "httpupgrade" | "xhttp"
            | "grpc" | "trojan" | "shadowsocks" => None,
            _ => Some("wrongcl UDP relay is still being built out for this protocol family".into()),
        }
    } else if payload_networks.contains(&PayloadNetworkId::Ip) && profile != "wireguard" {
        Some("wrongcl has no TUN or routed-tunnel runtime yet".into())
    } else {
        None
    }
}

fn wrongcl_stack_label(profile: &str) -> &'static str {
    match profile {
        "raw" => "VLESS over raw TCP",
        "tls" => "VLESS over TLS",
        "reality" => "VLESS over REALITY",
        "anytls" => "VLESS over AnyTLS",
        "shadowtls" => "VLESS over ShadowTLS",
        "hysteria2" => "Hysteria2",
        "tuic" => "TUIC",
        "quic" => "VLESS over QUIC",
        "kcp" => "VLESS over KCP",
        "meek" => "VLESS over Meek",
        "gdocsviewer" => "VLESS over Google Docs Viewer",
        "webtransport" => "VLESS over WebTransport",
        "naive" => "Naive",
        "wireguard" => "WireGuard",
        "websocket" => "VLESS over WebSocket",
        "httpupgrade" => "VLESS over HTTPUpgrade",
        "xhttp" => "VLESS over XHTTP",
        "grpc" => "VLESS over gRPC",
        "trojan" => "Trojan over TLS",
        "mixed" => "remote mixed proxy",
        "shadowsocks" => "Shadowsocks",
        _ => "wrongsv profile",
    }
}

fn parse_listen_port(listen: &str) -> Option<u16> {
    listen.rsplit_once(':')?.1.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import_config::{ImportConfig, import_resolution_hint};

    #[test]
    fn wrongcl_capability_view_marks_vmess_as_unsupported() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[vmess]
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Unsupported);
        assert!(!view.config_adaptable);
        assert!(view.active_reason.contains("not implemented"));
    }

    #[test]
    fn wrongcl_capability_view_reports_missing_reality_public_key() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[reality]
short_ids = ["aaaaaaaa"]
dest = "www.microsoft.com:443"
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Partial);
        assert!(!view.config_adaptable);
        assert_eq!(view.missing_fields.len(), 1);
        assert_eq!(view.missing_fields[0].field, "reality.public-key");
        assert!(view.active_reason.contains("missing client-side fields"));
    }

    #[test]
    fn wrongcl_capability_view_marks_reality_private_key_as_supported() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[reality]
private_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
short_ids = ["aaaaaaaa"]
dest = "www.microsoft.com:443"
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Supported);
        assert!(view.config_adaptable);
        assert!(view.missing_fields.is_empty());
        assert!(view.active_reason.contains("VLESS over REALITY"));
    }

    #[test]
    fn wrongcl_capability_view_marks_shadowtls_as_supported() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[shadowtls]
password = "shadow-pass"
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Supported);
        assert!(view.config_adaptable);
        assert!(view.missing_fields.is_empty());
        assert!(view.active_reason.contains("ShadowTLS"));
    }

    #[test]
    fn wrongcl_capability_view_marks_hysteria2_as_supported() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[hysteria2]
password = "secret"
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Supported);
        assert!(view.config_adaptable);
        assert!(view.missing_fields.is_empty());
        assert!(view.active_reason.contains("Hysteria2"));
    }

    #[test]
    fn wrongcl_capability_view_marks_webtransport_as_supported() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[webtransport]
path = "/wt"
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Supported);
        assert!(view.config_adaptable);
        assert!(view.missing_fields.is_empty());
        assert!(view.active_reason.contains("WebTransport"));
    }

    #[test]
    fn wrongcl_capability_view_marks_meek_as_supported() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[meek]
path = "/meek"
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Supported);
        assert!(view.config_adaptable);
        assert!(view.missing_fields.is_empty());
        assert!(view.active_reason.contains("Meek"));
    }

    #[test]
    fn wrongcl_capability_view_marks_naive_as_supported() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[naive]
padding_header_name = "Padding"

[naive.tls]
dest = "cover.example:443"

[[naive.users]]
username = "alice"
password = "secret"
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Supported);
        assert!(view.config_adaptable);
        assert!(view.missing_fields.is_empty());
        assert!(view.active_reason.contains("Naive"));
    }

    #[test]
    fn wrongcl_capability_view_marks_gdocsviewer_as_supported() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[gdocsviewer]
path_prefix = "/gdocsviewer"
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Supported);
        assert!(view.config_adaptable);
        assert!(view.missing_fields.is_empty());
        assert!(view.active_reason.contains("Google Docs Viewer"));
    }

    #[test]
    fn wrongcl_capability_view_marks_wireguard_as_partial() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:51820"

[wireguard]
private_key = "EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10="
server_cidrs = ["10.77.0.1/32"]
outbound = true

[[wireguard.peers]]
public_key = "MmLJ5iHFVVBp7VsB0hxfpQ0wEzAbT2KQnpQpj0+RtBw="
allowed_ips = ["10.77.0.2/32"]
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Partial);
        assert!(!view.config_adaptable);
        assert_eq!(view.missing_fields.len(), 1);
        assert_eq!(view.missing_fields[0].field, "wireguard.peers.private-key");
        assert!(view.active_reason.contains("missing client-side fields"));
    }

    #[test]
    fn wrongcl_capability_view_marks_wireguard_with_peer_private_key_as_supported() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:51820"

[wireguard]
private_key = "gJ2bkwJoR/mZyVVzv9VWQ3t+yZ6R37/C5VXhaOSUgWI="
server_cidrs = ["10.66.66.1/32"]

[[wireguard.peers]]
private_key = "6D5AXLjT/KiUZxP92lk9B1zlf7R9x2Xp5a04FdknUEI="
public_key = "mvBoFRzzhoWrCZC9nQkrr57AG6oY03qzZ3+kDVumBG8="
allowed_ips = ["10.66.66.2/32"]

[[wireguard.forwards]]
service = "10.66.66.1:8080"
target = "127.0.0.1:3300"
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Supported);
        assert!(view.config_adaptable);
        assert!(view.missing_fields.is_empty());
        assert!(view.active_reason.contains("local wrongcl TCP proxying"));
    }

    #[test]
    fn wrongcl_capability_view_marks_hysteria2_obfs_as_partial() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[hysteria2]
password = "secret"

[hysteria2.obfs]
type = "salamander"
password = "obfs-secret"
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Partial);
        assert!(!view.config_adaptable);
        assert!(
            view.active_reason.contains("packet obfuscation"),
            "{}",
            view.active_reason
        );
    }

    #[test]
    fn wrongcl_capability_view_marks_tuic_as_supported() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[tuic]

[[tuic.users]]
uuid = "12345678-1234-1234-1234-123456789abc"
password = "tuic-pass"
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Supported);
        assert!(view.config_adaptable);
        assert!(view.missing_fields.is_empty());
        assert!(view.active_reason.contains("TUIC"));
    }

    #[test]
    fn wrongcl_capability_view_marks_quic_as_supported() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[quic]
udp_relay = true
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let view = build_wrongcl_capability_view(&config, &resolution);
        assert_eq!(view.active_support, WrongclSupportLevel::Supported);
        assert!(view.config_adaptable);
        assert!(view.missing_fields.is_empty());
        assert!(view.active_reason.contains("QUIC"));
    }

    #[test]
    fn wrongcl_adapt_plan_builds_draft_without_strict_spec_for_missing_reality_public_key() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[reality]
short_ids = ["aaaaaaaa"]
dest = "www.microsoft.com:443"
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let plan =
            build_wrongcl_adapt_plan(&config, &resolution, "wrong.example", "127.0.0.1", 1080)
                .unwrap();
        assert_eq!(plan.inspection.active_profile, "reality");
        assert!(!plan.inspection.config_adaptable);
        assert!(plan.draft_config.is_some());
        assert!(plan.strict_config.is_none());
    }
}
