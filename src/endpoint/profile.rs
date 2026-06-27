use clap::ValueEnum;
use serde::Serialize;

use crate::endpoint::{
    Component, EndpointModel, OuterSecurity, PayloadNetwork, ProtocolInternalSecurity,
};

#[derive(Debug, ValueEnum, Clone, Copy, PartialEq, Eq, Serialize)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum EndpointProfile {
    /// REALITY TLS (X25519 ECDH + HKDF auth)
    Reality,
    /// AnyTLS (SHA-256 password auth over TLS)
    #[clap(name = "anytls")]
    AnyTls,
    /// Plain TLS 1.3 (compatible with sing-box/mihomo TLS transport)
    Tls,
    /// Raw TCP (no TLS layer)
    Raw,
    /// WebSocket carrier (optional TLS)
    #[clap(name = "ws")]
    WebSocket,
    /// HTTPUpgrade carrier
    #[clap(name = "httpupgrade")]
    HttpUpgrade,
    /// gRPC carrier (HTTP/2 + gRPC frames)
    #[clap(name = "grpc")]
    Grpc,
    /// XHTTP (SplitHTTP) carrier
    #[clap(name = "xhttp")]
    Xhttp,
    /// Meek request transport
    #[clap(name = "meek")]
    Meek,
    /// Google Docs Viewer request transport
    #[clap(name = "gdocsviewer")]
    GdocsViewer,
    /// QUIC carrier
    #[clap(name = "quic")]
    Quic,
    /// KCP (mKCP) carrier
    #[clap(name = "kcp")]
    Kcp,
    /// WebTransport carrier (HTTP/3)
    #[clap(name = "webtransport")]
    WebTransport,
    /// ShadowTLS (TLS 1.3 + HMAC auth)
    #[clap(name = "shadowtls")]
    ShadowTls,
    /// VMess AEAD (AES-128-GCM encrypted proxy)
    #[clap(name = "vmess")]
    Vmess,
    /// Shadowsocks AEAD / AEAD-2022 inbound
    #[clap(name = "shadowsocks")]
    Shadowsocks,
    /// Trojan over TLS inbound
    #[clap(name = "trojan")]
    Trojan,
    /// Hysteria2 QUIC inbound
    #[clap(name = "hysteria2")]
    Hysteria2,
    /// TUIC QUIC inbound
    #[clap(name = "tuic")]
    Tuic,
    /// Mixed SOCKS4/4A/SOCKS5/HTTP proxy inbound
    #[clap(name = "mixed")]
    Mixed,
    /// WireGuard tunnel service
    #[clap(name = "wireguard")]
    WireGuard,
    /// Naive (padded HTTP/2 CONNECT over TLS) inbound
    #[clap(name = "naive")]
    Naive,
    /// Snell v1 AEAD TCP CONNECT inbound
    #[clap(name = "snell")]
    Snell,
    /// Lua configuration
    #[clap(name = "lua")]
    Lua,
    /// Masque configuration
    #[clap(name = "masque")]
    Masque,
    /// TrustTunnel configuration
    #[clap(name = "trusttunnel")]
    TrustTunnel,
    /// Brook configuration
    #[clap(name = "brook")]
    Brook,
    /// Vlite configuration
    #[clap(name = "vlite")]
    Vlite,
    /// Tor configuration
    #[clap(name = "tor")]
    Tor,
    /// SSH configuration
    #[clap(name = "ssh")]
    Ssh,
    /// Juicity configuration
    #[clap(name = "juicity")]
    Juicity,
    /// Mieru configuration
    #[clap(name = "mieru")]
    Mieru,
    /// Sudoku configuration
    #[clap(name = "sudoku")]
    Sudoku,
    /// VLESS-Encryption configuration
    #[clap(name = "vless-encryption")]
    VlessEncryption,
    /// ShadowQUIC configuration
    #[clap(name = "shadowquic")]
    Shadowquic,
    /// AnyTLS-Reality configuration
    #[clap(name = "anytls-reality")]
    AnytlsReality,
}

pub(crate) fn detect_profile(
    cfg: Option<&wrongsv_server::Config>,
    override_profile: Option<EndpointProfile>,
) -> EndpointProfile {
    override_profile.unwrap_or_else(|| match cfg {
        Some(config) if config.reality.is_some() => EndpointProfile::Reality,
        Some(config) if config.anytls.is_some() => EndpointProfile::AnyTls,
        Some(config) if config.websocket.is_some() => EndpointProfile::WebSocket,
        Some(config) if config.httpupgrade.is_some() => EndpointProfile::HttpUpgrade,
        Some(config) if config.grpc.is_some() => EndpointProfile::Grpc,
        Some(config) if config.xhttp.is_some() => EndpointProfile::Xhttp,
        Some(config) if config.meek.is_some() => EndpointProfile::Meek,
        Some(config) if config.gdocsviewer.is_some() => EndpointProfile::GdocsViewer,
        Some(config) if config.quic.is_some() => EndpointProfile::Quic,
        Some(config) if config.kcp.is_some() => EndpointProfile::Kcp,
        Some(config) if config.webtransport.is_some() => EndpointProfile::WebTransport,
        Some(config) if config.shadowtls.is_some() => EndpointProfile::ShadowTls,
        Some(config) if config.vmess.is_some() => EndpointProfile::Vmess,
        Some(config) if config.shadowsocks.is_some() => EndpointProfile::Shadowsocks,
        Some(config) if config.trojan.is_some() => EndpointProfile::Trojan,
        Some(config) if config.hysteria2.is_some() => EndpointProfile::Hysteria2,
        Some(config) if config.tuic.is_some() => EndpointProfile::Tuic,
        Some(config) if config.mixed.is_some() => EndpointProfile::Mixed,
        Some(config) if config.wireguard.is_some() => EndpointProfile::WireGuard,
        Some(config) if config.naive.is_some() => EndpointProfile::Naive,
        Some(config) if config.snell.is_some() => EndpointProfile::Snell,
        Some(config) if config.lua.is_some() => EndpointProfile::Lua,
        Some(config) if config.masque.is_some() => EndpointProfile::Masque,
        Some(config) if config.trusttunnel.is_some() => EndpointProfile::TrustTunnel,
        Some(config) if config.brook.is_some() => EndpointProfile::Brook,
        Some(config) if config.vlite.is_some() => EndpointProfile::Vlite,
        Some(config) if config.tor.is_some() => EndpointProfile::Tor,
        Some(config) if config.ssh.is_some() => EndpointProfile::Ssh,
        Some(config) if config.juicity.is_some() => EndpointProfile::Juicity,
        Some(config) if config.mieru.is_some() => EndpointProfile::Mieru,
        Some(config) if config.sudoku.is_some() => EndpointProfile::Sudoku,
        Some(config) if config.vless_encryption.is_some() => EndpointProfile::VlessEncryption,
        Some(config) if config.shadowquic.is_some() => EndpointProfile::Shadowquic,
        Some(config) if config.anytls_reality.is_some() => EndpointProfile::AnytlsReality,
        Some(config) if config.tls.is_some() => EndpointProfile::Tls,
        _ => EndpointProfile::Raw,
    })
}

pub(crate) fn resolve_outer_security(
    cfg: Option<&wrongsv_server::Config>,
    profile: EndpointProfile,
) -> Option<OuterSecurity> {
    match profile {
        EndpointProfile::Reality => Some(OuterSecurity::Reality),
        EndpointProfile::AnyTls
        | EndpointProfile::Tls
        | EndpointProfile::Quic
        | EndpointProfile::WebTransport
        | EndpointProfile::ShadowTls
        | EndpointProfile::Trojan
        | EndpointProfile::Hysteria2
        | EndpointProfile::Tuic
        | EndpointProfile::Naive => Some(OuterSecurity::Tls),
        EndpointProfile::WebSocket => cfg
            .and_then(|c| c.websocket.as_ref())
            .and_then(|ws| ws.tls.as_ref())
            .map(|_| OuterSecurity::Tls),
        EndpointProfile::HttpUpgrade => cfg
            .and_then(|c| c.httpupgrade.as_ref())
            .and_then(|httpupgrade| httpupgrade.tls.as_ref())
            .map(|_| OuterSecurity::Tls),
        EndpointProfile::Grpc => cfg
            .and_then(|c| c.grpc.as_ref())
            .and_then(|grpc| grpc.tls.as_ref())
            .map(|_| OuterSecurity::Tls),
        EndpointProfile::Xhttp => cfg
            .and_then(|c| c.xhttp.as_ref())
            .and_then(|xhttp| xhttp.tls.as_ref())
            .map(|_| OuterSecurity::Tls),
        EndpointProfile::Meek => cfg
            .and_then(|c| c.meek.as_ref())
            .and_then(|meek| meek.tls.as_ref())
            .map(|_| OuterSecurity::Tls),
        EndpointProfile::GdocsViewer => cfg
            .and_then(|c| c.gdocsviewer.as_ref())
            .and_then(|gdocs| gdocs.tls.as_ref())
            .map(|_| OuterSecurity::Tls),
        EndpointProfile::Raw
        | EndpointProfile::Kcp
        | EndpointProfile::Vmess
        | EndpointProfile::Shadowsocks
        | EndpointProfile::Snell
        | EndpointProfile::Mixed
        | EndpointProfile::WireGuard
        | EndpointProfile::Lua
        | EndpointProfile::Masque
        | EndpointProfile::TrustTunnel
        | EndpointProfile::Brook
        | EndpointProfile::Vlite
        | EndpointProfile::Tor
        | EndpointProfile::Ssh
        | EndpointProfile::Juicity
        | EndpointProfile::Mieru
        | EndpointProfile::Sudoku
        | EndpointProfile::VlessEncryption
        | EndpointProfile::Shadowquic
        | EndpointProfile::AnytlsReality => None,
    }
}

pub(crate) fn build_endpoint_model(
    cfg: Option<&wrongsv_server::Config>,
    profile: EndpointProfile,
    flow: &str,
) -> EndpointModel {
    let mut model =
        EndpointModel::from_profile(profile, resolve_outer_security(cfg, profile), flow);
    match (cfg, profile) {
        (Some(config), EndpointProfile::Shadowsocks) => {
            if let Some(shadowsocks) = &config.shadowsocks {
                model.protocol_internal_security =
                    Some(if shadowsocks.method.starts_with("2022-") {
                        ProtocolInternalSecurity::Shadowsocks2022Aead
                    } else {
                        ProtocolInternalSecurity::ShadowsocksAead
                    });
                if !shadowsocks.udp {
                    model.payload_networks = vec![PayloadNetwork::Tcp];
                    model.base_carriers = vec![crate::endpoint::BaseCarrier::Tcp];
                }
            }
        }
        (Some(config), EndpointProfile::Hysteria2) => {
            if let Some(hysteria2) = &config.hysteria2 {
                if hysteria2.disable_udp {
                    model.payload_networks = vec![PayloadNetwork::Tcp];
                }
                if let Some(obfs) = &hysteria2.obfs {
                    if obfs.obfs_type == "salamander" {
                        model
                            .components
                            .camouflage
                            .push(Component::HysteriaSalamander);
                    }
                    if obfs.obfs_type == "gecko" {
                        model.components.camouflage.push(Component::HysteriaGecko);
                    }
                }
            }
        }
        (Some(config), EndpointProfile::WireGuard) => {
            if let Some(wireguard) = &config.wireguard
                && wireguard.outbound
            {
                model.components.network.push(Component::RoutedTunnel);
            }
        }
        (Some(_), EndpointProfile::Naive) => {
            model.components.camouflage.push(Component::NaivePadding);
        }
        _ => {}
    }
    if has_configured_fallback_destination(cfg, profile) {
        model
            .components
            .ingress
            .push(Component::FallbackDestination);
    }
    model
}

fn has_configured_fallback_destination(
    cfg: Option<&wrongsv_server::Config>,
    profile: EndpointProfile,
) -> bool {
    let Some(cfg) = cfg else { return false };
    let dest = match profile {
        EndpointProfile::Reality => cfg.reality.as_ref().and_then(|c| c.dest.as_deref()),
        EndpointProfile::AnyTls => cfg.anytls.as_ref().and_then(|c| c.dest.as_deref()),
        EndpointProfile::Tls => cfg.tls.as_ref().and_then(|c| c.dest.as_deref()),
        EndpointProfile::Trojan => cfg.trojan.as_ref().and_then(|c| c.dest.as_deref()),
        EndpointProfile::ShadowTls => cfg.shadowtls.as_ref().and_then(|c| c.dest.as_deref()),
        EndpointProfile::WebSocket => cfg
            .websocket
            .as_ref()
            .and_then(|c| c.tls.as_ref())
            .and_then(|tls| tls.dest.as_deref()),
        EndpointProfile::HttpUpgrade => cfg
            .httpupgrade
            .as_ref()
            .and_then(|c| c.tls.as_ref())
            .and_then(|tls| tls.dest.as_deref()),
        EndpointProfile::Grpc => cfg
            .grpc
            .as_ref()
            .and_then(|c| c.tls.as_ref())
            .and_then(|tls| tls.dest.as_deref()),
        EndpointProfile::Xhttp => cfg
            .xhttp
            .as_ref()
            .and_then(|c| c.tls.as_ref())
            .and_then(|tls| tls.dest.as_deref()),
        EndpointProfile::Meek => cfg
            .meek
            .as_ref()
            .and_then(|c| c.tls.as_ref())
            .and_then(|tls| tls.dest.as_deref()),
        EndpointProfile::GdocsViewer => cfg
            .gdocsviewer
            .as_ref()
            .and_then(|c| c.tls.as_ref())
            .and_then(|tls| tls.dest.as_deref()),
        EndpointProfile::Quic => cfg
            .quic
            .as_ref()
            .and_then(|c| c.tls.as_ref())
            .and_then(|tls| tls.dest.as_deref()),
        EndpointProfile::WebTransport => cfg
            .webtransport
            .as_ref()
            .and_then(|c| c.tls.as_ref())
            .and_then(|tls| tls.dest.as_deref()),
        EndpointProfile::Hysteria2 => cfg
            .hysteria2
            .as_ref()
            .and_then(|c| c.tls.as_ref())
            .and_then(|tls| tls.dest.as_deref()),
        EndpointProfile::Tuic => cfg
            .tuic
            .as_ref()
            .and_then(|c| c.tls.as_ref())
            .and_then(|tls| tls.dest.as_deref()),
        EndpointProfile::Naive => cfg.naive.as_ref().and_then(|c| c.tls.dest.as_deref()),
        EndpointProfile::Raw
        | EndpointProfile::Kcp
        | EndpointProfile::Vmess
        | EndpointProfile::Shadowsocks
        | EndpointProfile::Snell
        | EndpointProfile::Mixed
        | EndpointProfile::WireGuard
        | EndpointProfile::Lua
        | EndpointProfile::Masque
        | EndpointProfile::TrustTunnel
        | EndpointProfile::Brook
        | EndpointProfile::Vlite
        | EndpointProfile::Tor
        | EndpointProfile::Ssh
        | EndpointProfile::Juicity
        | EndpointProfile::Mieru
        | EndpointProfile::Sudoku
        | EndpointProfile::VlessEncryption
        | EndpointProfile::Shadowquic
        | EndpointProfile::AnytlsReality => None,
    };
    dest.is_some_and(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{Component, PayloadNetwork, ProxyProtocol};

    #[test]
    fn detect_profile_prefers_explicit_override() {
        let config: wrongsv_server::Config = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"

[websocket]
path = "/ws"
"#,
        )
        .expect("config should parse");
        assert_eq!(
            detect_profile(Some(&config), Some(EndpointProfile::Grpc)),
            EndpointProfile::Grpc
        );
    }

    #[test]
    fn detect_profile_and_outer_security_for_meek_tls() {
        let config: wrongsv_server::Config = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"

[meek]
path = "/meek"

[meek.tls]
certificate = "cert"
key = "key"
"#,
        )
        .expect("config should parse");
        let profile = detect_profile(Some(&config), None);
        assert_eq!(profile, EndpointProfile::Meek);
        assert_eq!(
            resolve_outer_security(Some(&config), profile),
            Some(OuterSecurity::Tls)
        );
    }

    #[test]
    fn detect_profile_and_build_model_for_hysteria2_salamander() {
        let config: wrongsv_server::Config = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[hysteria2]
password = "secret"
disable_udp = true

[hysteria2.obfs]
type = "salamander"
password = "obfs-secret"
"#,
        )
        .expect("config should parse");
        let profile = detect_profile(Some(&config), None);
        assert_eq!(profile, EndpointProfile::Hysteria2);
        let model = build_endpoint_model(Some(&config), profile, "");
        assert_eq!(model.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(
            model.transport,
            Some(crate::endpoint::TransportMethod::Quic)
        );
        assert_eq!(model.outer_security, Some(OuterSecurity::Tls));
        assert_eq!(model.payload_networks, vec![PayloadNetwork::Tcp]);
        assert!(
            model
                .components
                .camouflage
                .contains(&Component::HysteriaSalamander)
        );
    }

    #[test]
    fn detect_profile_and_build_model_for_hysteria2_gecko() {
        let config: wrongsv_server::Config = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[hysteria2]
password = "secret"

[hysteria2.obfs]
type = "gecko"
password = "obfs-secret"
"#,
        )
        .expect("config should parse");
        let profile = detect_profile(Some(&config), None);
        assert_eq!(profile, EndpointProfile::Hysteria2);
        let model = build_endpoint_model(Some(&config), profile, "");
        assert!(
            model
                .components
                .camouflage
                .contains(&Component::HysteriaGecko)
        );
    }

    #[test]
    fn reality_dest_surfaces_as_fallback_ingress_component() {
        let config: wrongsv_server::Config = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"

[reality]
private_key = "0000000000000000000000000000000000000000000000000000000000000000"
dest = "www.microsoft.com:443"
"#,
        )
        .expect("config should parse");
        let profile = detect_profile(Some(&config), None);
        assert_eq!(profile, EndpointProfile::Reality);
        let model = build_endpoint_model(Some(&config), profile, "");
        assert!(
            model
                .components
                .ingress
                .contains(&Component::FallbackDestination)
        );
    }

    #[test]
    fn websocket_tls_dest_surfaces_as_fallback_ingress_component() {
        let config: wrongsv_server::Config = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"

[websocket]
path = "/ws"

[websocket.tls]
certificate = "cert"
key = "key"
dest = "127.0.0.1:8080"
"#,
        )
        .expect("config should parse");
        let profile = detect_profile(Some(&config), None);
        assert_eq!(profile, EndpointProfile::WebSocket);
        let model = build_endpoint_model(Some(&config), profile, "");
        assert!(
            model
                .components
                .ingress
                .contains(&Component::FallbackDestination)
        );
    }

    #[test]
    fn missing_dest_does_not_surface_fallback_ingress_component() {
        let config: wrongsv_server::Config = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "user@example.com"

[websocket]
path = "/ws"
"#,
        )
        .expect("config should parse");
        let profile = detect_profile(Some(&config), None);
        let model = build_endpoint_model(Some(&config), profile, "");
        assert!(
            !model
                .components
                .ingress
                .contains(&Component::FallbackDestination)
        );
    }

    #[test]
    fn wireguard_outbound_surfaces_routed_tunnel_network_component() {
        let config: wrongsv_server::Config = toml::from_str(
            r#"
listen = "0.0.0.0:51820"

[wireguard]
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
server_cidrs = ["10.0.0.1/24"]
outbound = true

[[wireguard.peers]]
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
allowed_ips = ["10.0.0.2/32"]
"#,
        )
        .expect("config should parse");
        let profile = detect_profile(Some(&config), None);
        assert_eq!(profile, EndpointProfile::WireGuard);
        let model = build_endpoint_model(Some(&config), profile, "");
        assert!(model.components.network.contains(&Component::RoutedTunnel));
    }

    #[test]
    fn wireguard_forwards_mode_omits_routed_tunnel_network_component() {
        let config: wrongsv_server::Config = toml::from_str(
            r#"
listen = "0.0.0.0:51820"

[wireguard]
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
server_cidrs = ["10.0.0.1/24"]

[[wireguard.peers]]
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
allowed_ips = ["10.0.0.2/32"]

[[wireguard.forwards]]
service = "10.0.0.1:80"
target = "127.0.0.1:8080"
"#,
        )
        .expect("config should parse");
        let profile = detect_profile(Some(&config), None);
        assert_eq!(profile, EndpointProfile::WireGuard);
        let model = build_endpoint_model(Some(&config), profile, "");
        assert!(!model.components.network.contains(&Component::RoutedTunnel));
    }

    #[test]
    fn detect_profile_and_build_model_for_naive() {
        let config: wrongsv_server::Config = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[naive]

[naive.tls]
certificate = "cert"
key = "key"

[[naive.users]]
username = "user"
password = "secret"
email = "user@example.com"
"#,
        )
        .expect("config should parse");
        let profile = detect_profile(Some(&config), None);
        assert_eq!(profile, EndpointProfile::Naive);
        assert_eq!(
            resolve_outer_security(Some(&config), profile),
            Some(OuterSecurity::Tls)
        );
        let model = build_endpoint_model(Some(&config), profile, "");
        assert_eq!(model.protocol, ProxyProtocol::Naive);
        assert_eq!(
            model.transport,
            Some(crate::endpoint::TransportMethod::H2Connect)
        );
        assert_eq!(model.outer_security, Some(OuterSecurity::Tls));
        assert_eq!(model.payload_networks, vec![PayloadNetwork::Tcp]);
        assert!(
            model
                .components
                .camouflage
                .contains(&Component::NaivePadding)
        );
    }

    #[test]
    fn naive_dest_surfaces_as_fallback_ingress_component() {
        let config: wrongsv_server::Config = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[naive]

[naive.tls]
certificate = "cert"
key = "key"
dest = "127.0.0.1:8080"

[[naive.users]]
username = "user"
password = "secret"
email = "user@example.com"
"#,
        )
        .expect("config should parse");
        let profile = detect_profile(Some(&config), None);
        assert_eq!(profile, EndpointProfile::Naive);
        let model = build_endpoint_model(Some(&config), profile, "");
        assert!(
            model
                .components
                .ingress
                .contains(&Component::FallbackDestination)
        );
    }
}
