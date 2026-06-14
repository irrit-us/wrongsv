use clap::ValueEnum;
use serde::Serialize;

use crate::endpoint::OuterSecurity;

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
    /// WireGuard tunnel service
    #[clap(name = "wireguard")]
    WireGuard,
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
        Some(config) if config.wireguard.is_some() => EndpointProfile::WireGuard,
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
        | EndpointProfile::ShadowTls => Some(OuterSecurity::Tls),
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
        | EndpointProfile::WireGuard => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
