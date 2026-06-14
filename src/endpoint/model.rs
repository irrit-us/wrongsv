use serde::Serialize;

use crate::endpoint::EndpointProfile as Transport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum ProxyProtocol {
    #[serde(rename = "vless")]
    Vless,
    #[serde(rename = "vmess")]
    Vmess,
    #[serde(rename = "shadowsocks")]
    Shadowsocks,
    #[serde(rename = "trojan")]
    Trojan,
    #[serde(rename = "hysteria2")]
    Hysteria2,
    #[serde(rename = "tuic")]
    Tuic,
    #[serde(rename = "mixed")]
    Mixed,
    #[serde(rename = "wireguard")]
    WireGuard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum PayloadNetwork {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
    #[serde(rename = "ip")]
    Ip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum TransportMethod {
    #[serde(rename = "raw")]
    Raw,
    #[serde(rename = "websocket")]
    WebSocket,
    #[serde(rename = "httpupgrade")]
    HttpUpgrade,
    #[serde(rename = "grpc")]
    Grpc,
    #[serde(rename = "xhttp")]
    Xhttp,
    #[serde(rename = "meek")]
    Meek,
    #[serde(rename = "gdocsviewer")]
    GdocsViewer,
    #[serde(rename = "quic")]
    Quic,
    #[serde(rename = "kcp")]
    Kcp,
    #[serde(rename = "webtransport")]
    WebTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum OuterSecurity {
    #[serde(rename = "tls")]
    Tls,
    #[serde(rename = "reality")]
    Reality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum ProtocolInternalSecurity {
    #[serde(rename = "vmess_aead")]
    VmessAead,
    #[serde(rename = "shadowsocks_aead")]
    ShadowsocksAead,
    #[serde(rename = "shadowsocks_2022")]
    Shadowsocks2022Aead,
    #[serde(rename = "wireguard_noise")]
    WireGuardNoise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum BaseCarrier {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum Component {
    #[serde(rename = "vision")]
    Vision,
    #[serde(rename = "anytls")]
    AnyTls,
    #[serde(rename = "shadowtls")]
    ShadowTls,
    #[serde(rename = "salamander")]
    Salamander,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub(crate) struct EndpointComponents {
    pub camouflage: Vec<Component>,
    pub ingress: Vec<Component>,
    pub performance: Vec<Component>,
    pub network: Vec<Component>,
}

impl EndpointComponents {
    pub(crate) fn contains(&self, component: Component) -> bool {
        self.camouflage.contains(&component)
            || self.ingress.contains(&component)
            || self.performance.contains(&component)
            || self.network.contains(&component)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointModel {
    pub protocol: ProxyProtocol,
    pub payload_networks: Vec<PayloadNetwork>,
    pub transport: Option<TransportMethod>,
    pub outer_security: Option<OuterSecurity>,
    pub protocol_internal_security: Option<ProtocolInternalSecurity>,
    pub base_carriers: Vec<BaseCarrier>,
    pub components: EndpointComponents,
}

impl EndpointModel {
    pub(crate) fn from_profile(
        profile: Transport,
        transport_outer_security: Option<OuterSecurity>,
        flow: &str,
    ) -> Self {
        let vision_enabled = flow == "xtls-rprx-vision";

        match profile {
            Transport::Vmess => EndpointModel {
                protocol: ProxyProtocol::Vmess,
                payload_networks: vec![PayloadNetwork::Tcp],
                transport: None,
                outer_security: None,
                protocol_internal_security: Some(ProtocolInternalSecurity::VmessAead),
                base_carriers: vec![BaseCarrier::Tcp],
                components: EndpointComponents::default(),
            },
            Transport::WireGuard => EndpointModel {
                protocol: ProxyProtocol::WireGuard,
                payload_networks: vec![PayloadNetwork::Ip],
                transport: None,
                outer_security: None,
                protocol_internal_security: Some(ProtocolInternalSecurity::WireGuardNoise),
                base_carriers: vec![BaseCarrier::Udp],
                components: EndpointComponents::default(),
            },
            Transport::Shadowsocks => EndpointModel {
                protocol: ProxyProtocol::Shadowsocks,
                payload_networks: vec![PayloadNetwork::Tcp, PayloadNetwork::Udp],
                transport: Some(TransportMethod::Raw),
                outer_security: None,
                protocol_internal_security: Some(ProtocolInternalSecurity::ShadowsocksAead),
                base_carriers: vec![BaseCarrier::Tcp, BaseCarrier::Udp],
                components: EndpointComponents::default(),
            },
            Transport::Trojan => EndpointModel {
                protocol: ProxyProtocol::Trojan,
                payload_networks: vec![PayloadNetwork::Tcp, PayloadNetwork::Udp],
                transport: Some(TransportMethod::Raw),
                outer_security: Some(OuterSecurity::Tls),
                protocol_internal_security: None,
                base_carriers: vec![BaseCarrier::Tcp],
                components: EndpointComponents::default(),
            },
            Transport::Hysteria2 => EndpointModel {
                protocol: ProxyProtocol::Hysteria2,
                payload_networks: vec![PayloadNetwork::Tcp, PayloadNetwork::Udp],
                transport: Some(TransportMethod::Quic),
                outer_security: Some(OuterSecurity::Tls),
                protocol_internal_security: None,
                base_carriers: vec![BaseCarrier::Udp],
                components: EndpointComponents::default(),
            },
            Transport::Tuic => EndpointModel {
                protocol: ProxyProtocol::Tuic,
                payload_networks: vec![PayloadNetwork::Tcp, PayloadNetwork::Udp],
                transport: Some(TransportMethod::Quic),
                outer_security: Some(OuterSecurity::Tls),
                protocol_internal_security: None,
                base_carriers: vec![BaseCarrier::Udp],
                components: EndpointComponents::default(),
            },
            Transport::Mixed => EndpointModel {
                protocol: ProxyProtocol::Mixed,
                payload_networks: vec![PayloadNetwork::Tcp],
                transport: None,
                outer_security: None,
                protocol_internal_security: None,
                base_carriers: vec![BaseCarrier::Tcp],
                components: EndpointComponents::default(),
            },
            Transport::Reality => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::Raw),
                Some(OuterSecurity::Reality),
                vec![BaseCarrier::Tcp],
                EndpointComponents::default(),
            ),
            Transport::AnyTls => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::Raw),
                Some(OuterSecurity::Tls),
                vec![BaseCarrier::Tcp],
                EndpointComponents {
                    camouflage: vec![Component::AnyTls],
                    ..EndpointComponents::default()
                },
            ),
            Transport::Tls => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::Raw),
                Some(OuterSecurity::Tls),
                vec![BaseCarrier::Tcp],
                EndpointComponents::default(),
            ),
            Transport::Raw => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::Raw),
                None,
                vec![BaseCarrier::Tcp],
                EndpointComponents::default(),
            ),
            Transport::WebSocket => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::WebSocket),
                transport_outer_security,
                vec![BaseCarrier::Tcp],
                EndpointComponents::default(),
            ),
            Transport::HttpUpgrade => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::HttpUpgrade),
                transport_outer_security,
                vec![BaseCarrier::Tcp],
                EndpointComponents::default(),
            ),
            Transport::Grpc => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::Grpc),
                transport_outer_security,
                vec![BaseCarrier::Tcp],
                EndpointComponents::default(),
            ),
            Transport::Xhttp => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::Xhttp),
                transport_outer_security,
                vec![BaseCarrier::Tcp],
                EndpointComponents::default(),
            ),
            Transport::Meek => Self::vless_model(
                false,
                Some(TransportMethod::Meek),
                transport_outer_security,
                vec![BaseCarrier::Tcp],
                EndpointComponents::default(),
            ),
            Transport::GdocsViewer => Self::vless_model(
                false,
                Some(TransportMethod::GdocsViewer),
                transport_outer_security,
                vec![BaseCarrier::Tcp],
                EndpointComponents::default(),
            ),
            Transport::Quic => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::Quic),
                Some(OuterSecurity::Tls),
                vec![BaseCarrier::Udp],
                EndpointComponents::default(),
            ),
            Transport::Kcp => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::Kcp),
                None,
                vec![BaseCarrier::Udp],
                EndpointComponents::default(),
            ),
            Transport::WebTransport => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::WebTransport),
                Some(OuterSecurity::Tls),
                vec![BaseCarrier::Udp],
                EndpointComponents::default(),
            ),
            Transport::ShadowTls => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::Raw),
                Some(OuterSecurity::Tls),
                vec![BaseCarrier::Tcp],
                EndpointComponents {
                    camouflage: vec![Component::ShadowTls],
                    ..EndpointComponents::default()
                },
            ),
        }
    }

    fn vless_model(
        vision_enabled: bool,
        transport: Option<TransportMethod>,
        outer_security: Option<OuterSecurity>,
        base_carriers: Vec<BaseCarrier>,
        mut components: EndpointComponents,
    ) -> Self {
        if vision_enabled {
            components.performance.push(Component::Vision);
        }
        EndpointModel {
            protocol: ProxyProtocol::Vless,
            payload_networks: if vision_enabled {
                vec![PayloadNetwork::Tcp]
            } else {
                vec![PayloadNetwork::Tcp, PayloadNetwork::Udp]
            },
            transport,
            outer_security,
            protocol_internal_security: None,
            base_carriers,
            components,
        }
    }

    pub(crate) fn has_component(&self, component: Component) -> bool {
        self.components.contains(component)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_vless_uses_tcp_without_outer_security() {
        let model = EndpointModel::from_profile(Transport::Raw, None, "");
        assert_eq!(model.protocol, ProxyProtocol::Vless);
        assert_eq!(model.base_carriers, vec![BaseCarrier::Tcp]);
        assert_eq!(model.transport, Some(TransportMethod::Raw));
        assert_eq!(model.outer_security, None);
        assert_eq!(model.payload_networks, vec![PayloadNetwork::Tcp, PayloadNetwork::Udp]);
    }

    #[test]
    fn kcp_vless_uses_udp_base_carrier() {
        let model = EndpointModel::from_profile(Transport::Kcp, None, "");
        assert_eq!(model.transport, Some(TransportMethod::Kcp));
        assert_eq!(model.base_carriers, vec![BaseCarrier::Udp]);
        assert_eq!(model.outer_security, None);
    }

    #[test]
    fn wireguard_exposes_ip_payloads() {
        let model = EndpointModel::from_profile(Transport::WireGuard, None, "");
        assert_eq!(model.protocol, ProxyProtocol::WireGuard);
        assert_eq!(model.protocol_internal_security, Some(ProtocolInternalSecurity::WireGuardNoise));
        assert_eq!(model.payload_networks, vec![PayloadNetwork::Ip]);
        assert_eq!(model.base_carriers, vec![BaseCarrier::Udp]);
    }

    #[test]
    fn vision_becomes_performance_component_and_removes_udp() {
        let model = EndpointModel::from_profile(
            Transport::Reality,
            Some(OuterSecurity::Reality),
            "xtls-rprx-vision",
        );
        assert!(model.has_component(Component::Vision));
        assert_eq!(model.payload_networks, vec![PayloadNetwork::Tcp]);
    }

    #[test]
    fn component_contains_checks_network_bucket() {
        let mut components = EndpointComponents::default();
        components.network.push(Component::ShadowTls);
        assert!(components.contains(Component::ShadowTls));
    }
}
