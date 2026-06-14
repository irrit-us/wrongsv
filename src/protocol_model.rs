use serde::Serialize;

use crate::Transport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum ProxyProtocol {
    #[serde(rename = "vless")]
    Vless,
    #[serde(rename = "vmess")]
    Vmess,
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
    pub base_carrier: BaseCarrier,
    pub components: EndpointComponents,
}

impl EndpointModel {
    pub(crate) fn from_transport_profile(
        profile: Transport,
        has_tls: bool,
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
                base_carrier: BaseCarrier::Tcp,
                components: EndpointComponents::default(),
            },
            Transport::WireGuard => EndpointModel {
                protocol: ProxyProtocol::WireGuard,
                payload_networks: vec![PayloadNetwork::Ip],
                transport: None,
                outer_security: None,
                protocol_internal_security: Some(ProtocolInternalSecurity::WireGuardNoise),
                base_carrier: BaseCarrier::Udp,
                components: EndpointComponents::default(),
            },
            Transport::Reality => Self::vless_model(
                vision_enabled,
                None,
                Some(OuterSecurity::Reality),
                BaseCarrier::Tcp,
                EndpointComponents::default(),
            ),
            Transport::AnyTls => Self::vless_model(
                vision_enabled,
                None,
                Some(OuterSecurity::Tls),
                BaseCarrier::Tcp,
                EndpointComponents {
                    camouflage: vec![Component::AnyTls],
                    ..EndpointComponents::default()
                },
            ),
            Transport::Tls => Self::vless_model(
                vision_enabled,
                None,
                Some(OuterSecurity::Tls),
                BaseCarrier::Tcp,
                EndpointComponents::default(),
            ),
            Transport::Raw => Self::vless_model(
                vision_enabled,
                None,
                None,
                BaseCarrier::Tcp,
                EndpointComponents::default(),
            ),
            Transport::WebSocket => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::WebSocket),
                has_tls.then_some(OuterSecurity::Tls),
                BaseCarrier::Tcp,
                EndpointComponents::default(),
            ),
            Transport::HttpUpgrade => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::HttpUpgrade),
                has_tls.then_some(OuterSecurity::Tls),
                BaseCarrier::Tcp,
                EndpointComponents::default(),
            ),
            Transport::Grpc => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::Grpc),
                has_tls.then_some(OuterSecurity::Tls),
                BaseCarrier::Tcp,
                EndpointComponents::default(),
            ),
            Transport::Xhttp => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::Xhttp),
                has_tls.then_some(OuterSecurity::Tls),
                BaseCarrier::Tcp,
                EndpointComponents::default(),
            ),
            Transport::Meek => Self::vless_model(
                false,
                Some(TransportMethod::Meek),
                has_tls.then_some(OuterSecurity::Tls),
                BaseCarrier::Tcp,
                EndpointComponents::default(),
            ),
            Transport::GdocsViewer => Self::vless_model(
                false,
                Some(TransportMethod::GdocsViewer),
                has_tls.then_some(OuterSecurity::Tls),
                BaseCarrier::Tcp,
                EndpointComponents::default(),
            ),
            Transport::Quic => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::Quic),
                Some(OuterSecurity::Tls),
                BaseCarrier::Udp,
                EndpointComponents::default(),
            ),
            Transport::Kcp => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::Kcp),
                None,
                BaseCarrier::Udp,
                EndpointComponents::default(),
            ),
            Transport::WebTransport => Self::vless_model(
                vision_enabled,
                Some(TransportMethod::WebTransport),
                Some(OuterSecurity::Tls),
                BaseCarrier::Udp,
                EndpointComponents::default(),
            ),
            Transport::ShadowTls => Self::vless_model(
                vision_enabled,
                None,
                Some(OuterSecurity::Tls),
                BaseCarrier::Tcp,
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
        base_carrier: BaseCarrier,
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
            base_carrier,
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
        let model = EndpointModel::from_transport_profile(Transport::Raw, false, "");
        assert_eq!(model.protocol, ProxyProtocol::Vless);
        assert_eq!(model.base_carrier, BaseCarrier::Tcp);
        assert_eq!(model.transport, None);
        assert_eq!(model.outer_security, None);
        assert_eq!(model.payload_networks, vec![PayloadNetwork::Tcp, PayloadNetwork::Udp]);
    }

    #[test]
    fn kcp_vless_uses_udp_base_carrier() {
        let model = EndpointModel::from_transport_profile(Transport::Kcp, false, "");
        assert_eq!(model.transport, Some(TransportMethod::Kcp));
        assert_eq!(model.base_carrier, BaseCarrier::Udp);
        assert_eq!(model.outer_security, None);
    }

    #[test]
    fn wireguard_exposes_ip_payloads() {
        let model = EndpointModel::from_transport_profile(Transport::WireGuard, false, "");
        assert_eq!(model.protocol, ProxyProtocol::WireGuard);
        assert_eq!(model.protocol_internal_security, Some(ProtocolInternalSecurity::WireGuardNoise));
        assert_eq!(model.payload_networks, vec![PayloadNetwork::Ip]);
        assert_eq!(model.base_carrier, BaseCarrier::Udp);
    }

    #[test]
    fn vision_becomes_performance_component_and_removes_udp() {
        let model =
            EndpointModel::from_transport_profile(Transport::Reality, true, "xtls-rprx-vision");
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
