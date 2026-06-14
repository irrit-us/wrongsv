use serde::Serialize;

use crate::endpoint::model::{
    BaseCarrier, Component, EndpointComponents, EndpointModel, OuterSecurity, PayloadNetwork,
    ProtocolInternalSecurity, ProxyProtocol, TransportMethod,
};

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LayerMode {
    Selectable,
    Required,
    Optional,
    Fixed,
    Forbidden,
    BackendDefined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct LayerDescriptor<T: Copy + 'static> {
    pub mode: LayerMode,
    pub supported: &'static [T],
    pub default: Option<T>,
    pub fixed_value: Option<T>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct PayloadDescriptor {
    pub supported: &'static [PayloadNetwork],
    pub default: &'static [PayloadNetwork],
    pub user_configurable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct ComponentDescriptorSet {
    pub camouflage: &'static [Component],
    pub ingress: &'static [Component],
    pub performance: &'static [Component],
    pub network: &'static [Component],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct ProtocolDescriptor {
    pub id: ProxyProtocol,
    pub display_name: &'static str,
    pub payload_networks: PayloadDescriptor,
    pub transport: LayerDescriptor<TransportMethod>,
    pub outer_security: LayerDescriptor<OuterSecurity>,
    pub protocol_internal_security: Option<ProtocolInternalSecurity>,
    pub components: ComponentDescriptorSet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ResolvedEndpoint {
    pub protocol: ProxyProtocol,
    pub payload_networks: Vec<PayloadNetwork>,
    pub protocol_internal_security: Option<ProtocolInternalSecurity>,
    pub transport: Option<TransportMethod>,
    pub outer_security: Option<OuterSecurity>,
    pub base_carriers: Vec<BaseCarrier>,
    pub active_components: EndpointComponents,
    pub stack_summary: String,
}

const VLESS_PAYLOADS: &[PayloadNetwork] = &[PayloadNetwork::Tcp, PayloadNetwork::Udp];
const VMESS_PAYLOADS: &[PayloadNetwork] = &[PayloadNetwork::Tcp];
const SHADOWSOCKS_PAYLOADS: &[PayloadNetwork] = &[PayloadNetwork::Tcp, PayloadNetwork::Udp];
const TROJAN_PAYLOADS: &[PayloadNetwork] = &[PayloadNetwork::Tcp, PayloadNetwork::Udp];
const HYSTERIA2_PAYLOADS: &[PayloadNetwork] = &[PayloadNetwork::Tcp, PayloadNetwork::Udp];
const TUIC_PAYLOADS: &[PayloadNetwork] = &[PayloadNetwork::Tcp, PayloadNetwork::Udp];
const MIXED_PAYLOADS: &[PayloadNetwork] = &[PayloadNetwork::Tcp];
const WIREGUARD_PAYLOADS: &[PayloadNetwork] = &[PayloadNetwork::Ip];
const NAIVE_PAYLOADS: &[PayloadNetwork] = &[PayloadNetwork::Tcp];
const VLESS_CAMOUFLAGE_COMPONENTS: &[Component] = &[Component::AnyTls, Component::ShadowTls];
const VLESS_PERFORMANCE_COMPONENTS: &[Component] = &[Component::Vision];
const VLESS_INGRESS_COMPONENTS: &[Component] = &[Component::FallbackDestination];
const TROJAN_INGRESS_COMPONENTS: &[Component] = &[Component::FallbackDestination];
const HYSTERIA2_CAMOUFLAGE_COMPONENTS: &[Component] =
    &[Component::HysteriaSalamander, Component::HysteriaGecko];
const HYSTERIA2_INGRESS_COMPONENTS: &[Component] = &[Component::FallbackDestination];
const TUIC_INGRESS_COMPONENTS: &[Component] = &[Component::FallbackDestination];
const WIREGUARD_NETWORK_COMPONENTS: &[Component] = &[Component::RoutedTunnel];
const NAIVE_CAMOUFLAGE_COMPONENTS: &[Component] = &[Component::NaivePadding];
const NAIVE_INGRESS_COMPONENTS: &[Component] = &[Component::FallbackDestination];
const EMPTY_COMPONENTS: &[Component] = &[];
const VLESS_TRANSPORTS: &[TransportMethod] = &[
    TransportMethod::Raw,
    TransportMethod::WebSocket,
    TransportMethod::HttpUpgrade,
    TransportMethod::Grpc,
    TransportMethod::Xhttp,
    TransportMethod::Meek,
    TransportMethod::GdocsViewer,
    TransportMethod::Quic,
    TransportMethod::Kcp,
    TransportMethod::WebTransport,
];
const VLESS_SECURITIES: &[OuterSecurity] = &[OuterSecurity::Tls, OuterSecurity::Reality];

pub(crate) fn protocol_descriptor(protocol: ProxyProtocol) -> &'static ProtocolDescriptor {
    match protocol {
        ProxyProtocol::Vless => &ProtocolDescriptor {
            id: ProxyProtocol::Vless,
            display_name: "VLESS",
            payload_networks: PayloadDescriptor {
                supported: VLESS_PAYLOADS,
                default: VLESS_PAYLOADS,
                user_configurable: true,
            },
            transport: LayerDescriptor {
                mode: LayerMode::Selectable,
                supported: VLESS_TRANSPORTS,
                default: Some(TransportMethod::Raw),
                fixed_value: None,
            },
            outer_security: LayerDescriptor {
                mode: LayerMode::Optional,
                supported: VLESS_SECURITIES,
                default: None,
                fixed_value: None,
            },
            protocol_internal_security: None,
            components: ComponentDescriptorSet {
                camouflage: VLESS_CAMOUFLAGE_COMPONENTS,
                ingress: VLESS_INGRESS_COMPONENTS,
                performance: VLESS_PERFORMANCE_COMPONENTS,
                network: EMPTY_COMPONENTS,
            },
        },
        ProxyProtocol::Vmess => &ProtocolDescriptor {
            id: ProxyProtocol::Vmess,
            display_name: "VMess",
            payload_networks: PayloadDescriptor {
                supported: VMESS_PAYLOADS,
                default: VMESS_PAYLOADS,
                user_configurable: false,
            },
            transport: LayerDescriptor {
                mode: LayerMode::BackendDefined,
                supported: &[],
                default: None,
                fixed_value: None,
            },
            outer_security: LayerDescriptor {
                mode: LayerMode::Forbidden,
                supported: &[],
                default: None,
                fixed_value: None,
            },
            protocol_internal_security: Some(ProtocolInternalSecurity::VmessAead),
            components: ComponentDescriptorSet {
                camouflage: EMPTY_COMPONENTS,
                ingress: EMPTY_COMPONENTS,
                performance: EMPTY_COMPONENTS,
                network: EMPTY_COMPONENTS,
            },
        },
        ProxyProtocol::Shadowsocks => &ProtocolDescriptor {
            id: ProxyProtocol::Shadowsocks,
            display_name: "Shadowsocks",
            payload_networks: PayloadDescriptor {
                supported: SHADOWSOCKS_PAYLOADS,
                default: SHADOWSOCKS_PAYLOADS,
                user_configurable: true,
            },
            transport: LayerDescriptor {
                mode: LayerMode::Fixed,
                supported: &[TransportMethod::Raw],
                default: Some(TransportMethod::Raw),
                fixed_value: Some(TransportMethod::Raw),
            },
            outer_security: LayerDescriptor {
                mode: LayerMode::Forbidden,
                supported: &[],
                default: None,
                fixed_value: None,
            },
            protocol_internal_security: Some(ProtocolInternalSecurity::ShadowsocksAead),
            components: ComponentDescriptorSet {
                camouflage: EMPTY_COMPONENTS,
                ingress: EMPTY_COMPONENTS,
                performance: EMPTY_COMPONENTS,
                network: EMPTY_COMPONENTS,
            },
        },
        ProxyProtocol::Trojan => &ProtocolDescriptor {
            id: ProxyProtocol::Trojan,
            display_name: "Trojan",
            payload_networks: PayloadDescriptor {
                supported: TROJAN_PAYLOADS,
                default: TROJAN_PAYLOADS,
                user_configurable: true,
            },
            transport: LayerDescriptor {
                mode: LayerMode::Fixed,
                supported: &[TransportMethod::Raw],
                default: Some(TransportMethod::Raw),
                fixed_value: Some(TransportMethod::Raw),
            },
            outer_security: LayerDescriptor {
                mode: LayerMode::Fixed,
                supported: &[OuterSecurity::Tls],
                default: Some(OuterSecurity::Tls),
                fixed_value: Some(OuterSecurity::Tls),
            },
            protocol_internal_security: None,
            components: ComponentDescriptorSet {
                camouflage: EMPTY_COMPONENTS,
                ingress: TROJAN_INGRESS_COMPONENTS,
                performance: EMPTY_COMPONENTS,
                network: EMPTY_COMPONENTS,
            },
        },
        ProxyProtocol::Hysteria2 => &ProtocolDescriptor {
            id: ProxyProtocol::Hysteria2,
            display_name: "Hysteria2",
            payload_networks: PayloadDescriptor {
                supported: HYSTERIA2_PAYLOADS,
                default: HYSTERIA2_PAYLOADS,
                user_configurable: true,
            },
            transport: LayerDescriptor {
                mode: LayerMode::Fixed,
                supported: &[TransportMethod::Quic],
                default: Some(TransportMethod::Quic),
                fixed_value: Some(TransportMethod::Quic),
            },
            outer_security: LayerDescriptor {
                mode: LayerMode::Fixed,
                supported: &[OuterSecurity::Tls],
                default: Some(OuterSecurity::Tls),
                fixed_value: Some(OuterSecurity::Tls),
            },
            protocol_internal_security: None,
            components: ComponentDescriptorSet {
                camouflage: HYSTERIA2_CAMOUFLAGE_COMPONENTS,
                ingress: HYSTERIA2_INGRESS_COMPONENTS,
                performance: EMPTY_COMPONENTS,
                network: EMPTY_COMPONENTS,
            },
        },
        ProxyProtocol::Tuic => &ProtocolDescriptor {
            id: ProxyProtocol::Tuic,
            display_name: "TUIC",
            payload_networks: PayloadDescriptor {
                supported: TUIC_PAYLOADS,
                default: TUIC_PAYLOADS,
                user_configurable: true,
            },
            transport: LayerDescriptor {
                mode: LayerMode::Fixed,
                supported: &[TransportMethod::Quic],
                default: Some(TransportMethod::Quic),
                fixed_value: Some(TransportMethod::Quic),
            },
            outer_security: LayerDescriptor {
                mode: LayerMode::Fixed,
                supported: &[OuterSecurity::Tls],
                default: Some(OuterSecurity::Tls),
                fixed_value: Some(OuterSecurity::Tls),
            },
            protocol_internal_security: None,
            components: ComponentDescriptorSet {
                camouflage: EMPTY_COMPONENTS,
                ingress: TUIC_INGRESS_COMPONENTS,
                performance: EMPTY_COMPONENTS,
                network: EMPTY_COMPONENTS,
            },
        },
        ProxyProtocol::Mixed => &ProtocolDescriptor {
            id: ProxyProtocol::Mixed,
            display_name: "Mixed",
            payload_networks: PayloadDescriptor {
                supported: MIXED_PAYLOADS,
                default: MIXED_PAYLOADS,
                user_configurable: false,
            },
            transport: LayerDescriptor {
                mode: LayerMode::Forbidden,
                supported: &[],
                default: None,
                fixed_value: None,
            },
            outer_security: LayerDescriptor {
                mode: LayerMode::Forbidden,
                supported: &[],
                default: None,
                fixed_value: None,
            },
            protocol_internal_security: None,
            components: ComponentDescriptorSet {
                camouflage: EMPTY_COMPONENTS,
                ingress: EMPTY_COMPONENTS,
                performance: EMPTY_COMPONENTS,
                network: EMPTY_COMPONENTS,
            },
        },
        ProxyProtocol::WireGuard => &ProtocolDescriptor {
            id: ProxyProtocol::WireGuard,
            display_name: "WireGuard",
            payload_networks: PayloadDescriptor {
                supported: WIREGUARD_PAYLOADS,
                default: WIREGUARD_PAYLOADS,
                user_configurable: false,
            },
            transport: LayerDescriptor {
                mode: LayerMode::Forbidden,
                supported: &[],
                default: None,
                fixed_value: None,
            },
            outer_security: LayerDescriptor {
                mode: LayerMode::Forbidden,
                supported: &[],
                default: None,
                fixed_value: None,
            },
            protocol_internal_security: Some(ProtocolInternalSecurity::WireGuardNoise),
            components: ComponentDescriptorSet {
                camouflage: EMPTY_COMPONENTS,
                ingress: EMPTY_COMPONENTS,
                performance: EMPTY_COMPONENTS,
                network: WIREGUARD_NETWORK_COMPONENTS,
            },
        },
        ProxyProtocol::Naive => &ProtocolDescriptor {
            id: ProxyProtocol::Naive,
            display_name: "Naive",
            payload_networks: PayloadDescriptor {
                supported: NAIVE_PAYLOADS,
                default: NAIVE_PAYLOADS,
                user_configurable: false,
            },
            transport: LayerDescriptor {
                mode: LayerMode::Fixed,
                supported: &[TransportMethod::H2Connect],
                default: Some(TransportMethod::H2Connect),
                fixed_value: Some(TransportMethod::H2Connect),
            },
            outer_security: LayerDescriptor {
                mode: LayerMode::Fixed,
                supported: &[OuterSecurity::Tls],
                default: Some(OuterSecurity::Tls),
                fixed_value: Some(OuterSecurity::Tls),
            },
            protocol_internal_security: None,
            components: ComponentDescriptorSet {
                camouflage: NAIVE_CAMOUFLAGE_COMPONENTS,
                ingress: NAIVE_INGRESS_COMPONENTS,
                performance: EMPTY_COMPONENTS,
                network: EMPTY_COMPONENTS,
            },
        },
    }
}

pub(crate) fn resolve_endpoint(model: &EndpointModel) -> ResolvedEndpoint {
    let descriptor = protocol_descriptor(model.protocol);
    let transport = model.transport;
    let outer_security = model.outer_security;
    let stack_summary = build_stack_summary(model, descriptor.display_name);

    ResolvedEndpoint {
        protocol: model.protocol,
        payload_networks: model.payload_networks.clone(),
        protocol_internal_security: model.protocol_internal_security,
        transport,
        outer_security,
        base_carriers: model.base_carriers.clone(),
        active_components: model.components.clone(),
        stack_summary,
    }
}

fn build_stack_summary(model: &EndpointModel, display_name: &str) -> String {
    let mut layers = Vec::new();
    layers.push(format!(
        "Payload {}",
        payloads_label(&model.payload_networks)
    ));
    layers.push(display_name.to_string());
    if let Some(transport) = model.transport {
        layers.push(transport_label(transport).to_string());
    }
    if let Some(security) = model.outer_security {
        layers.push(outer_security_label(security).to_string());
    }
    layers.push(base_carriers_label(&model.base_carriers));
    layers.join(" -> ")
}

fn payloads_label(payloads: &[PayloadNetwork]) -> String {
    payloads
        .iter()
        .map(|payload| match payload {
            PayloadNetwork::Tcp => "TCP",
            PayloadNetwork::Udp => "UDP",
            PayloadNetwork::Ip => "IP",
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn transport_label(transport: TransportMethod) -> &'static str {
    match transport {
        TransportMethod::Raw => "RAW",
        TransportMethod::WebSocket => "WebSocket",
        TransportMethod::HttpUpgrade => "HTTPUpgrade",
        TransportMethod::Grpc => "gRPC",
        TransportMethod::Xhttp => "XHTTP",
        TransportMethod::Meek => "Meek",
        TransportMethod::GdocsViewer => "Google Docs Viewer",
        TransportMethod::Quic => "QUIC",
        TransportMethod::Kcp => "KCP",
        TransportMethod::WebTransport => "WebTransport",
        TransportMethod::H2Connect => "H/2 CONNECT",
    }
}

fn outer_security_label(security: OuterSecurity) -> &'static str {
    match security {
        OuterSecurity::Tls => "TLS",
        OuterSecurity::Reality => "REALITY",
    }
}

fn base_carriers_label(carriers: &[BaseCarrier]) -> String {
    carriers
        .iter()
        .map(|carrier| match carrier {
            BaseCarrier::Tcp => "TCP",
            BaseCarrier::Udp => "UDP",
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::model::Component;

    #[test]
    fn wireguard_descriptor_matches_spec_shape() {
        let descriptor = protocol_descriptor(ProxyProtocol::WireGuard);
        assert_eq!(descriptor.display_name, "WireGuard");
        assert_eq!(descriptor.payload_networks.default, WIREGUARD_PAYLOADS);
        assert_eq!(descriptor.transport.mode, LayerMode::Forbidden);
        assert_eq!(
            descriptor.protocol_internal_security,
            Some(ProtocolInternalSecurity::WireGuardNoise)
        );
        assert_eq!(descriptor.components.network, WIREGUARD_NETWORK_COMPONENTS);
    }

    #[test]
    fn vless_descriptor_declares_component_categories() {
        let descriptor = protocol_descriptor(ProxyProtocol::Vless);
        assert_eq!(descriptor.transport.default, Some(TransportMethod::Raw));
        assert_eq!(descriptor.outer_security.mode, LayerMode::Optional);
        assert_eq!(
            descriptor.components.camouflage,
            VLESS_CAMOUFLAGE_COMPONENTS
        );
        assert_eq!(
            descriptor.components.performance,
            VLESS_PERFORMANCE_COMPONENTS
        );
        assert_eq!(descriptor.components.ingress, VLESS_INGRESS_COMPONENTS);
        assert!(descriptor.components.network.is_empty());
    }

    #[test]
    fn resolved_stack_summary_lists_layers_in_order() {
        let model = EndpointModel::from_profile(
            crate::Transport::WebSocket,
            Some(OuterSecurity::Tls),
            "xtls-rprx-vision",
        );
        let resolved = resolve_endpoint(&model);
        assert_eq!(
            resolved.stack_summary,
            "Payload TCP -> VLESS -> WebSocket -> TLS -> TCP"
        );
    }

    #[test]
    fn resolved_stack_summary_for_wireguard_uses_ip_and_udp() {
        let model = EndpointModel::from_profile(crate::Transport::WireGuard, None, "");
        let resolved = resolve_endpoint(&model);
        assert_eq!(resolved.stack_summary, "Payload IP -> WireGuard -> UDP");
    }

    #[test]
    fn resolved_stack_summary_for_raw_vless_includes_raw_transport() {
        let model = EndpointModel::from_profile(crate::Transport::Raw, None, "");
        let resolved = resolve_endpoint(&model);
        assert_eq!(
            resolved.stack_summary,
            "Payload TCP/UDP -> VLESS -> RAW -> TCP"
        );
    }

    #[test]
    fn component_flags_are_preserved_in_resolved_endpoint() {
        let mut model = EndpointModel::from_profile(
            crate::Transport::ShadowTls,
            Some(OuterSecurity::Tls),
            "xtls-rprx-vision",
        );
        model.components.ingress.push(Component::ShadowTls);
        let resolved = resolve_endpoint(&model);
        assert!(
            resolved
                .active_components
                .camouflage
                .contains(&Component::ShadowTls)
        );
        assert!(
            resolved
                .active_components
                .ingress
                .contains(&Component::ShadowTls)
        );
    }
}
