#![allow(dead_code)]

use std::path::Path;

use serde::Serialize;

mod client_config;
mod endpoint;
mod import_config;
mod wrongcl_result;
mod wrongcl_support;

#[cfg(test)]
pub(crate) use endpoint::EndpointProfile as Transport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientFormat {
    Mihomo,
    SingBox,
    Xray,
    Hiddify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PayloadNetworkId {
    Tcp,
    Udp,
    Ip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaseCarrierId {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EndpointInspection {
    pub active_profile: String,
    pub payload_networks: Vec<PayloadNetworkId>,
    pub base_carriers: Vec<BaseCarrierId>,
    pub stack_summary: String,
}

pub use import_config::{
    ImportAnyTlsConfig, ImportConfig, ImportGrpcConfig, ImportHttpUpgradeConfig, ImportMixedConfig,
    ImportRealityConfig, ImportResolutionHint, ImportShadowsocksConfig, ImportSnellConfig,
    ImportTlsConfig, ImportTrojanConfig, ImportTrojanUser, ImportUser, ImportWebSocketConfig,
    ImportXhttpConfig, WrongclClientConfigDocument, WrongclImportSpec, WrongclLocalConfigDocument,
    WrongclOuterSecurityDocument, WrongclOuterSecuritySpec, WrongclProxyDocument, WrongclProxySpec,
    WrongclServerConfigDocument, WrongclTransportDocument, WrongclTransportSpec, active_profile_id,
    build_wrongcl_client_config_document, build_wrongcl_import_spec, import_resolution_hint,
    load_import_config_path,
};
pub use wrongcl_result::{WrongclAdaptResultDocument, build_wrongcl_adapt_result};
pub use wrongcl_support::{
    WrongclAdaptPlan, WrongclCapabilityView, WrongclInspection, WrongclMissingField,
    WrongclProfileView, WrongclSupportLevel, build_wrongcl_adapt_plan,
    build_wrongcl_capability_view, build_wrongcl_inspection,
};

pub fn inspect_server_config_path(path: impl AsRef<Path>) -> Result<EndpointInspection, String> {
    let config_path = path.as_ref();
    let config_path = config_path
        .to_str()
        .ok_or_else(|| format!("config path is not valid UTF-8: {}", config_path.display()))?;
    let values = client_config::resolve_client_values(Some(config_path), None, "YOUR_SNI");
    let active_profile = resolved_active_profile_id(values.endpoint.clone());
    let diagnostics = client_config::build_endpoint_diagnostics(&values, None);
    Ok(EndpointInspection {
        active_profile,
        payload_networks: diagnostics
            .resolved
            .payload_networks
            .into_iter()
            .map(map_payload_network)
            .collect(),
        base_carriers: diagnostics
            .resolved
            .base_carriers
            .into_iter()
            .map(map_base_carrier)
            .collect(),
        stack_summary: diagnostics.resolved.stack_summary,
    })
}

fn resolved_active_profile_id(model: endpoint::EndpointModel) -> String {
    use endpoint::{Component, OuterSecurity, ProxyProtocol, TransportMethod};

    match model.protocol {
        ProxyProtocol::Vless => {
            if model.outer_security == Some(OuterSecurity::Reality) {
                "reality"
            } else if model.components.contains(Component::AnyTls) {
                "anytls"
            } else {
                match model.transport {
                    Some(TransportMethod::WebSocket) => "websocket",
                    Some(TransportMethod::HttpUpgrade) => "httpupgrade",
                    Some(TransportMethod::Grpc) => "grpc",
                    Some(TransportMethod::Xhttp) => "xhttp",
                    Some(TransportMethod::Meek) => "meek",
                    Some(TransportMethod::GdocsViewer) => "gdocsviewer",
                    Some(TransportMethod::Quic) => "quic",
                    Some(TransportMethod::Kcp) => "kcp",
                    Some(TransportMethod::WebTransport) => "webtransport",
                    Some(TransportMethod::Raw)
                        if model.outer_security == Some(OuterSecurity::Tls) =>
                    {
                        "tls"
                    }
                    _ => "raw",
                }
            }
        }
        ProxyProtocol::Vmess => "vmess",
        ProxyProtocol::Shadowsocks => "shadowsocks",
        ProxyProtocol::Trojan => "trojan",
        ProxyProtocol::Hysteria2 => "hysteria2",
        ProxyProtocol::Tuic => "tuic",
        ProxyProtocol::Mixed => "mixed",
        ProxyProtocol::WireGuard => "wireguard",
        ProxyProtocol::Naive => "naive",
        ProxyProtocol::Snell => "snell",
    }
    .to_string()
}

fn map_payload_network(payload: endpoint::PayloadNetwork) -> PayloadNetworkId {
    match payload {
        endpoint::PayloadNetwork::Tcp => PayloadNetworkId::Tcp,
        endpoint::PayloadNetwork::Udp => PayloadNetworkId::Udp,
        endpoint::PayloadNetwork::Ip => PayloadNetworkId::Ip,
    }
}

fn map_base_carrier(carrier: endpoint::BaseCarrier) -> BaseCarrierId {
    match carrier {
        endpoint::BaseCarrier::Tcp => BaseCarrierId::Tcp,
        endpoint::BaseCarrier::Udp => BaseCarrierId::Udp,
    }
}
