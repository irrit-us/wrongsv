use crate::endpoint::{
    detect_profile, resolve_outer_security, Component, EndpointModel, EndpointProfile as Transport,
    OuterSecurity, PayloadNetwork, ProxyProtocol, TransportMethod,
};

#[derive(Debug, Clone)]
pub(crate) struct ClientConfigValues {
    pub endpoint: EndpointModel,
    pub uuid: String,
    pub flow: String,
    pub port: String,
    pub short_id: String,
    pub x25519_pk: String,
    pub servername: String,
    pub ws_path: String,
    pub grpc_service_name: String,
    pub kcp_seed: String,
    pub kcp_mtu: u16,
    pub kcp_tti: u16,
    pub xhttp_path: String,
    pub xhttp_host: String,
    pub shadowtls_password: String,
    pub wireguard_private_key: String,
    pub wireguard_public_key: String,
    pub wireguard_preshared_key: Option<String>,
    pub wireguard_client_ip: String,
    pub wireguard_allowed_ips: Vec<String>,
    pub wireguard_mtu: u32,
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

    let transport = detect_profile(toml_config.as_ref(), transport_override);

    match toml_config {
        Some(ref cfg) => {
            let transport_outer_security = resolve_outer_security(Some(cfg), transport);
            let uuid = match transport {
                Transport::Vmess => cfg
                    .vmess
                    .as_ref()
                    .and_then(|v| v.users.first())
                    .map(|u| u.id.as_str())
                    .unwrap_or(build_uuid()),
                Transport::WireGuard => build_uuid(),
                _ => cfg
                    .users
                    .first()
                    .map(|u| u.id.as_str())
                    .unwrap_or(build_uuid()),
            };
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
            let shadowtls_password = cfg
                .shadowtls
                .as_ref()
                .map(|s| s.password.clone())
                .unwrap_or_default();
            let wireguard_private_key = cfg
                .wireguard
                .as_ref()
                .map(|wg| wg.private_key.clone())
                .unwrap_or_default();
            let wireguard_public_key = cfg
                .wireguard
                .as_ref()
                .and_then(|wg| wg.peers.first())
                .map(|peer| peer.public_key.clone())
                .unwrap_or_default();
            let wireguard_preshared_key = cfg
                .wireguard
                .as_ref()
                .and_then(|wg| wg.peers.first())
                .and_then(|peer| peer.preshared_key.clone());
            let wireguard_client_ip = cfg
                .wireguard
                .as_ref()
                .and_then(|wg| wg.peers.first())
                .and_then(|peer| peer.allowed_ips.first())
                .cloned()
                .unwrap_or_else(|| "10.66.66.2/32".to_string());
            let wireguard_allowed_ips = cfg
                .wireguard
                .as_ref()
                .and_then(|wg| wg.forwards.first())
                .map(|forward| {
                    let service = forward.service.split(':').next().unwrap_or("10.66.66.1");
                    vec![format!("{service}/32")]
                })
                .unwrap_or_else(|| vec!["10.66.66.1/32".to_string()]);
            let wireguard_mtu = cfg
                .wireguard
                .as_ref()
                .map(|wg| wg.mtu)
                .unwrap_or(1400);
            let endpoint =
                EndpointModel::from_profile(transport, transport_outer_security, flow);

            ClientConfigValues {
                endpoint,
                uuid: uuid.to_string(),
                flow: flow.to_string(),
                port: port.to_string(),
                short_id: sid,
                x25519_pk: pk,
                servername,
                ws_path,
                grpc_service_name,
                kcp_seed,
                kcp_mtu,
                kcp_tti,
                xhttp_path,
                xhttp_host,
                shadowtls_password,
                wireguard_private_key,
                wireguard_public_key,
                wireguard_preshared_key,
                wireguard_client_ip,
                wireguard_allowed_ips,
                wireguard_mtu,
            }
        }
        None => ClientConfigValues {
            endpoint: EndpointModel::from_profile(
                transport,
                resolve_outer_security(None, transport),
                "xtls-rprx-vision",
            ),
            uuid: build_uuid().to_string(),
            flow: "xtls-rprx-vision".to_string(),
            port: build_port().to_string(),
            short_id: build_sid().to_string(),
            x25519_pk: build_pk().to_string(),
            servername: servername_override.to_string(),
            ws_path: "/".to_string(),
            grpc_service_name: "GunService".to_string(),
            kcp_seed: String::new(),
            kcp_mtu: 1350,
            kcp_tti: 50,
            xhttp_path: "/xhttp".to_string(),
            xhttp_host: String::new(),
            shadowtls_password: String::new(),
            wireguard_private_key: String::new(),
            wireguard_public_key: String::new(),
            wireguard_preshared_key: None,
            wireguard_client_ip: "10.66.66.2/32".to_string(),
            wireguard_allowed_ips: vec!["10.66.66.1/32".to_string()],
            wireguard_mtu: 1400,
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

impl ClientConfigValues {
    pub(crate) fn protocol(&self) -> ProxyProtocol {
        self.endpoint.protocol
    }

    pub(crate) fn supports_payload(&self, payload: PayloadNetwork) -> bool {
        self.endpoint.payload_networks.contains(&payload)
    }

    pub(crate) fn transport_method(&self) -> Option<TransportMethod> {
        self.endpoint.transport
    }

    pub(crate) fn outer_security(&self) -> Option<OuterSecurity> {
        self.endpoint.outer_security
    }

    pub(crate) fn has_component(&self, component: Component) -> bool {
        self.endpoint.has_component(component)
    }

    pub(crate) fn enabled_payload_network_field(&self) -> Option<&'static str> {
        match (
            self.supports_payload(PayloadNetwork::Tcp),
            self.supports_payload(PayloadNetwork::Udp),
        ) {
            (true, true) => None,
            (true, false) => Some("tcp"),
            (false, true) => Some("udp"),
            _ => None,
        }
    }

    pub(crate) fn udp_packet_encoding(&self) -> Option<&'static str> {
        self.supports_payload(PayloadNetwork::Udp)
            .then_some("packetaddr")
    }
}
