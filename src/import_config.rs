use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{BaseCarrierId, PayloadNetworkId};

#[derive(Debug, Clone, Deserialize)]
pub struct ImportConfig {
    pub listen: String,
    #[serde(default)]
    pub users: Vec<ImportUser>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub tls: Option<ImportTlsConfig>,
    #[serde(default)]
    pub reality: Option<ImportRealityConfig>,
    #[serde(default)]
    pub anytls: Option<ImportAnyTlsConfig>,
    #[serde(default)]
    pub websocket: Option<ImportWebSocketConfig>,
    #[serde(default)]
    pub httpupgrade: Option<ImportHttpUpgradeConfig>,
    #[serde(default)]
    pub grpc: Option<ImportGrpcConfig>,
    #[serde(default)]
    pub xhttp: Option<ImportXhttpConfig>,
    #[serde(default)]
    pub meek: Option<toml::Value>,
    #[serde(default)]
    pub gdocsviewer: Option<toml::Value>,
    #[serde(default)]
    pub quic: Option<toml::Value>,
    #[serde(default)]
    pub kcp: Option<toml::Value>,
    #[serde(default)]
    pub webtransport: Option<toml::Value>,
    #[serde(default)]
    pub shadowtls: Option<ImportShadowTlsConfig>,
    #[serde(default)]
    pub vmess: Option<toml::Value>,
    #[serde(default)]
    pub shadowsocks: Option<ImportShadowsocksConfig>,
    #[serde(default)]
    pub trojan: Option<ImportTrojanConfig>,
    #[serde(default)]
    pub hysteria2: Option<toml::Value>,
    #[serde(default)]
    pub tuic: Option<toml::Value>,
    #[serde(default)]
    pub mixed: Option<ImportMixedConfig>,
    #[serde(default)]
    pub wireguard: Option<toml::Value>,
    #[serde(default)]
    pub naive: Option<toml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportUser {
    pub id: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default = "default_udp")]
    pub udp: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportTlsConfig {
    #[serde(default, alias = "server_name", alias = "server-name", alias = "sni")]
    pub server_name: Option<String>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(
        default,
        alias = "insecure",
        alias = "insecure_skip_verify",
        alias = "insecure-skip-verify"
    )]
    pub insecure: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportRealityConfig {
    #[serde(default, alias = "server_name", alias = "server-name", alias = "sni")]
    pub server_name: Option<String>,
    #[serde(default)]
    pub dest: Option<String>,
    #[serde(
        default,
        alias = "public_key",
        alias = "public-key",
        alias = "publickey"
    )]
    pub public_key: Option<String>,
    #[serde(default, alias = "short_id", alias = "short-id", alias = "shortid")]
    pub short_id: Option<String>,
    #[serde(default, alias = "short_ids", alias = "short-ids")]
    pub short_ids: Option<Vec<String>>,
    #[serde(
        default,
        alias = "raw_pubkey",
        alias = "raw-pubkey",
        alias = "server_pubkey",
        alias = "server-pubkey"
    )]
    pub raw_pubkey: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportAnyTlsConfig {
    pub password: String,
    #[serde(default, alias = "server_name", alias = "server-name", alias = "sni")]
    pub server_name: Option<String>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(
        default,
        alias = "insecure",
        alias = "insecure_skip_verify",
        alias = "insecure-skip-verify"
    )]
    pub insecure: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportShadowTlsConfig {
    pub password: String,
    #[serde(default)]
    pub dest: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportWebSocketConfig {
    #[serde(default = "default_ws_path")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub tls: Option<ImportTlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportHttpUpgradeConfig {
    #[serde(default = "default_hu_path")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub tls: Option<ImportTlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportXhttpConfig {
    #[serde(default = "default_xhttp_path")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub tls: Option<ImportTlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportGrpcConfig {
    #[serde(default, rename = "service_name", alias = "service-name")]
    pub service_name: Option<String>,
    #[serde(default)]
    pub tls: Option<ImportTlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportMixedConfig {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportShadowsocksConfig {
    pub method: String,
    pub password: String,
    #[serde(default = "default_udp")]
    pub udp: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportTrojanConfig {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub users: Vec<ImportTrojanUser>,
    #[serde(default)]
    pub tls: Option<ImportTlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportTrojanUser {
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportResolutionHint {
    pub active_profile: String,
    pub payload_networks: Vec<PayloadNetworkId>,
    pub base_carriers: Vec<BaseCarrierId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrongclImportSpec {
    pub active_profile: String,
    pub listen_port: u16,
    pub proxy: WrongclProxySpec,
    pub transport: WrongclTransportSpec,
    pub outer_security: WrongclOuterSecuritySpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrongclProxySpec {
    Vless {
        uuid: String,
        flow: String,
    },
    Trojan {
        password: String,
    },
    Mixed {
        username: Option<String>,
        password: Option<String>,
    },
    Shadowsocks {
        method: String,
        password: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrongclTransportSpec {
    Raw,
    WebSocket { path: String, host: Option<String> },
    HttpUpgrade { path: String, host: Option<String> },
    Xhttp { path: String, host: Option<String> },
    Grpc { service_name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrongclOuterSecuritySpec {
    None,
    Tls {
        server_name: String,
        insecure_skip_verify: bool,
        alpn: Vec<String>,
    },
    Reality {
        server_name: String,
        public_key: String,
        short_id: String,
        raw_pubkey: String,
    },
    AnyTls {
        server_name: String,
        password: String,
        insecure_skip_verify: bool,
        alpn: Vec<String>,
    },
    ShadowTls {
        server_name: String,
        password: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WrongclClientConfigDocument {
    pub server: WrongclServerConfigDocument,
    pub local: WrongclLocalConfigDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WrongclServerConfigDocument {
    pub host: String,
    pub port: u16,
    #[serde(flatten)]
    pub endpoint: WrongclEndpointDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WrongclLocalConfigDocument {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WrongclEndpointDocument {
    pub proxy: WrongclProxyDocument,
    #[serde(default)]
    pub transport: WrongclTransportDocument,
    #[serde(default, rename = "outer-security")]
    pub outer_security: WrongclOuterSecurityDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum WrongclProxyDocument {
    Vless {
        uuid: String,
        #[serde(default)]
        flow: String,
    },
    Trojan {
        password: String,
    },
    Mixed {
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    Shadowsocks {
        method: String,
        password: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum WrongclTransportDocument {
    #[default]
    Raw,
    Websocket {
        path: String,
        #[serde(default)]
        host: Option<String>,
    },
    Httpupgrade {
        path: String,
        #[serde(default)]
        host: Option<String>,
    },
    Xhttp {
        path: String,
        #[serde(default)]
        host: Option<String>,
    },
    Grpc {
        #[serde(rename = "service-name")]
        service_name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum WrongclOuterSecurityDocument {
    #[default]
    None,
    Tls {
        #[serde(rename = "server-name")]
        server_name: String,
        #[serde(default, rename = "insecure-skip-verify")]
        insecure_skip_verify: bool,
        #[serde(default)]
        alpn: Vec<String>,
    },
    Reality {
        #[serde(rename = "server-name")]
        server_name: String,
        #[serde(rename = "public-key")]
        public_key: String,
        #[serde(rename = "short-id")]
        short_id: String,
        #[serde(default, rename = "raw-pubkey")]
        raw_pubkey: String,
    },
    #[serde(rename = "any-tls")]
    AnyTls {
        #[serde(rename = "server-name")]
        server_name: String,
        password: String,
        #[serde(default, rename = "insecure-skip-verify")]
        insecure_skip_verify: bool,
        #[serde(default)]
        alpn: Vec<String>,
    },
    #[serde(rename = "shadowtls")]
    ShadowTls {
        #[serde(rename = "server-name")]
        server_name: String,
        password: String,
    },
}

pub fn load_import_config_path(path: impl AsRef<Path>) -> Result<ImportConfig, String> {
    let content = fs::read_to_string(path.as_ref())
        .map_err(|error| format!("failed to read config {}: {error}", path.as_ref().display()))?;
    toml::from_str(&content).map_err(|error| error.to_string())
}

pub fn import_resolution_hint(config: &ImportConfig) -> ImportResolutionHint {
    let active_profile = active_profile_id(config).to_string();
    let payload_networks = payload_networks_for(config, &active_profile);
    let base_carriers = base_carriers_for(&active_profile, &payload_networks);
    ImportResolutionHint {
        active_profile,
        payload_networks,
        base_carriers,
    }
}

pub fn build_wrongcl_import_spec(
    config: &ImportConfig,
    profile: &str,
    server_host: &str,
    draft_mode: bool,
) -> Result<WrongclImportSpec, String> {
    let listen_port = parse_listen_port(&config.listen)
        .ok_or_else(|| format!("invalid wrongsv listen: {}", config.listen))?;

    let (proxy, transport, outer_security) = match profile {
        "raw" => (
            vless_proxy_spec(config)?,
            WrongclTransportSpec::Raw,
            WrongclOuterSecuritySpec::None,
        ),
        "tls" => (
            vless_proxy_spec(config)?,
            WrongclTransportSpec::Raw,
            tls_spec(config.tls.as_ref(), server_host),
        ),
        "reality" => (
            vless_proxy_spec(config)?,
            WrongclTransportSpec::Raw,
            reality_spec(config.reality.as_ref(), server_host, draft_mode)?,
        ),
        "anytls" => (
            vless_proxy_spec(config)?,
            WrongclTransportSpec::Raw,
            anytls_spec(config.anytls.as_ref(), server_host)?,
        ),
        "shadowtls" => (
            vless_proxy_spec(config)?,
            WrongclTransportSpec::Raw,
            shadowtls_spec(config.shadowtls.as_ref())?,
        ),
        "websocket" => {
            let websocket = config
                .websocket
                .as_ref()
                .ok_or_else(|| "missing [websocket] table".to_string())?;
            (
                vless_proxy_spec(config)?,
                WrongclTransportSpec::WebSocket {
                    path: websocket.path.clone(),
                    host: websocket.host.clone(),
                },
                websocket
                    .tls
                    .as_ref()
                    .map_or(WrongclOuterSecuritySpec::None, |tls| {
                        tls_spec(Some(tls), server_host)
                    }),
            )
        }
        "httpupgrade" => {
            let httpupgrade = config
                .httpupgrade
                .as_ref()
                .ok_or_else(|| "missing [httpupgrade] table".to_string())?;
            (
                vless_proxy_spec(config)?,
                WrongclTransportSpec::HttpUpgrade {
                    path: httpupgrade.path.clone(),
                    host: httpupgrade.host.clone(),
                },
                httpupgrade
                    .tls
                    .as_ref()
                    .map_or(WrongclOuterSecuritySpec::None, |tls| {
                        tls_spec(Some(tls), server_host)
                    }),
            )
        }
        "xhttp" => {
            let xhttp = config
                .xhttp
                .as_ref()
                .ok_or_else(|| "missing [xhttp] table".to_string())?;
            (
                vless_proxy_spec(config)?,
                WrongclTransportSpec::Xhttp {
                    path: xhttp.path.clone(),
                    host: xhttp.host.clone(),
                },
                xhttp
                    .tls
                    .as_ref()
                    .map_or(WrongclOuterSecuritySpec::None, |tls| {
                        tls_spec(Some(tls), server_host)
                    }),
            )
        }
        "grpc" => {
            let grpc = config
                .grpc
                .as_ref()
                .ok_or_else(|| "missing [grpc] table".to_string())?;
            (
                vless_proxy_spec(config)?,
                WrongclTransportSpec::Grpc {
                    service_name: grpc
                        .service_name
                        .clone()
                        .filter(|value| !value.trim().is_empty())
                        .unwrap_or_else(|| "GunService".to_string()),
                },
                grpc.tls
                    .as_ref()
                    .map_or(WrongclOuterSecuritySpec::None, |tls| {
                        tls_spec(Some(tls), server_host)
                    }),
            )
        }
        "trojan" => (
            trojan_proxy_spec(config)?,
            WrongclTransportSpec::Raw,
            tls_spec(
                config
                    .trojan
                    .as_ref()
                    .and_then(|trojan| trojan.tls.as_ref()),
                server_host,
            ),
        ),
        "mixed" => (
            mixed_proxy_spec(config)?,
            WrongclTransportSpec::Raw,
            WrongclOuterSecuritySpec::None,
        ),
        "shadowsocks" => (
            shadowsocks_proxy_spec(config)?,
            WrongclTransportSpec::Raw,
            WrongclOuterSecuritySpec::None,
        ),
        other => {
            return Err(format!(
                "wrongsv profile '{other}' is recognized but not implemented in wrongcl yet"
            ));
        }
    };

    Ok(WrongclImportSpec {
        active_profile: profile.to_string(),
        listen_port,
        proxy,
        transport,
        outer_security,
    })
}

pub fn build_wrongcl_client_config_document(
    spec: &WrongclImportSpec,
    server_host: &str,
    listen_host: &str,
    listen_port: u16,
) -> WrongclClientConfigDocument {
    WrongclClientConfigDocument {
        server: WrongclServerConfigDocument {
            host: server_host.to_string(),
            port: spec.listen_port,
            endpoint: WrongclEndpointDocument {
                proxy: wrongcl_proxy_document(&spec.proxy),
                transport: wrongcl_transport_document(&spec.transport),
                outer_security: wrongcl_outer_security_document(&spec.outer_security),
            },
        },
        local: WrongclLocalConfigDocument {
            host: listen_host.to_string(),
            port: listen_port,
        },
    }
}

fn default_ws_path() -> String {
    "/".into()
}

fn default_hu_path() -> String {
    "/".into()
}

fn default_xhttp_path() -> String {
    "/xhttp".into()
}

fn default_udp() -> bool {
    true
}

pub fn active_profile_id(config: &ImportConfig) -> &'static str {
    if config.reality.is_some() {
        "reality"
    } else if config.anytls.is_some() {
        "anytls"
    } else if config.websocket.is_some() {
        "websocket"
    } else if config.httpupgrade.is_some() {
        "httpupgrade"
    } else if config.grpc.is_some() {
        "grpc"
    } else if config.xhttp.is_some() {
        "xhttp"
    } else if config.meek.is_some() {
        "meek"
    } else if config.gdocsviewer.is_some() {
        "gdocsviewer"
    } else if config.quic.is_some() {
        "quic"
    } else if config.kcp.is_some() {
        "kcp"
    } else if config.webtransport.is_some() {
        "webtransport"
    } else if config.shadowtls.is_some() {
        "shadowtls"
    } else if config.vmess.is_some() {
        "vmess"
    } else if config.shadowsocks.is_some() {
        "shadowsocks"
    } else if config.trojan.is_some() {
        "trojan"
    } else if config.hysteria2.is_some() {
        "hysteria2"
    } else if config.tuic.is_some() {
        "tuic"
    } else if config.mixed.is_some() {
        "mixed"
    } else if config.wireguard.is_some() {
        "wireguard"
    } else if config.naive.is_some() {
        "naive"
    } else if config.tls.is_some() {
        "tls"
    } else {
        "raw"
    }
}

fn payload_networks_for(config: &ImportConfig, profile: &str) -> Vec<PayloadNetworkId> {
    match profile {
        "mixed" | "vmess" | "naive" => vec![PayloadNetworkId::Tcp],
        "wireguard" => vec![PayloadNetworkId::Ip],
        "shadowsocks" => {
            if config
                .shadowsocks
                .as_ref()
                .map(|options| options.udp)
                .unwrap_or(true)
            {
                vec![PayloadNetworkId::Tcp, PayloadNetworkId::Udp]
            } else {
                vec![PayloadNetworkId::Tcp]
            }
        }
        "trojan" | "hysteria2" | "tuic" => vec![PayloadNetworkId::Tcp, PayloadNetworkId::Udp],
        _ => {
            if active_flow(config) == "xtls-rprx-vision" {
                vec![PayloadNetworkId::Tcp]
            } else if active_user_udp(config) {
                vec![PayloadNetworkId::Tcp, PayloadNetworkId::Udp]
            } else {
                vec![PayloadNetworkId::Tcp]
            }
        }
    }
}

fn base_carriers_for(profile: &str, payload_networks: &[PayloadNetworkId]) -> Vec<BaseCarrierId> {
    match profile {
        "quic" | "kcp" | "webtransport" | "hysteria2" | "tuic" | "wireguard" => {
            vec![BaseCarrierId::Udp]
        }
        "shadowsocks" if payload_networks.contains(&PayloadNetworkId::Udp) => {
            vec![BaseCarrierId::Tcp, BaseCarrierId::Udp]
        }
        _ => vec![BaseCarrierId::Tcp],
    }
}

fn active_user_udp(config: &ImportConfig) -> bool {
    config.users.first().map(|user| user.udp).unwrap_or(true)
}

fn active_flow(config: &ImportConfig) -> &str {
    config
        .users
        .first()
        .map(|user| user.flow.as_str())
        .filter(|flow| !flow.is_empty())
        .or_else(|| config.flow.as_deref().filter(|flow| !flow.is_empty()))
        .unwrap_or("")
}

fn parse_listen_port(listen: &str) -> Option<u16> {
    listen.rsplit_once(':')?.1.parse().ok()
}

fn wrongcl_proxy_document(proxy: &WrongclProxySpec) -> WrongclProxyDocument {
    match proxy {
        WrongclProxySpec::Vless { uuid, flow } => WrongclProxyDocument::Vless {
            uuid: uuid.clone(),
            flow: flow.clone(),
        },
        WrongclProxySpec::Trojan { password } => WrongclProxyDocument::Trojan {
            password: password.clone(),
        },
        WrongclProxySpec::Mixed { username, password } => WrongclProxyDocument::Mixed {
            username: username.clone(),
            password: password.clone(),
        },
        WrongclProxySpec::Shadowsocks { method, password } => WrongclProxyDocument::Shadowsocks {
            method: method.clone(),
            password: password.clone(),
        },
    }
}

fn wrongcl_transport_document(transport: &WrongclTransportSpec) -> WrongclTransportDocument {
    match transport {
        WrongclTransportSpec::Raw => WrongclTransportDocument::Raw,
        WrongclTransportSpec::WebSocket { path, host } => WrongclTransportDocument::Websocket {
            path: path.clone(),
            host: host.clone(),
        },
        WrongclTransportSpec::HttpUpgrade { path, host } => WrongclTransportDocument::Httpupgrade {
            path: path.clone(),
            host: host.clone(),
        },
        WrongclTransportSpec::Xhttp { path, host } => WrongclTransportDocument::Xhttp {
            path: path.clone(),
            host: host.clone(),
        },
        WrongclTransportSpec::Grpc { service_name } => WrongclTransportDocument::Grpc {
            service_name: service_name.clone(),
        },
    }
}

fn wrongcl_outer_security_document(
    outer_security: &WrongclOuterSecuritySpec,
) -> WrongclOuterSecurityDocument {
    match outer_security {
        WrongclOuterSecuritySpec::None => WrongclOuterSecurityDocument::None,
        WrongclOuterSecuritySpec::Tls {
            server_name,
            insecure_skip_verify,
            alpn,
        } => WrongclOuterSecurityDocument::Tls {
            server_name: server_name.clone(),
            insecure_skip_verify: *insecure_skip_verify,
            alpn: alpn.clone(),
        },
        WrongclOuterSecuritySpec::Reality {
            server_name,
            public_key,
            short_id,
            raw_pubkey,
        } => WrongclOuterSecurityDocument::Reality {
            server_name: server_name.clone(),
            public_key: public_key.clone(),
            short_id: short_id.clone(),
            raw_pubkey: raw_pubkey.clone(),
        },
        WrongclOuterSecuritySpec::AnyTls {
            server_name,
            password,
            insecure_skip_verify,
            alpn,
        } => WrongclOuterSecurityDocument::AnyTls {
            server_name: server_name.clone(),
            password: password.clone(),
            insecure_skip_verify: *insecure_skip_verify,
            alpn: alpn.clone(),
        },
        WrongclOuterSecuritySpec::ShadowTls {
            server_name,
            password,
        } => WrongclOuterSecurityDocument::ShadowTls {
            server_name: server_name.clone(),
            password: password.clone(),
        },
    }
}

fn vless_proxy_spec(config: &ImportConfig) -> Result<WrongclProxySpec, String> {
    let user = config
        .users
        .first()
        .ok_or_else(|| "wrongsv config has no [[users]] entry".to_string())?;
    let flow = if user.flow.is_empty() {
        config.flow.clone().unwrap_or_default()
    } else {
        user.flow.clone()
    };
    Ok(WrongclProxySpec::Vless {
        uuid: user.id.clone(),
        flow,
    })
}

fn trojan_proxy_spec(config: &ImportConfig) -> Result<WrongclProxySpec, String> {
    let trojan = config
        .trojan
        .as_ref()
        .ok_or_else(|| "missing [trojan] table".to_string())?;
    let password = trojan
        .password
        .clone()
        .or_else(|| trojan.users.first().map(|user| user.password.clone()))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Trojan requires a password".to_string())?;
    Ok(WrongclProxySpec::Trojan { password })
}

fn mixed_proxy_spec(config: &ImportConfig) -> Result<WrongclProxySpec, String> {
    let mixed = config
        .mixed
        .as_ref()
        .ok_or_else(|| "missing [mixed] table".to_string())?;
    Ok(WrongclProxySpec::Mixed {
        username: mixed.username.clone(),
        password: mixed.password.clone(),
    })
}

fn shadowsocks_proxy_spec(config: &ImportConfig) -> Result<WrongclProxySpec, String> {
    let shadowsocks = config
        .shadowsocks
        .as_ref()
        .ok_or_else(|| "missing [shadowsocks] table".to_string())?;
    Ok(WrongclProxySpec::Shadowsocks {
        method: shadowsocks.method.clone(),
        password: shadowsocks.password.clone(),
    })
}

fn tls_spec(tls: Option<&ImportTlsConfig>, server_host: &str) -> WrongclOuterSecuritySpec {
    let server_name = tls
        .and_then(|item| item.server_name.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| server_host.to_string());
    let alpn = tls.and_then(|item| item.alpn.clone()).unwrap_or_default();
    let insecure_skip_verify = tls.and_then(|item| item.insecure).unwrap_or(false);
    WrongclOuterSecuritySpec::Tls {
        server_name,
        insecure_skip_verify,
        alpn,
    }
}

fn reality_spec(
    reality: Option<&ImportRealityConfig>,
    server_host: &str,
    draft_mode: bool,
) -> Result<WrongclOuterSecuritySpec, String> {
    let reality = reality.ok_or_else(|| "missing [reality] table".to_string())?;
    let server_name = reality
        .server_name
        .clone()
        .or_else(|| reality.dest.clone().map(|dest| host_from_dest(&dest)))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| server_host.to_string());
    let public_key = reality
        .public_key
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| draft_mode.then(String::new))
        .ok_or_else(|| {
            "REALITY [reality].public-key is required (server config holds private_key; client needs the matching public_key)".to_string()
        })?;
    let short_id = reality
        .short_id
        .clone()
        .or_else(|| {
            reality
                .short_ids
                .as_ref()
                .and_then(|list| list.first().cloned())
        })
        .filter(|value| !value.trim().is_empty())
        .or_else(|| draft_mode.then(String::new))
        .ok_or_else(|| "REALITY [reality].short-id is required".to_string())?;
    Ok(WrongclOuterSecuritySpec::Reality {
        server_name,
        public_key,
        short_id,
        raw_pubkey: reality.raw_pubkey.clone().unwrap_or_default(),
    })
}

fn anytls_spec(
    anytls: Option<&ImportAnyTlsConfig>,
    server_host: &str,
) -> Result<WrongclOuterSecuritySpec, String> {
    let anytls = anytls.ok_or_else(|| "missing [anytls] table".to_string())?;
    if anytls.password.trim().is_empty() {
        return Err("AnyTLS [anytls].password is required".to_string());
    }
    Ok(WrongclOuterSecuritySpec::AnyTls {
        server_name: anytls
            .server_name
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| server_host.to_string()),
        password: anytls.password.clone(),
        insecure_skip_verify: anytls.insecure.unwrap_or(true),
        alpn: anytls.alpn.clone().unwrap_or_default(),
    })
}

fn shadowtls_spec(
    shadowtls: Option<&ImportShadowTlsConfig>,
) -> Result<WrongclOuterSecuritySpec, String> {
    let shadowtls = shadowtls.ok_or_else(|| "missing [shadowtls] table".to_string())?;
    if shadowtls.password.trim().is_empty() {
        return Err("ShadowTLS [shadowtls].password is required".to_string());
    }
    Ok(WrongclOuterSecuritySpec::ShadowTls {
        server_name: shadowtls
            .dest
            .as_deref()
            .map(host_from_dest)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "cloudfront.net".to_string()),
        password: shadowtls.password.clone(),
    })
}

fn host_from_dest(dest: &str) -> String {
    dest.rsplit_once(':')
        .map(|(host, _)| host.to_string())
        .unwrap_or_else(|| dest.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_hint_detects_reality_vision_as_tcp_only() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
flow = "xtls-rprx-vision"

[reality]
short_ids = ["aaaaaaaa"]
dest = "www.microsoft.com:443"
"#,
        )
        .unwrap();

        let hint = import_resolution_hint(&config);
        assert_eq!(hint.active_profile, "reality");
        assert_eq!(hint.payload_networks, vec![PayloadNetworkId::Tcp]);
        assert_eq!(hint.base_carriers, vec![BaseCarrierId::Tcp]);
    }

    #[test]
    fn wrongcl_import_spec_builds_reality_draft_without_public_key() {
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

        let spec = build_wrongcl_import_spec(&config, "reality", "wrong.example", true).unwrap();
        assert_eq!(spec.active_profile, "reality");
        assert_eq!(spec.listen_port, 443);
        match spec.proxy {
            WrongclProxySpec::Vless { uuid, flow } => {
                assert_eq!(uuid, "12345678-1234-1234-1234-123456789abc");
                assert_eq!(flow, "");
            }
            other => panic!("unexpected proxy {other:?}"),
        }
        match spec.outer_security {
            WrongclOuterSecuritySpec::Reality {
                server_name,
                public_key,
                short_id,
                raw_pubkey,
            } => {
                assert_eq!(server_name, "www.microsoft.com");
                assert_eq!(public_key, "");
                assert_eq!(short_id, "aaaaaaaa");
                assert_eq!(raw_pubkey, "");
            }
            other => panic!("unexpected outer security {other:?}"),
        }
    }

    #[test]
    fn wrongcl_import_spec_builds_shadowtls_config() {
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

        let spec = build_wrongcl_import_spec(&config, "shadowtls", "wrong.example", false).unwrap();
        assert_eq!(spec.active_profile, "shadowtls");
        assert_eq!(spec.listen_port, 443);
        match spec.outer_security {
            WrongclOuterSecuritySpec::ShadowTls {
                server_name,
                password,
            } => {
                assert_eq!(server_name, "cloudfront.net");
                assert_eq!(password, "shadow-pass");
            }
            other => panic!("unexpected outer security {other:?}"),
        }
    }

    #[test]
    fn wrongcl_client_config_document_matches_wrongcl_json_shape() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[websocket]
path = "/ws"

[websocket.tls]
server_name = "example.com"
"#,
        )
        .unwrap();

        let spec = build_wrongcl_import_spec(&config, "websocket", "wrong.example", false).unwrap();
        let document =
            build_wrongcl_client_config_document(&spec, "wrong.example", "127.0.0.1", 1080);
        let value = serde_json::to_value(document).unwrap();

        assert_eq!(value["server"]["host"], "wrong.example");
        assert_eq!(value["server"]["transport"]["type"], "websocket");
        assert_eq!(value["server"]["outer-security"]["type"], "tls");
        assert_eq!(value["local"]["port"], 1080);
    }
}
