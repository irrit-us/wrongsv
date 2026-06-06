use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Address to listen on, e.g. "0.0.0.0:443"
    pub listen: String,
    /// VLESS users
    #[serde(default)]
    pub users: Vec<UserConfig>,
    /// Optional encryption (base64-encoded key chain)
    #[serde(default)]
    pub decryption: Option<String>,
    /// Global default flow
    #[serde(default)]
    pub flow: Option<String>,
    /// ML-KEM-512 secret key seed (64 bytes, hex-encoded).
    /// When set, the server can decapsulate Kyber-encrypted session keys
    /// carried in client addons.
    #[serde(default)]
    pub kyber_secret_key: Option<String>,
    /// REALITY configuration. When set, TLS REALITY is enabled.
    #[serde(default)]
    pub reality: Option<RealityServerConfig>,
    /// AnyTLS configuration. When set, AnyTLS TLS disguise is enabled.
    #[serde(default)]
    pub anytls: Option<AnyTlsServerConfig>,
    /// Standard TLS configuration. When set, plain TLS 1.3 + VLESS is enabled.
    /// Compatible with clients that support VLESS + tls transport
    /// (sing-box, mihomo/flclash, xray-core).
    #[serde(default)]
    pub tls: Option<TlsServerConfig>,
    /// Shadowsocks AEAD TCP inbound configuration. When set, this listener
    /// accepts Shadowsocks instead of VLESS.
    #[serde(default)]
    pub shadowsocks: Option<ShadowsocksServerConfig>,
    /// Mixed plain proxy inbound configuration. When set, this listener
    /// accepts SOCKS4/4A, SOCKS5 CONNECT, and HTTP forward/CONNECT instead of VLESS.
    #[serde(default)]
    pub mixed: Option<MixedServerConfig>,
}

/// REALITY server-side configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct RealityServerConfig {
    /// X25519 private key (32 bytes, hex-encoded).
    pub private_key: String,
    /// Allowed short IDs (hex-encoded, 8 hex chars = 4 bytes each).
    #[serde(default)]
    pub short_ids: Vec<String>,
    /// Fallback destination for spider mode (e.g. "www.microsoft.com:443").
    #[serde(default)]
    pub dest: Option<String>,
    /// Maximum allowed clock skew in seconds (default 300 = 5 min).
    #[serde(default = "default_max_time_diff")]
    pub max_time_diff: u64,
}

fn default_max_time_diff() -> u64 {
    300
}

/// AnyTLS server-side configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AnyTlsServerConfig {
    /// Password for SHA-256 authentication.
    pub password: String,
    /// Fallback destination for unauthenticated probes (e.g. "127.0.0.1:8080").
    #[serde(default)]
    pub dest: Option<String>,
    /// Optional TLS certificate PEM (self-signed if not provided).
    #[serde(default)]
    pub certificate: Option<String>,
    /// Optional TLS key PEM.
    #[serde(default)]
    pub key: Option<String>,
    /// Optional padding scheme string (same format as anytls-go).
    #[serde(default)]
    pub padding_scheme: Option<String>,
}

/// Standard TLS server-side configuration.
///
/// Enables plain TLS 1.3 + VLESS — compatible with sing-box, mihomo/flclash,
/// and xray-core clients using `tls` transport (not REALITY, not AnyTLS).
#[derive(Debug, Clone, Deserialize)]
pub struct TlsServerConfig {
    /// Optional TLS certificate PEM (self-signed if not provided).
    #[serde(default)]
    pub certificate: Option<String>,
    /// Optional TLS key PEM.
    #[serde(default)]
    pub key: Option<String>,
    /// Fallback destination for probes (optional).
    #[serde(default)]
    pub dest: Option<String>,
}

/// Shadowsocks server-side configuration.
///
/// Supports TCP relay with AEAD methods shared by Shadowsocks, Outline,
/// sing-box, xray-core, mihomo, and GOST clients.
#[derive(Debug, Clone, Deserialize)]
pub struct ShadowsocksServerConfig {
    pub method: String,
    pub password: String,
    #[serde(default = "default_udp")]
    pub udp: bool,
    #[serde(default)]
    pub tcp_prefix: Option<String>,
    #[serde(default)]
    pub udp_prefix: Option<String>,
}

/// Mixed plain proxy server-side configuration.
///
/// Supports SOCKS4/4A, SOCKS5 CONNECT, and HTTP forward/CONNECT. Optional
/// credentials are shared between SOCKS5 username/password auth and HTTP Basic
/// proxy auth; SOCKS4/4A is rejected when credentials are set.
#[derive(Debug, Clone, Deserialize)]
pub struct MixedServerConfig {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    /// UUID string
    pub id: String,
    /// Optional email
    #[serde(default)]
    pub email: String,
    /// Flow: "" or "xtls-rprx-vision"
    #[serde(default)]
    pub flow: String,
    /// Optional per-user encryption
    #[serde(default)]
    pub encryption: String,
    /// Allow UDP command (default true). When false, UDP requests are rejected.
    #[serde(default = "default_udp")]
    pub udp: bool,
}

fn default_udp() -> bool {
    true
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid UUID for user '{0}': {1}")]
    InvalidUuid(String, String),
    #[error("unknown flow '{0}' for user '{1}'")]
    UnknownFlow(String, String),
    #[error("unsupported Shadowsocks method '{0}'")]
    UnsupportedShadowsocksMethod(String),
    #[error("Shadowsocks salt prefixes must be at most 16 bytes")]
    ShadowsocksPrefixTooLong,
    #[error("Shadowsocks inbound cannot be combined with VLESS users")]
    ShadowsocksWithVlessUsers,
    #[error("Shadowsocks inbound cannot be combined with VLESS transport layers")]
    ShadowsocksWithVlessTransport,
    #[error("only one non-VLESS inbound can be configured")]
    MultipleInboundProtocols,
    #[error("mixed inbound cannot be combined with VLESS users")]
    MixedWithVlessUsers,
    #[error("mixed inbound cannot be combined with VLESS transport layers")]
    MixedWithVlessTransport,
    #[error("mixed inbound credentials require both username and password")]
    MixedIncompleteCredentials,
    #[error("mixed inbound credentials must be 1..=255 bytes for SOCKS5 username/password auth")]
    MixedInvalidCredentials,
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        for user in &self.users {
            wrongsv_uuid::Uuid::parse_string(&user.id).map_err(
                |e: wrongsv_uuid::ParseUuidError| {
                    ConfigError::InvalidUuid(user.email.clone(), e.to_string())
                },
            )?;
            if !user.flow.is_empty() && user.flow != "xtls-rprx-vision" {
                return Err(ConfigError::UnknownFlow(
                    user.flow.clone(),
                    user.email.clone(),
                ));
            }
        }
        if self.shadowsocks.is_some() && self.mixed.is_some() {
            return Err(ConfigError::MultipleInboundProtocols);
        }
        if let Some(shadowsocks) = &self.shadowsocks {
            if !self.users.is_empty() {
                return Err(ConfigError::ShadowsocksWithVlessUsers);
            }
            if self.reality.is_some() || self.anytls.is_some() || self.tls.is_some() {
                return Err(ConfigError::ShadowsocksWithVlessTransport);
            }
            wrongsv_shadowsocks::Method::parse(&shadowsocks.method).map_err(|_| {
                ConfigError::UnsupportedShadowsocksMethod(shadowsocks.method.clone())
            })?;
            if shadowsocks
                .tcp_prefix
                .as_deref()
                .is_some_and(|prefix| prefix.len() > 16)
                || shadowsocks
                    .udp_prefix
                    .as_deref()
                    .is_some_and(|prefix| prefix.len() > 16)
            {
                return Err(ConfigError::ShadowsocksPrefixTooLong);
            }
        }
        if let Some(mixed) = &self.mixed {
            if !self.users.is_empty() {
                return Err(ConfigError::MixedWithVlessUsers);
            }
            if self.reality.is_some() || self.anytls.is_some() || self.tls.is_some() {
                return Err(ConfigError::MixedWithVlessTransport);
            }
            match (&mixed.username, &mixed.password) {
                (None, None) => {}
                (Some(username), Some(password)) => {
                    if username.is_empty()
                        || username.len() > 255
                        || password.is_empty()
                        || password.len() > 255
                    {
                        return Err(ConfigError::MixedInvalidCredentials);
                    }
                }
                _ => return Err(ConfigError::MixedIncompleteCredentials),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_toml_config() {
        let toml = r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
email = "test@example.com"
flow = "xtls-rprx-vision"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.listen, "0.0.0.0:443");
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].flow, "xtls-rprx-vision");
        config.validate().unwrap();
    }

    #[test]
    fn test_validate_invalid_uuid() {
        let config = Config {
            listen: "0.0.0.0:443".into(),
            users: vec![UserConfig {
                id: "this-is-too-long-to-be-a-short-name-and-also-not-a-valid-uuid".into(),
                email: "bad@test.com".into(),
                flow: String::new(),
                encryption: String::new(),
                udp: true,
            }],
            decryption: None,
            flow: None,
            kyber_secret_key: None,
            reality: None,
            anytls: None,
            tls: None,
            shadowsocks: None,
            mixed: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_flow() {
        let config = Config {
            listen: "0.0.0.0:443".into(),
            users: vec![UserConfig {
                id: "12345678-1234-1234-1234-123456789abc".into(),
                email: "bad@test.com".into(),
                flow: "xtls-rprx-vision-udp443".into(), // not valid for standalone server
                encryption: String::new(),
                udp: true,
            }],
            decryption: None,
            flow: None,
            kyber_secret_key: None,
            reality: None,
            anytls: None,
            tls: None,
            shadowsocks: None,
            mixed: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_parse_shadowsocks_config() {
        let toml = r#"
listen = "0.0.0.0:8388"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"
tcp_prefix = "HTTP/1.1 "
udp_prefix = "k{\u0001 "
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let shadowsocks = config.shadowsocks.unwrap();
        assert_eq!(shadowsocks.method, "chacha20-ietf-poly1305");
        assert_eq!(shadowsocks.password, "secret");
        assert!(shadowsocks.udp);
        assert_eq!(shadowsocks.tcp_prefix.as_deref(), Some("HTTP/1.1 "));
        assert_eq!(shadowsocks.udp_prefix.as_deref(), Some("k{\u{1} "));
    }

    #[test]
    fn test_shadowsocks_rejects_long_salt_prefix() {
        let toml = r#"
listen = "0.0.0.0:8388"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"
tcp_prefix = "12345678901234567"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowsocksPrefixTooLong)
        ));
    }

    #[test]
    fn test_shadowsocks_rejects_vless_users() {
        let toml = r#"
listen = "0.0.0.0:8388"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowsocksWithVlessUsers)
        ));
    }

    #[test]
    fn test_shadowsocks_rejects_vless_transport() {
        let toml = r#"
listen = "0.0.0.0:8388"

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"

[tls]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ShadowsocksWithVlessTransport)
        ));
    }

    #[test]
    fn test_parse_mixed_config() {
        let toml = r#"
listen = "127.0.0.1:1080"

[mixed]
username = "admin"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        let mixed = config.mixed.unwrap();
        assert_eq!(mixed.username.as_deref(), Some("admin"));
        assert_eq!(mixed.password.as_deref(), Some("secret"));
    }

    #[test]
    fn test_mixed_rejects_vless_users() {
        let toml = r#"
listen = "127.0.0.1:1080"

[mixed]

[[users]]
id = "12345678-1234-1234-1234-123456789abc"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MixedWithVlessUsers)
        ));
    }

    #[test]
    fn test_mixed_rejects_vless_transport() {
        let toml = r#"
listen = "127.0.0.1:1080"

[mixed]

[tls]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MixedWithVlessTransport)
        ));
    }

    #[test]
    fn test_mixed_rejects_shadowsocks_inbound() {
        let toml = r#"
listen = "127.0.0.1:1080"

[mixed]

[shadowsocks]
method = "chacha20-ietf-poly1305"
password = "secret"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MultipleInboundProtocols)
        ));
    }

    #[test]
    fn test_mixed_rejects_incomplete_credentials() {
        let toml = r#"
listen = "127.0.0.1:1080"

[mixed]
username = "admin"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MixedIncompleteCredentials)
        ));
    }
}
