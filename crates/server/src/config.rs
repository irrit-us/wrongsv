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
        };
        assert!(config.validate().is_err());
    }
}
