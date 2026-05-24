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
            wrongsv_uuid::Uuid::parse_string(&user.id)
                .map_err(|e: wrongsv_uuid::ParseUuidError| ConfigError::InvalidUuid(user.email.clone(), e.to_string()))?;
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
            }],
            decryption: None,
            flow: None,
            kyber_secret_key: None,
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
            }],
            decryption: None,
            flow: None,
            kyber_secret_key: None,
        };
        assert!(config.validate().is_err());
    }
}
