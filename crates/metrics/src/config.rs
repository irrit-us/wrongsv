use serde::Deserialize;

/// Optional `[metrics]` section in the wrongsv config.
///
/// When absent, no metrics listener is started. When present, the server binds
/// a small HTTP listener on `bind:port` that responds to `GET /metrics` with
/// Prometheus text-format output.
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    pub port: u16,
    #[serde(default = "default_bind")]
    pub bind: String,
}

fn default_bind() -> String {
    "127.0.0.1".to_string()
}

impl MetricsConfig {
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.bind, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bind_is_loopback() {
        let cfg: MetricsConfig = toml::from_str("port = 9100").unwrap();
        assert_eq!(cfg.bind, "127.0.0.1");
        assert_eq!(cfg.port, 9100);
        assert_eq!(cfg.socket_addr(), "127.0.0.1:9100");
    }

    #[test]
    fn custom_bind_address() {
        let cfg: MetricsConfig = toml::from_str(
            r#"
port = 9100
bind = "0.0.0.0"
"#,
        )
        .unwrap();
        assert_eq!(cfg.bind, "0.0.0.0");
        assert_eq!(cfg.socket_addr(), "0.0.0.0:9100");
    }
}
