use serde::Serialize;

use crate::import_config::{
    WrongclClientConfigDocument, WrongclOuterSecurityDocument, WrongclProxyDocument,
    WrongclTransportDocument,
};
use crate::wrongcl_support::{WrongclAdaptPlan, WrongclInspection};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WrongclAdaptResultDocument {
    pub report: WrongclInspection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<WrongclClientConfigDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub draft_config: Option<WrongclClientConfigDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_summary: Option<String>,
}

pub fn build_wrongcl_adapt_result(plan: &WrongclAdaptPlan) -> WrongclAdaptResultDocument {
    let stack_summary = plan
        .strict_config
        .as_ref()
        .or(plan.draft_config.as_ref())
        .map(stack_summary_from_document);
    WrongclAdaptResultDocument {
        report: plan.inspection.clone(),
        config: plan.strict_config.clone(),
        draft_config: plan.draft_config.clone(),
        stack_summary,
    }
}

fn stack_summary_from_document(document: &WrongclClientConfigDocument) -> String {
    if matches!(
        document.server.endpoint.proxy,
        WrongclProxyDocument::Hysteria2 { .. }
    ) {
        return "Hysteria2 → QUIC → TLS → TCP".to_string();
    }

    let mut parts: Vec<&str> = Vec::new();
    parts.push(match &document.server.endpoint.proxy {
        WrongclProxyDocument::Vless { .. } => "VLESS",
        WrongclProxyDocument::Hysteria2 { .. } => "Hysteria2",
        WrongclProxyDocument::Trojan { .. } => "Trojan",
        WrongclProxyDocument::Mixed { .. } => "Mixed remote SOCKS/HTTP",
        WrongclProxyDocument::Shadowsocks { .. } => "Shadowsocks",
    });
    parts.push(match &document.server.endpoint.transport {
        WrongclTransportDocument::Raw => "raw",
        WrongclTransportDocument::Websocket { .. } => "WebSocket",
        WrongclTransportDocument::Httpupgrade { .. } => "HTTPUpgrade",
        WrongclTransportDocument::Xhttp { .. } => "XHTTP",
        WrongclTransportDocument::Grpc { .. } => "gRPC",
    });
    match &document.server.endpoint.outer_security {
        WrongclOuterSecurityDocument::None => {}
        WrongclOuterSecurityDocument::Tls { .. } => parts.push("TLS"),
        WrongclOuterSecurityDocument::Reality { .. } => parts.push("REALITY"),
        WrongclOuterSecurityDocument::AnyTls { .. } => parts.push("AnyTLS"),
        WrongclOuterSecurityDocument::ShadowTls { .. } => parts.push("ShadowTLS"),
    }
    parts.push("TCP");
    parts.join(" → ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import_config::{
        ImportConfig, build_wrongcl_client_config_document, build_wrongcl_import_spec,
        import_resolution_hint,
    };
    use crate::wrongcl_support::build_wrongcl_adapt_plan;

    #[test]
    fn wrongcl_adapt_result_document_prefers_strict_stack_summary() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[grpc]
service_name = "GunService"

[grpc.tls]
server_name = "grpc.example"
"#,
        )
        .unwrap();

        let resolution = import_resolution_hint(&config);
        let plan =
            build_wrongcl_adapt_plan(&config, &resolution, "wrong.example", "127.0.0.1", 1080)
                .unwrap();
        let result = build_wrongcl_adapt_result(&plan);

        assert_eq!(
            result.stack_summary.as_deref(),
            Some("VLESS → gRPC → TLS → TCP")
        );
        assert!(result.config.is_some());
        assert!(result.draft_config.is_some());
    }

    #[test]
    fn wrongcl_stack_summary_matches_wrongcl_document_shape() {
        let config: ImportConfig = toml::from_str(
            r#"
listen = "0.0.0.0:443"

[[users]]
id = "12345678-1234-1234-1234-123456789abc"

[websocket]
path = "/ws"
"#,
        )
        .unwrap();

        let spec = build_wrongcl_import_spec(&config, "websocket", "wrong.example", false).unwrap();
        let document =
            build_wrongcl_client_config_document(&spec, "wrong.example", "127.0.0.1", 1080);
        assert_eq!(
            stack_summary_from_document(&document),
            "VLESS → WebSocket → TCP"
        );
    }
}
