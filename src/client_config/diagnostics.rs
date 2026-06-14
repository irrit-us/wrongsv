use serde::Serialize;

use crate::endpoint::{protocol_descriptor, resolve_endpoint, ProtocolDescriptor, ResolvedEndpoint};
use crate::ClientFormat;

use super::{ClientConfigValues, validate_client_format_support};

#[derive(Debug, Serialize)]
pub(crate) struct EndpointDiagnostics<'a> {
    pub descriptor: &'a ProtocolDescriptor,
    pub resolved: ResolvedEndpoint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export: Option<ExportDiagnostics>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ExportDiagnostics {
    pub format: &'static str,
    pub supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub(crate) fn build_endpoint_diagnostics(
    vals: &ClientConfigValues,
    format: Option<ClientFormat>,
) -> EndpointDiagnostics<'_> {
    let descriptor = protocol_descriptor(vals.protocol());
    let resolved = resolve_endpoint(&vals.endpoint);
    let export = format.map(|format| match validate_client_format_support(format, vals) {
        Ok(()) => ExportDiagnostics {
            format: client_format_name(format),
            supported: true,
            error: None,
        },
        Err(error) => ExportDiagnostics {
            format: client_format_name(format),
            supported: false,
            error: Some(error),
        },
    });

    EndpointDiagnostics {
        descriptor,
        resolved,
        export,
    }
}

fn client_format_name(format: ClientFormat) -> &'static str {
    match format {
        ClientFormat::Mihomo => "mihomo",
        ClientFormat::SingBox => "sing-box",
        ClientFormat::Xray => "xray",
        ClientFormat::Hiddify => "hiddify",
    }
}
