use std::net::TcpStream;
use std::time::Duration;
use tracing::{debug, info, trace};

use crate::config::MixedServerConfig;
use crate::mixed_proxy::{self, MixedProtocol};

use super::*;

pub(crate) fn parse_mixed_config(
    mc: &MixedServerConfig,
) -> Result<mixed_proxy::MixedProxyConfig, String> {
    mixed_proxy::MixedProxyConfig::new(mc.username.clone(), mc.password.clone())
        .map_err(|e| format!("mixed proxy: {e}"))
}
pub(crate) fn handle_mixed_proxy_connection(
    mut stream: TcpStream,
    config: &mixed_proxy::MixedProxyConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} mixed proxy connection");
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    let protocol = mixed_proxy::detect_protocol(&stream)?;
    let request = match protocol {
        MixedProtocol::Socks4 => mixed_proxy::accept_socks4_connect(&mut stream, config),
        MixedProtocol::Socks5 => mixed_proxy::accept_socks5_connect(&mut stream, config),
        MixedProtocol::HttpConnect => mixed_proxy::accept_http_request(&mut stream, config),
        MixedProtocol::HttpForward => unreachable!("HTTP forwarding is selected after parsing"),
    };
    let request = match request {
        Ok(request) => request,
        Err(e) => {
            if protocol == MixedProtocol::HttpConnect {
                let _ = mixed_proxy::write_http_error(&mut stream, &e);
            }
            return Err(Box::new(e));
        }
    };

    let target_addr = format!("{}:{}", request.address, request.port);
    let target = match connect_tcp_target(&request.address, request.port) {
        Ok(target) => target,
        Err(e) => {
            match request.protocol {
                MixedProtocol::Socks4 => {
                    let _ = mixed_proxy::write_socks4_connect_error(&mut stream);
                }
                MixedProtocol::Socks5 => {
                    let _ = mixed_proxy::write_socks5_connect_error(&mut stream, &e);
                }
                MixedProtocol::HttpConnect => {
                    let _ = mixed_proxy::write_http_bad_gateway(&mut stream);
                }
                MixedProtocol::HttpForward => {
                    let _ = mixed_proxy::write_http_bad_gateway(&mut stream);
                }
            }
            return Err(Box::new(e));
        }
    };
    target.set_nodelay(true)?;

    match request.protocol {
        MixedProtocol::Socks4 => {
            mixed_proxy::write_socks4_success(&mut stream, target.local_addr().ok())?;
        }
        MixedProtocol::Socks5 => {
            mixed_proxy::write_socks5_success(&mut stream, target.local_addr().ok())?;
        }
        MixedProtocol::HttpConnect => {
            mixed_proxy::write_http_success(&mut stream)?;
        }
        MixedProtocol::HttpForward => {}
    }

    stream.set_read_timeout(None)?;
    info!(
        "{peer} {} -> {target_addr}",
        mixed_protocol_name(request.protocol)
    );
    relay_raw_with_initial(stream, target, request.initial_data)?;
    debug!("{peer} mixed proxy relay finished");
    Ok(())
}
