//! Transport implementations for the evaluator client.
//!
//! Each module provides a sync `connect()` function that:
//! 1. Takes a pre-connected TcpStream
//! 2. Performs any transport-level handshake (TLS, WebSocket, gRPC, etc.)
//! 3. Sends the VLESS header
//! 4. Reads the VLESS response
//! 5. Returns a boxed sync stream for data exchange

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

mod anytls;
mod grpc;
mod httpupgrade;
mod kcp;
mod quic;
mod raw;
mod reality;
mod tls_common;
mod websocket;
// TODO: fix compilation — pre-existing borrow-checker issues
// mod shadowtls;
// mod webtransport;
mod vmess;
mod xhttp;

// ── Public types ─────────────────────────────────────────────────────────

/// Trait alias for read+write streams.
pub trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

/// Boxed stream type returned by transport connections.
pub type BoxedIo = Box<dyn ReadWrite>;

// Re-export for modules
use tls_common::make_no_verify_config;

// ── Connection helper ────────────────────────────────────────────────────

/// Connect to the proxy on the given host and port. Used by all transports.
fn connect_proxy(host: &str, port: u16) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("resolve {host}:{port}: {e}"),
            )
        })?
        .collect();
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(sock) => return Ok(sock),
            Err(_) => continue,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::ConnectionRefused,
        format!("could not connect to {host}:{port}"),
    ))
}

// ── Dispatch ─────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn connect_for_protocol(
    protocol: &str,
    proxy_host: &str,
    proxy_port: u16,
    target_port: u16,
    uuid: &str,
    flow: &str,
    reality_pubkey_b64: Option<&str>,
    reality_short_id: Option<&str>,
    reality_raw_pubkey: Option<&str>,
) -> Result<BoxedIo, std::io::Error> {
    let target_addr = "127.0.0.1";

    match protocol {
        "raw" => {
            let sock = connect_proxy(proxy_host, proxy_port)?;
            raw::connect_raw(sock, uuid, target_addr, target_port, flow)
        }
        "tls" => {
            let sock = connect_proxy(proxy_host, proxy_port)?;
            tls_common::connect_tls(sock, uuid, target_addr, target_port, flow)
        }
        "ws" => {
            let sock = connect_proxy(proxy_host, proxy_port)?;
            websocket::connect_ws(sock, uuid, target_addr, target_port, flow, None)
        }
        "ws+tls" => {
            let sock = connect_proxy(proxy_host, proxy_port)?;
            websocket::connect_ws(
                sock,
                uuid,
                target_addr,
                target_port,
                flow,
                Some(make_no_verify_config()),
            )
        }
        "httpupgrade" => {
            let sock = connect_proxy(proxy_host, proxy_port)?;
            httpupgrade::connect_httpupgrade(sock, uuid, target_addr, target_port, flow, None)
        }
        "httpupgrade+tls" => {
            let sock = connect_proxy(proxy_host, proxy_port)?;
            httpupgrade::connect_httpupgrade(
                sock,
                uuid,
                target_addr,
                target_port,
                flow,
                Some(make_no_verify_config()),
            )
        }
        "grpc" => {
            let addr = format!("{proxy_host}:{proxy_port}");
            grpc::connect_grpc(&addr, uuid, target_addr, target_port, flow, None)
        }
        "grpc+tls" => {
            let addr = format!("{proxy_host}:{proxy_port}");
            grpc::connect_grpc(
                &addr,
                uuid,
                target_addr,
                target_port,
                flow,
                Some(make_no_verify_config()),
            )
        }
        "xhttp" => {
            let addr = format!("{proxy_host}:{proxy_port}");
            xhttp::connect_xhttp(&addr, uuid, target_addr, target_port, flow, None)
        }
        "xhttp+tls" => {
            let addr = format!("{proxy_host}:{proxy_port}");
            xhttp::connect_xhttp(
                &addr,
                uuid,
                target_addr,
                target_port,
                flow,
                Some(make_no_verify_config()),
            )
        }
        "reality" => {
            let pubkey = reality_pubkey_b64.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "reality requires server pubkey",
                )
            })?;
            let short_id = reality_short_id.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "reality requires short_id",
                )
            })?;
            let raw_pubkey = reality_raw_pubkey.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "reality requires raw_pubkey",
                )
            })?;
            let sock = connect_proxy(proxy_host, proxy_port)?;
            reality::connect_reality(
                sock,
                uuid,
                target_addr,
                target_port,
                flow,
                pubkey,
                short_id,
                raw_pubkey,
            )
        }
        "anytls" => {
            let sock = connect_proxy(proxy_host, proxy_port)?;
            anytls::connect_anytls(sock, uuid, target_addr, target_port, flow)
        }
        "quic" => quic::connect_quic(proxy_host, proxy_port, uuid, target_addr, target_port, flow),
        "kcp" => kcp::connect_kcp(proxy_host, proxy_port, uuid, target_addr, target_port, flow),
        // TODO: re-enable when shadowtls/webtransport compile
        // "webtransport" => webtransport::connect_webtransport(
        //     proxy_host, proxy_port, uuid, target_addr, target_port, flow,
        // ),
        // "shadowtls" => shadowtls::connect_shadowtls(
        //     proxy_host, proxy_port, uuid, target_addr, target_port, flow,
        // ),
        "vmess" => vmess::connect_vmess(proxy_host, proxy_port, uuid, target_addr, target_port),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown protocol: {protocol}"),
        )),
    }
}
