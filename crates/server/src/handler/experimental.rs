use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tracing::info;

// Custom handlers for experimental/newly-added protocols from protocols.md:
// Lua, Masque, TrustTunnel, Brook, Vlite, Tor, SSH, Juicity, Mieru, Sudoku, VLESS-Encryption, ShadowQUIC, AnyTLS-Reality

pub(crate) fn handle_lua_connection(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    info!("{peer} Lua connection");
    echo_relay(stream)
}

pub(crate) fn handle_masque_connection(
    stream: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    info!("{peer} Masque connection");
    echo_relay(stream)
}

pub(crate) fn handle_trusttunnel_connection(
    stream: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    info!("{peer} TrustTunnel connection");
    echo_relay(stream)
}

pub(crate) fn handle_brook_connection(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    info!("{peer} Brook connection");
    echo_relay(stream)
}

pub(crate) fn handle_vlite_connection(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    info!("{peer} Vlite connection");
    echo_relay(stream)
}

pub(crate) fn handle_tor_connection(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    info!("{peer} Tor connection");
    echo_relay(stream)
}

pub(crate) fn handle_ssh_connection(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    info!("{peer} SSH connection");
    echo_relay(stream)
}

pub(crate) fn handle_juicity_connection(
    stream: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    info!("{peer} Juicity connection");
    echo_relay(stream)
}

pub(crate) fn handle_mieru_connection(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    info!("{peer} Mieru connection");
    echo_relay(stream)
}

pub(crate) fn handle_sudoku_connection(
    stream: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    info!("{peer} Sudoku connection");
    echo_relay(stream)
}

pub(crate) fn handle_vless_encryption_connection(
    stream: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    info!("{peer} VLESS-Encryption connection");
    echo_relay(stream)
}

pub(crate) fn handle_shadowquic_connection(
    stream: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    info!("{peer} ShadowQUIC connection");
    echo_relay(stream)
}

pub(crate) fn handle_anytls_reality_connection(
    stream: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    info!("{peer} AnyTLS-Reality connection");
    echo_relay(stream)
}

fn echo_relay(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                stream.write_all(&buf[..n])?;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
