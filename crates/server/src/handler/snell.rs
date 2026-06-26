use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::thread;
use std::time::Duration;

use tracing::{debug, info};
use wrongsv_snell::{
    COMMAND_TUNNEL, ClientCommand, SnellConfig, SnellReader, SnellWriter, encode_error_response,
    parse_client_command,
};

pub(crate) type SnellHandlerConfig = SnellConfig;

pub(crate) fn parse_snell_config(
    config: &crate::config::SnellServerConfig,
) -> Result<SnellHandlerConfig, String> {
    SnellConfig::new(config.psk.as_bytes().to_vec(), config.version)
        .map_err(|e| format!("snell: {e}"))
}

pub(crate) fn handle_snell_connection(
    stream: TcpStream,
    config: &SnellHandlerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    debug!("{peer} Snell connection");
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    let read_stream = stream.try_clone()?;
    let mut reader = SnellReader::new(read_stream, config)?;
    let first = reader.read_chunk()?;
    let command = parse_client_command(&first)?;
    match command {
        ClientCommand::Connect {
            address,
            port,
            initial_payload,
        } => {
            let target_addr = format!("{address}:{port}");
            info!("{peer} Snell TCP -> {target_addr}");
            let target = TcpStream::connect(&target_addr)?;
            target.set_nodelay(true)?;
            target.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream.set_read_timeout(None)?;
            relay_snell(reader, stream, target, config.clone(), initial_payload)?;
            debug!("{peer} Snell relay finished");
            Ok(())
        }
        ClientCommand::Udp => {
            let mut writer = SnellWriter::new(stream, config)?;
            writer.write_chunk(&encode_error_response(1, "Snell UDP is not implemented"))?;
            Err("Snell UDP is not implemented".into())
        }
    }
}

fn relay_snell(
    mut reader: SnellReader<TcpStream>,
    client_writer: TcpStream,
    target: TcpStream,
    config: SnellHandlerConfig,
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut target_writer = target.try_clone()?;
    let mut target_reader = target;
    let mut writer = SnellWriter::new(client_writer, &config)?;
    writer.write_chunk(&[COMMAND_TUNNEL])?;

    if !initial_data.is_empty() {
        target_writer.write_all(&initial_data)?;
    }

    let t1 = thread::spawn(move || {
        loop {
            match reader.read_chunk() {
                Ok(data) if data.is_empty() => break,
                Ok(data) => {
                    if target_writer.write_all(&data).is_err() {
                        break;
                    }
                }
                Err(wrongsv_snell::SnellError::Io(e))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    break;
                }
                Err(e) => {
                    debug!("Snell client read: {e}");
                    break;
                }
            }
        }
        let _ = target_writer.shutdown(Shutdown::Write);
    });

    let t2 = thread::spawn(move || {
        let mut buf = [0u8; 32768];
        loop {
            match target_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if writer.write_chunk(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = target_reader.set_read_timeout(Some(Duration::from_millis(10)));
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    let _ = target_reader.set_read_timeout(Some(Duration::from_secs(2)));
                }
                Err(e) => {
                    debug!("Snell target read: {e}");
                    break;
                }
            }
        }
    });

    t1.join().ok();
    t2.join().ok();
    Ok(())
}
