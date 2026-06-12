//! VMess AEAD handler — standalone proxy protocol relay.
//!
//! Accepts VMess connections, authenticates via EAuID + encrypted header,
//! and relays TCP to the target.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tracing::{debug, info, trace, warn};

use crate::config::VmessServerConfig;
use crate::vmess;

// ── Config builder ─────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct VmessHandlerConfig {
    pub users: Arc<Vec<VmessHandlerUser>>,
}

#[derive(Clone)]
pub(crate) struct VmessHandlerUser {
    pub cmd_key: [u8; 16],
    pub email: String,
}

pub(crate) fn parse_vmess_handler_config(
    sc: &VmessServerConfig,
) -> Result<VmessHandlerConfig, String> {
    let users: Vec<VmessHandlerUser> = sc
        .users
        .iter()
        .map(|u| {
            let uuid = wrongsv_uuid::Uuid::parse_string(&u.id)
                .map_err(|e| format!("vmess uuid '{}': {e}", u.id))?;
            let uuid_bytes: [u8; 16] = *uuid.as_bytes();
            let cmd_key = vmess::derive_cmd_key(&uuid_bytes);
            Ok(VmessHandlerUser {
                email: u.email.clone(),
                cmd_key,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(VmessHandlerConfig {
        users: Arc::new(users),
    })
}

// ── Connection handler ─────────────────────────────────────────────────

pub(crate) fn handle_vmess_connection(
    stream: TcpStream,
    config: &VmessHandlerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream.peer_addr()?;
    trace!("{peer} VMess connection");

    let mut sock = stream;
    // 60s read timeout for auth phase
    sock.set_read_timeout(Some(Duration::from_secs(60)))?;

    // ── Read EAuID ─────────────────────────────────────────────────────
    let mut eaudid = [0u8; 16];
    read_exact(&mut sock, &mut eaudid)?;

    // ── Try to authenticate against known users ────────────────────────
    let (user_cmd_key, user_email) = match authenticate(&eaudid, &config.users) {
        Ok(u) => u,
        Err(e) => {
            warn!("{peer} VMess auth failed: {e}");
            return Err(e.into());
        }
    };
    info!("{peer} VMess auth OK user={user_email}");

    // ── Read header ────────────────────────────────────────────────────
    let mut header_len_buf = [0u8; 2];
    read_exact(&mut sock, &mut header_len_buf)?;
    let header_len = u16::from_be_bytes(header_len_buf) as usize;
    if !(28..=8192).contains(&header_len) {
        return Err(format!("VMess header length out of range: {header_len}").into());
    }

    let mut header_payload = vec![0u8; header_len];
    read_exact(&mut sock, &mut header_payload)?;

    let instr = match vmess::decrypt_header(&user_cmd_key, &eaudid, &header_payload) {
        Ok(inst) => inst,
        Err(e) => {
            warn!("{peer} VMess header decrypt failed: {e}");
            return Err(e.into());
        }
    };

    trace!(
        "{peer} VMess request: {:?} {}:{}",
        instr.command, instr.address, instr.port
    );

    // ── Send response auth ─────────────────────────────────────────────
    let response_key = vmess::derive_response_key(&user_cmd_key);
    let resp_payload = vmess::build_response(&response_key)?;
    sock.write_all(&resp_payload)?;

    // ── Relay ──────────────────────────────────────────────────────────
    let target_addr = format!("{}:{}", instr.address, instr.port);
    debug!("{peer} VMess connecting to target {target_addr}");

    let target = match TcpStream::connect(&target_addr) {
        Ok(t) => t,
        Err(e) => {
            warn!("{peer} VMess target connect failed: {e}");
            return Err(e.into());
        }
    };
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(60)))?;

    sock.set_read_timeout(Some(Duration::from_secs(1)))?;
    sock.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Body readers/writers — same key and IV for both directions
    let client_body_key = &instr.body_key;
    let client_body_iv = &instr.body_iv;

    let mut client_r = sock.try_clone()?;
    let mut client_w = sock;

    let mut target_r = target.try_clone()?;
    let mut target_w = target;

    // Channel for client→target relay errors
    let (err_tx, err_rx) = std::sync::mpsc::channel::<String>();

    // Thread 1: Read VMess chunks from client → decrypt → write to target
    let cbk = *client_body_key;
    let cbv = *client_body_iv;
    let err_tx1 = err_tx.clone();
    let t1 = thread::spawn(move || {
        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let mut reader = vmess::VmessBodyReader::new(&cbk, &cbv);
            loop {
                let mut plaintext = Vec::with_capacity(16384);
                match reader.read_chunk(&mut client_r, &mut plaintext) {
                    Ok(true) => {
                        target_w.write_all(&plaintext)?;
                    }
                    Ok(false) => break, // EOF
                    Err(vmess::VmessError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => {
                        let _ = err_tx1.send(format!("client read: {e}"));
                        break;
                    }
                }
            }
            let _ = target_w.shutdown(std::net::Shutdown::Write);
            Ok(())
        })();
        if let Err(e) = result {
            let _ = err_tx1.send(format!("client thread: {e}"));
        }
    });

    // Thread 2: Read from target → encrypt with VMess body → write to client
    let sbk = *client_body_key;
    let sbv = *client_body_iv;
    let t2 = thread::spawn(move || {
        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let mut writer = vmess::VmessBodyWriter::new(&sbk, &sbv);
            let mut buf = [0u8; 16384];
            loop {
                match target_r.read(&mut buf) {
                    Ok(0) => {
                        writer.write_eof(&mut client_w)?;
                        break;
                    }
                    Ok(n) => {
                        writer.write_chunk(&mut client_w, &buf[..n])?;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => {
                        return Err(format!("target read: {e}").into());
                    }
                }
            }
            let _ = client_w.shutdown(std::net::Shutdown::Write);
            Ok(())
        })();
        if let Err(e) = result {
            let _ = err_tx.send(format!("server thread: {e}"));
        }
    });

    // Wait for both threads
    let _ = t1.join();
    let _ = t2.join();

    // Drain error channel
    while let Ok(err_msg) = err_rx.try_recv() {
        debug!("{peer} VMess relay ended: {err_msg}");
    }

    debug!("{peer} VMess relay finished");
    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────

fn read_exact(sock: &mut TcpStream, buf: &mut [u8]) -> Result<(), io::Error> {
    let mut total = 0usize;
    while total < buf.len() {
        match sock.read(&mut buf[total..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn authenticate(
    eaudid: &[u8; 16],
    users: &[VmessHandlerUser],
) -> Result<([u8; 16], String), &'static str> {
    let mut last_err: &str = "no matching user";
    for user in users {
        match vmess::verify_eaudid(&user.cmd_key, eaudid) {
            Ok(_ts) => return Ok((user.cmd_key, user.email.clone())),
            Err(vmess::VmessError::AuthFailed(reason)) => {
                last_err = "eaudid verification failed";
                trace!("VMess auth attempt failed for {}: {reason}", user.email);
            }
            Err(e) => {
                last_err = "eaudid error";
                trace!("VMess auth error for {}: {e}", user.email);
            }
        }
    }
    Err(last_err)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VmessUserConfig;

    #[test]
    fn test_parse_vmess_handler_config_single_user() {
        let sc = VmessServerConfig {
            users: vec![VmessUserConfig {
                id: "12345678-1234-1234-1234-123456789abc".into(),
                email: "test@example.com".into(),
            }],
        };
        let cfg = parse_vmess_handler_config(&sc).unwrap();
        assert_eq!(cfg.users.len(), 1);
        assert_eq!(cfg.users[0].email, "test@example.com");
    }

    #[test]
    fn test_parse_vmess_handler_config_invalid_uuid() {
        let sc = VmessServerConfig {
            users: vec![VmessUserConfig {
                id: "this-is-too-long-to-be-a-short-name-and-also-not-a-valid-uuid".into(),
                email: String::new(),
            }],
        };
        assert!(parse_vmess_handler_config(&sc).is_err());
    }

    #[test]
    fn test_authenticate_finds_correct_user() {
        use crate::vmess::generate_eaudid;
        let user = VmessHandlerUser {
            email: "alice".into(),
            cmd_key: vmess::derive_cmd_key(&[1u8; 16]),
        };
        let (_plain, eaudid) = generate_eaudid(&user.cmd_key);
        let result = authenticate(&eaudid, std::slice::from_ref(&user)).unwrap();
        assert_eq!(result.1, "alice");
    }

    #[test]
    fn test_authenticate_rejects_wrong_user() {
        use crate::vmess::generate_eaudid;
        let user1 = VmessHandlerUser {
            email: "alice".into(),
            cmd_key: vmess::derive_cmd_key(&[1u8; 16]),
        };
        let user2 = VmessHandlerUser {
            email: "bob".into(),
            cmd_key: vmess::derive_cmd_key(&[2u8; 16]),
        };
        let (_plain, eaudid) = generate_eaudid(&user1.cmd_key);
        let result = authenticate(&eaudid, &[user2]);
        assert!(result.is_err());
    }
}
