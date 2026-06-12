//! VMess AEAD client transport.
//!
//! Connects to a wrongsv VMess server, authenticates with EAuID, sends an
//! encrypted header, and returns a bidirectional stream with AEAD body
//! encryption/decryption handled internally.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use wrongsv_server::vmess;

use super::BoxedIo;

/// VMess stream — converts plain data ↔ AES-128-GCM chunked VMess body.
pub struct VmessStream {
    // Write side: send plaintext, it gets encrypted and written to socket
    write_tx: mpsc::SyncSender<Vec<u8>>,
    write_closed: mpsc::SyncSender<()>,
    // Read side: receive decrypted plaintext
    read_rx: mpsc::Receiver<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl Read for VmessStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Drain any leftover from previous chunk
        if self.read_pos < self.read_buf.len() {
            let available = self.read_buf.len() - self.read_pos;
            let n = available.min(buf.len());
            buf[..n].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
            self.read_pos += n;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Ok(n);
        }

        // Wait for next chunk
        match self.read_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(data) => {
                if data.is_empty() {
                    return Ok(0); // EOF
                }
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf = data;
                    self.read_pos = n;
                }
                Ok(n)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "vmess read timeout",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(0),
        }
    }
}

impl Write for VmessStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.write_tx.send(buf.to_vec()) {
            Ok(()) => Ok(buf.len()),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "vmess write closed",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for VmessStream {
    fn drop(&mut self) {
        let _ = self.write_closed.send(());
    }
}

/// Connect to a VMess AEAD server and return a bidirectional stream.
pub fn connect_vmess(
    proxy_host: &str,
    proxy_port: u16,
    uuid: &str,
    target_addr: &str,
    target_port: u16,
) -> Result<BoxedIo, io::Error> {
    // Parse UUID
    let uuid_parsed = wrongsv_uuid::Uuid::parse_string(uuid).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid vmess uuid: {e}"),
        )
    })?;
    let uuid_bytes: [u8; 16] = *uuid_parsed.as_bytes();
    let cmd_key = vmess::derive_cmd_key(&uuid_bytes);

    // Connect to proxy
    let mut sock = super::connect_proxy(proxy_host, proxy_port)?;
    sock.set_read_timeout(Some(Duration::from_secs(30)))?;

    // ── Generate EAuID ────────────────────────────────────────────────
    let (_plain, eaudid) = vmess::generate_eaudid(&cmd_key);

    // ── Generate body key/IV ──────────────────────────────────────────
    let mut body_key = [0u8; 16];
    let mut body_iv = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut body_key);
    rand::rngs::OsRng.fill_bytes(&mut body_iv);

    // ── Build header ──────────────────────────────────────────────────
    let request = vmess::VmessRequest {
        command: vmess::VmessCommand::Tcp,
        address: target_addr.to_string(),
        port: target_port,
    };

    let (total_len, header_payload): (u16, Vec<u8>) =
        match vmess::build_header(&cmd_key, &eaudid, &body_key, &body_iv, &request) {
            Ok(v) => v,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("vmess build header: {e}"),
                ));
            }
        };

    // ── Send EAuID + header ───────────────────────────────────────────
    sock.write_all(&eaudid)?;
    sock.write_all(&total_len.to_be_bytes())?;
    sock.write_all(&header_payload)?;

    // ── Read response ────────────────────────────────────────────────
    let response_key = vmess::derive_response_key(&cmd_key);
    match vmess::read_response(&response_key, &mut sock) {
        Ok(()) => {}
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("vmess response: {e}"),
            ));
        }
    }

    // ── Set up encrypted relay with channels ──────────────────────────
    // Write side: plaintext → encrypt → socket
    let (write_tx, write_rx) = mpsc::sync_channel::<Vec<u8>>(64);
    let (close_tx, close_rx) = mpsc::sync_channel::<()>(1);
    let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>();

    let mut writer_sock = match sock.try_clone() {
        Ok(s) => s,
        Err(e) => {
            return Err(io::Error::other(format!("clone: {e}")));
        }
    };
    let mut reader_sock = sock;

    // Thread: read plaintext from channel, encrypt, write to socket
    let bk = body_key;
    let bv = body_iv;
    let read_tx_err = read_tx.clone();
    thread::spawn(move || {
        let result = {
            let mut writer = vmess::VmessBodyWriter::new(&bk, &bv);
            let outcome = loop {
                match write_rx.recv_timeout(Duration::from_millis(10)) {
                    Ok(data) => {
                        if writer.write_chunk(&mut writer_sock, &data).is_err() {
                            break Err(io::Error::other("vmess write chunk failed"));
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // Check if close requested
                        if close_rx.try_recv().is_ok() {
                            let _ = writer.write_eof(&mut writer_sock);
                            break Ok(());
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        let _ = writer.write_eof(&mut writer_sock);
                        break Ok(());
                    }
                }
            };
            let _ = writer_sock.shutdown(Shutdown::Write);
            outcome
        };
        if let Err(_e) = result {
            let _ = read_tx_err.send(Vec::new());
        }
    });

    // Thread: read from socket, decrypt, send plaintext to channel
    thread::spawn(move || {
        let result = {
            let mut reader = vmess::VmessBodyReader::new(&bk, &bv);
            let mut plaintext = Vec::with_capacity(16384);
            let outcome = loop {
                plaintext.clear();
                match reader.read_chunk(&mut reader_sock, &mut plaintext) {
                    Ok(true) => {
                        if read_tx.send(plaintext.clone()).is_err() {
                            break Err(io::Error::other("vmess read channel closed"));
                        }
                    }
                    Ok(false) => {
                        let _ = read_tx.send(Vec::new()); // EOF marker
                        break Ok(());
                    }
                    Err(vmess::VmessError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => {
                        let _ = read_tx.send(Vec::new());
                        break Ok(());
                    }
                }
            };
            let _ = reader_sock.shutdown(Shutdown::Read);
            outcome
        };
        if let Err(_e) = result {
            let _ = read_tx.send(Vec::new());
        }
    });

    Ok(Box::new(VmessStream {
        write_tx,
        write_closed: close_tx,
        read_rx,
        read_buf: Vec::new(),
        read_pos: 0,
    }))
}
