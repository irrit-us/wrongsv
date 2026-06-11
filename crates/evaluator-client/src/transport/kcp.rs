//! KCP (mKCP) transport: UDP + mKCP auth + KCP reliable session + VLESS.
//!
//! Uses a background thread to drive the KCP update loop and bridge to sync
//! Read/Write via channels.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use kcp::Kcp;

use super::BoxedIo;

/// FNV1a-32 hash used by mKCP auth.
fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Seal a KCP segment with mKCP auth header.
fn mkcp_seal(seed: &str, cmd: u8, data: &[u8]) -> Vec<u8> {
    let mut auth_input = Vec::with_capacity(seed.len() + 1 + data.len());
    auth_input.extend_from_slice(seed.as_bytes());
    auth_input.push(cmd);
    auth_input.extend_from_slice(data);
    let auth = fnv1a_32(&auth_input) as u16;
    let mut packet = Vec::with_capacity(3 + data.len());
    packet.extend_from_slice(&auth.to_be_bytes());
    packet.push(cmd);
    packet.extend_from_slice(data);
    packet
}

/// KCP output that collects bytes into a buffer.
struct KcpOutput {
    udp: UdpSocket,
    server_addr: SocketAddr,
    seed: String,
}

impl Write for KcpOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Wrap in mKCP frame and send via UDP
        let packet = mkcp_seal(&self.seed, 1, buf); // CMD_DATA=1
        let _ = self.udp.send_to(&packet, self.server_addr)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct KcpStream {
    read_rx: Receiver<Vec<u8>>,
    write_tx: SyncSender<Vec<u8>>,
    read_buf: Vec<u8>,
    _handle: JoinHandle<()>,
}

impl Read for KcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.len());
            buf[..n].copy_from_slice(&self.read_buf[..n]);
            self.read_buf.drain(..n);
            if n > 0 {
                return Ok(n);
            }
        }
        match self.read_rx.recv() {
            Ok(data) => {
                if data.is_empty() {
                    return Ok(0);
                }
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf.extend_from_slice(&data[n..]);
                }
                Ok(n)
            }
            Err(_) => Ok(0),
        }
    }
}

impl Write for KcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "KCP write channel closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn connect_kcp(
    proxy_host: &str,
    proxy_port: u16,
    uuid: &str,
    target_addr: &str,
    target_port: u16,
    flow: &str,
) -> io::Result<BoxedIo> {
    let seed = "eval-kcp-seed";
    let header = super::raw::build_vless_header(uuid, target_addr, target_port, flow);
    let server_addr: SocketAddr = format!("{proxy_host}:{proxy_port}").parse().unwrap();

    let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>();
    let (write_tx, write_rx) = mpsc::sync_channel::<Vec<u8>>(32);
    let (hs_tx, hs_rx) = mpsc::sync_channel::<Result<(), io::Error>>(1);

    let handle = thread::spawn(move || {
        // Bind UDP socket
        let udp = match UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(e) => {
                let _ = hs_tx.send(Err(e));
                return;
            }
        };
        let _ = udp.set_read_timeout(Some(Duration::from_millis(100)));

        // Create KCP session with conv=rand
        let conv: u16 = rand::random();
        let output = KcpOutput {
            udp: udp.try_clone().unwrap(),
            server_addr,
            seed: seed.to_string(),
        };
        let mut kcp = Kcp::new(conv as u32, output);
        let _ = kcp.set_mtu(1350);
        kcp.set_nodelay(true, 10, 2, true);
        kcp.set_wndsize(128, 256);

        // Send VLESS header through KCP
        let _ = kcp.send(&header);
        // Drain KCP output to send the data
        // KCP output is handled via the Write impl on KcpOutput which sends UDP directly
        // But we need to call kcp.output() to flush... Actually, kcp.send() calls output.write().
        // Let's verify: Kcp::send calls self.output.write() internally, so data is sent immediately.

        // Wait for VLESS response
        let mut tick: u32 = 0;
        let mut response_buf = [0u8; 2];
        let mut resp_offset = 0;
        let mut got_response = false;

        // Poll for response with timeout
        for _ in 0..50 {
            tick = tick.wrapping_add(1);
            let _ = kcp.update(tick);

            // Try to receive UDP data
            let mut udp_buf = [0u8; 2048];
            match udp.recv_from(&mut udp_buf) {
                Ok((n, src)) if src == server_addr => {
                    // Feed raw KCP data into kcp (strip mKCP header)
                    if n >= 3 {
                        let cmd = udp_buf[2];
                        let data = &udp_buf[3..n];
                        if cmd == 1 {
                            // CMD_DATA
                            let _ = kcp.input(data);
                        }
                    }
                }
                _ => {}
            }

            // Try to read from KCP
            if !got_response {
                match kcp.recv(&mut response_buf[resp_offset..]) {
                    Ok(n) if n > 0 => {
                        resp_offset += n;
                        if resp_offset >= 2 {
                            got_response = true;
                            // Read addons if present
                            let addons_len = response_buf[1] as usize;
                            if addons_len > 0 {
                                let mut addons = vec![0u8; addons_len];
                                let mut off = 0;
                                while off < addons_len {
                                    match kcp.recv(&mut addons[off..]) {
                                        Ok(n) if n > 0 => off += n,
                                        _ => break,
                                    }
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {}
                }
            }

            if got_response {
                break;
            }

            thread::sleep(Duration::from_millis(10));
        }

        if !got_response {
            let _ = hs_tx.send(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "KCP VLESS response timeout",
            )));
            return;
        }

        let _ = hs_tx.send(Ok(()));

        // Main I/O loop
        loop {
            tick = tick.wrapping_add(1);
            let _ = kcp.update(tick);

            // Check for outgoing data
            while let Ok(data) = write_rx.try_recv() {
                let _ = kcp.send(&data);
            }

            // Check for incoming UDP data
            let mut udp_buf = [0u8; 2048];
            match udp.recv_from(&mut udp_buf) {
                Ok((n, src)) if src == server_addr && n >= 3 => {
                    let cmd = udp_buf[2];
                    let data = &udp_buf[3..n];
                    if cmd == 1 {
                        let _ = kcp.input(data);
                    }
                }
                _ => {}
            }

            // Read from KCP and forward to read channel
            let mut kcp_read_buf = [0u8; 4096];
            match kcp.recv(&mut kcp_read_buf) {
                Ok(n) if n > 0 => {
                    if read_tx.send(kcp_read_buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                _ => {}
            }

            thread::sleep(Duration::from_millis(5));
        }
    });

    hs_rx
        .recv()
        .map_err(|_| io::Error::other("KCP thread panicked"))??;

    Ok(Box::new(KcpStream {
        read_rx,
        write_tx,
        read_buf: Vec::new(),
        _handle: handle,
    }))
}
