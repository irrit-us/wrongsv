//! WebTransport transport: QUIC + HTTP/3 WebTransport session + stream + VLESS.
//!
//! Uses a background thread with tokio runtime for the async wtransport connection.

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::JoinHandle;
use std::time::Duration;

use super::BoxedIo;

struct WtStream {
    read_rx: Receiver<Vec<u8>>,
    write_tx: SyncSender<Vec<u8>>,
    read_buf: Vec<u8>,
    _handle: JoinHandle<()>,
}

impl Read for WtStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.len());
            buf[..n].copy_from_slice(&self.read_buf[..n]);
            self.read_buf.drain(..n);
            if n > 0 {
                return Ok(n);
            }
        }
        match self.read_rx.recv_timeout(Duration::from_millis(100)) {
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
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "WebTransport read timeout",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(0),
        }
    }
}

impl Write for WtStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx.send(buf.to_vec()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebTransport write channel closed",
            )
        })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn make_wt_tls_config() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(super::tls_common::NoVerify))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    config
}

// ── Connect ───────────────────────────────────────────────────────────

pub fn connect_webtransport(
    proxy_host: &str,
    proxy_port: u16,
    uuid: &str,
    target_addr: &str,
    target_port: u16,
    flow: &str,
) -> io::Result<BoxedIo> {
    let header = super::raw::build_vless_header(uuid, target_addr, target_port, flow)?;
    let server_addr: std::net::SocketAddr =
        std::net::ToSocketAddrs::to_socket_addrs(&(proxy_host, proxy_port))
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("resolve WT target {proxy_host}:{proxy_port}: {e}"),
                )
            })?
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("no addresses resolved for {proxy_host}:{proxy_port}"),
                )
            })?;

    let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>();
    let (write_tx, write_rx) = mpsc::sync_channel::<Vec<u8>>(32);
    let (hs_tx, hs_rx) = mpsc::sync_channel::<Result<(), io::Error>>(1);

    let (tokio_write_tx, mut tokio_write_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let bridge_tx = tokio_write_tx;
        std::thread::spawn(move || {
            while let Ok(data) = write_rx.recv() {
                if bridge_tx.blocking_send(data).is_err() {
                    break;
                }
            }
        });

        rt.block_on(async {
            // Create endpoint + connection here so they live for the
            // entire async block — dropping either closes the QUIC conn.
            let wt_client_config = wtransport::ClientConfig::builder()
                .with_bind_default()
                .with_custom_tls(make_wt_tls_config())
                .build();

            let endpoint = match wtransport::Endpoint::client(wt_client_config) {
                Ok(ep) => ep,
                Err(e) => {
                    let _ = hs_tx.send(Err(io::Error::other(format!("WT endpoint: {e}"))));
                    return;
                }
            };

            let url = format!("https://{server_addr}/eval");
            let connection = match endpoint.connect(url.as_str()).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = hs_tx.send(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("WT connect: {e}"),
                    )));
                    return;
                }
            };

            let (mut send, mut recv) = match connection.open_bi().await {
                Ok(open) => match open.await {
                    Ok(sr) => sr,
                    Err(e) => {
                        let _ =
                            hs_tx.send(Err(io::Error::other(format!("WT opening stream: {e}"))));
                        return;
                    }
                },
                Err(e) => {
                    let _ = hs_tx.send(Err(io::Error::other(format!("WT open bi: {e}"))));
                    return;
                }
            };

            // Send VLESS header
            if let Err(e) = send.write_all(&header).await {
                let _ = hs_tx.send(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
                return;
            }

            // Read VLESS response
            let mut resp = [0u8; 2];
            if let Err(e) = recv.read_exact(&mut resp).await {
                let _ = hs_tx.send(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("VLESS response: {e}"),
                )));
                return;
            }
            if resp[1] > 0 {
                let mut addons = vec![0u8; resp[1] as usize];
                let _ = recv.read_exact(&mut addons).await;
            }

            // Keep endpoint + connection alive for the relay lifetime
            let _endpoint = endpoint;
            let _connection = connection;

            let _ = hs_tx.send(Ok(()));

            // Read loop
            let read_handle: tokio::task::JoinHandle<()> = tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match recv.read(&mut buf).await {
                        Ok(Some(n)) => {
                            if read_tx.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                        Ok(None) | Err(_) => {
                            let _ = read_tx.send(Vec::new());
                            break;
                        }
                    }
                }
            });

            // Write loop
            loop {
                match tokio_write_rx.recv().await {
                    Some(data) => {
                        if send.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        tokio::spawn(async move {
                            let _ = send.finish().await;
                        });
                        break;
                    }
                }
            }

            read_handle.abort();
        });
    });

    hs_rx
        .recv()
        .map_err(|_| io::Error::other("WebTransport thread panicked"))??;

    Ok(Box::new(WtStream {
        read_rx,
        write_tx,
        read_buf: Vec::new(),
        _handle: handle,
    }))
}
