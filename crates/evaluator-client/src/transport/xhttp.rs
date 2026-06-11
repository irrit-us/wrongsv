//! XHTTP (SplitHTTP) transport: HTTP/2 + raw byte streaming + VLESS.
//!
//! XHTTP uses no protobuf framing — raw bytes over HTTP/2 DATA frames.
//! Spawns a background thread with tokio runtime for async h2.

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::JoinHandle;
use std::time::Duration;

use rustls::ClientConfig;

use super::BoxedIo;

struct XhttpStream {
    read_rx: Receiver<Vec<u8>>,
    write_tx: SyncSender<Vec<u8>>,
    read_buf: Vec<u8>,
    _handle: JoinHandle<()>,
}

impl Read for XhttpStream {
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
                "xHTTP read timeout",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(0),
        }
    }
}

impl Write for XhttpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_tx
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "xhttp write channel closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn xhttp_handshake(
    tcp: tokio::net::TcpStream,
    use_tls: bool,
    vless_header: &[u8],
) -> Result<(h2::RecvStream, h2::SendStream<bytes::Bytes>), io::Error> {
    tcp.set_nodelay(true).map_err(io::Error::other)?;

    let client = if use_tls {
        let tls_cfg = super::tls_common::make_no_verify_config();
        let server_name = rustls::pki_types::ServerName::try_from("cloudfront.net")
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad SNI"))?;
        let connector = tokio_rustls::TlsConnector::from(tls_cfg);
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| io::Error::other(format!("TLS: {e}")))?;
        let (client, conn) = h2::client::Builder::new()
            .initial_window_size(1_048_576)
            .handshake(tls_stream)
            .await
            .map_err(|e| io::Error::other(format!("h2: {e}")))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        client
    } else {
        let (client, conn) = h2::client::Builder::new()
            .initial_window_size(1_048_576)
            .handshake(tcp)
            .await
            .map_err(|e| io::Error::other(format!("h2: {e}")))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        client
    };

    let mut client = client
        .ready()
        .await
        .map_err(|e| io::Error::other(format!("h2 ready: {e}")))?;

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://xhttp.local/eval")
        .header("content-type", "application/octet-stream")
        .body(())
        .unwrap();

    let (response, mut send_stream) = client
        .send_request(request, false)
        .map_err(|e| io::Error::other(format!("send: {e}")))?;

    let response = response
        .await
        .map_err(|e| io::Error::other(format!("response: {e}")))?;

    if response.status() != http::StatusCode::OK {
        return Err(io::Error::other(format!(
            "XHTTP status: {}",
            response.status()
        )));
    }

    let mut body = response.into_body();

    // Send VLESS header as raw bytes over HTTP/2
    send_stream
        .send_data(bytes::Bytes::copy_from_slice(vless_header), false)
        .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;

    // Read VLESS response (raw bytes via HTTP/2 DATA frame)
    match body.data().await {
        Some(Ok(_data)) => {} // VLESS response received
        Some(Err(e)) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("VLESS response error: {e}"),
            ));
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "no VLESS response",
            ));
        }
    }

    Ok((body, send_stream))
}

pub fn connect_xhttp(
    proxy_addr: &str,
    uuid: &str,
    target_addr: &str,
    target_port: u16,
    flow: &str,
    tls_config: Option<Arc<ClientConfig>>,
) -> io::Result<BoxedIo> {
    let use_tls = tls_config.is_some();
    let header = super::raw::build_vless_header(uuid, target_addr, target_port, flow);
    let addr = proxy_addr.to_string();

    let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>();
    let (write_tx, write_rx) = mpsc::sync_channel::<Vec<u8>>(32);
    let (hs_tx, hs_rx) = mpsc::sync_channel::<Result<(), io::Error>>(1);

    let (tokio_write_tx, mut tokio_write_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        // Bridge sync write_rx → tokio_write_tx
        let bridge_tx = tokio_write_tx;
        std::thread::spawn(move || {
            while let Ok(data) = write_rx.recv() {
                if bridge_tx.blocking_send(data).is_err() {
                    break;
                }
            }
        });

        rt.block_on(async {
            let tcp = match tokio::net::TcpStream::connect(&addr).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = hs_tx.send(Err(io::Error::other(format!("TCP connect: {e}"))));
                    return;
                }
            };
            match xhttp_handshake(tcp, use_tls, &header).await {
                Ok((mut body, mut send_stream)) => {
                    let _ = hs_tx.send(Ok(()));

                    loop {
                        tokio::select! {
                            result = body.data() => {
                                match result {
                                    Some(Ok(data)) => {
                                        if read_tx.send(data.to_vec()).is_err() {
                                            break;
                                        }
                                    }
                                    Some(Err(_)) | None => {
                                        let _ = read_tx.send(Vec::new());
                                        break;
                                    }
                                }
                            }
                            maybe_data = tokio_write_rx.recv() => {
                                match maybe_data {
                                    Some(data) => {
                                        if send_stream.send_data(
                                            bytes::Bytes::from(data),
                                            false,
                                        ).is_err() {
                                            break;
                                        }
                                    }
                                    None => break,
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = hs_tx.send(Err(e));
                }
            }
        });
    });

    hs_rx
        .recv()
        .map_err(|_| io::Error::other("XHTTP thread panicked"))??;

    Ok(Box::new(XhttpStream {
        read_rx,
        write_tx,
        read_buf: Vec::new(),
        _handle: handle,
    }))
}
