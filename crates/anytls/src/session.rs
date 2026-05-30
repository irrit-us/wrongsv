/// sing-anytls session protocol: frame encoding, session state, reader loop.
///
/// After AnyTLS auth, sing-anytls multiplexes streams over the TLS connection
/// using 7-byte frame headers: cmd(1) | sid(4 BE) | data_len(2 BE) | data(N).
///
/// ## Concurrency model
///
/// The session reader loop **owns** the TLS connection exclusively. Stream
/// relay threads send outgoing frames through an mpsc channel. Between
/// frame reads, the reader loop drains the write channel. This prevents
/// deadlocks that would occur with `Arc<Mutex<>>` where the reader holds
/// the lock while blocking on TLS I/O.
use crate::AnyTlsError;
use rustls::ServerConnection;
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write as _};
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::stream::SingStream;

// ── Frame constants ────────────────────────────────────────────────────────

pub const CMD_WASTE: u8 = 0;
pub const CMD_SYN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_FIN: u8 = 3;
pub const CMD_SETTINGS: u8 = 4;
pub const CMD_ALERT: u8 = 5;
pub const CMD_UPDATE_PADDING: u8 = 6;
pub const CMD_SYNACK: u8 = 7;
pub const CMD_HEART_REQ: u8 = 8;
pub const CMD_HEART_RESP: u8 = 9;
pub const CMD_SERVER_SETTINGS: u8 = 10;

// ── Write channel ──────────────────────────────────────────────────────────

/// A pending outgoing frame queued by a stream relay thread.
#[derive(Debug, Clone)]
pub struct WriteJob {
    pub cmd: u8,
    pub sid: u32,
    pub data: Vec<u8>,
}

// ── Low-level frame I/O ────────────────────────────────────────────────────

/// Write a single frame (header + data), including TLS flush.
fn write_frame(
    conn: &mut ServerConnection,
    stream: &mut TcpStream,
    cmd: u8,
    sid: u32,
    data: &[u8],
) -> Result<(), AnyTlsError> {
    let data_len = data.len().min(65535) as u16;
    let header = [
        cmd,
        (sid >> 24) as u8,
        (sid >> 16) as u8,
        (sid >> 8) as u8,
        sid as u8,
        (data_len >> 8) as u8,
        data_len as u8,
    ];
    conn.writer().write_all(&header)?;
    if data_len > 0 {
        conn.writer().write_all(&data[..data_len as usize])?;
    }
    while conn.wants_write() {
        conn.write_tls(stream)?;
    }
    Ok(())
}

/// Try to read exactly `buf.len()` plaintext bytes without blocking on TCP.
/// Returns `Ok(())` on success, or an error with `WouldBlock` kind if no data
/// is currently available.
fn try_read_exact(
    conn: &mut ServerConnection,
    stream: &mut TcpStream,
    buf: &mut [u8],
) -> Result<(), AnyTlsError> {
    let want = buf.len();
    let mut got = 0;
    while got < want {
        match conn.reader().read(&mut buf[got..]) {
            Ok(n) if n > 0 => {
                got += n;
            }
            Ok(_) => {
                // No plaintext — try pulling one TLS record
                match conn.read_tls(stream) {
                    Ok(0) => {
                        return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "TLS EOF").into());
                    }
                    Ok(_) => {
                        conn.process_new_packets()
                            .map_err(|e| AnyTlsError::Tls(format!("process: {e}")))?;
                        continue;
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        return Err(std::io::Error::new(
                            ErrorKind::WouldBlock,
                            "no data available",
                        )
                        .into());
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                match conn.read_tls(stream) {
                    Ok(0) => {
                        return Err(
                            std::io::Error::new(ErrorKind::UnexpectedEof, "TLS EOF").into()
                        );
                    }
                    Ok(_) => {
                        conn.process_new_packets()
                            .map_err(|e| AnyTlsError::Tls(format!("process: {e}")))?;
                        continue;
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        return Err(std::io::Error::new(
                            ErrorKind::WouldBlock,
                            "no data available",
                        )
                        .into());
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes, blocking as needed (used for settings
/// handshake before the session loop starts).
fn read_exact(
    conn: &mut ServerConnection,
    stream: &mut TcpStream,
    buf: &mut [u8],
) -> Result<(), AnyTlsError> {
    let mut pos = 0;
    while pos < buf.len() {
        match conn.reader().read(&mut buf[pos..]) {
            Ok(0) => match conn.read_tls(stream) {
                Ok(0) => {
                    return Err(
                        std::io::Error::new(ErrorKind::UnexpectedEof, "TLS EOF").into(),
                    );
                }
                Ok(_) => {
                    conn.process_new_packets()
                        .map_err(|e| AnyTlsError::Tls(format!("process: {e}")))?;
                    continue;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => return Err(e.into()),
            },
            Ok(n) => pos += n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                match conn.read_tls(stream) {
                    Ok(0) => {
                        return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "TLS EOF").into());
                    }
                    Ok(_) => {
                        conn.process_new_packets()
                            .map_err(|e| AnyTlsError::Tls(format!("process: {e}")))?;
                        continue;
                    }
                    Err(e2) if e2.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e2) => return Err(e2.into()),
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

// ── SessionWriter ──────────────────────────────────────────────────────────

/// Thread-safe writer for sending sing-anytls frames.
///
/// Stream relay threads clone this writer and push `WriteJob`s onto an
/// internal mpsc channel. The session reader loop drains the channel
/// between frame reads and writes the frames to TLS.
pub struct SessionWriter {
    tx: Sender<WriteJob>,
}

impl SessionWriter {
    pub fn new(tx: Sender<WriteJob>) -> Self {
        Self { tx }
    }

    fn send_frame(&self, cmd: u8, sid: u32, data: &[u8]) -> Result<(), AnyTlsError> {
        let job = WriteJob {
            cmd,
            sid,
            data: data.to_vec(),
        };
        self.tx.send(job).map_err(|_| {
            AnyTlsError::Tls("session write channel closed".into())
        })?;
        Ok(())
    }

    pub fn send_psh(&self, sid: u32, data: &[u8]) -> Result<(), AnyTlsError> {
        // Split large PSH into multiple frames
        if data.len() > 65535 {
            for chunk in data.chunks(65535) {
                self.send_frame(CMD_PSH, sid, chunk)?;
            }
            Ok(())
        } else {
            self.send_frame(CMD_PSH, sid, data)
        }
    }

    pub fn send_fin(&self, sid: u32) -> Result<(), AnyTlsError> {
        self.send_frame(CMD_FIN, sid, &[])
    }

    pub fn send_synack(&self, sid: u32) -> Result<(), AnyTlsError> {
        self.send_frame(CMD_SYNACK, sid, &[])
    }

    pub fn send_synack_error(&self, sid: u32, err: &str) -> Result<(), AnyTlsError> {
        self.send_frame(CMD_SYNACK, sid, err.as_bytes())
    }
}

impl Clone for SessionWriter {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

// ── StreamHandle ───────────────────────────────────────────────────────────

struct StreamHandle {
    data_tx: Sender<Vec<u8>>,
}

// ── SingSession ────────────────────────────────────────────────────────────

pub struct SingSession {
    streams: HashMap<u32, StreamHandle>,
    pub client_version: u32,
    pub client_name: String,
}

impl SingSession {
    pub fn new(client_version: u32, client_name: String) -> Self {
        Self {
            streams: HashMap::new(),
            client_version,
            client_name,
        }
    }

    pub fn create_stream(&mut self, sid: u32) -> SingStream {
        let (tx, rx) = mpsc::channel();
        self.streams.insert(sid, StreamHandle { data_tx: tx });
        SingStream::new(sid, rx)
    }

    pub fn deliver_data(&self, sid: u32, data: Vec<u8>) {
        if let Some(handle) = self.streams.get(&sid) {
            let _ = handle.data_tx.send(data);
        }
    }

    pub fn close_stream(&mut self, sid: u32) {
        self.streams.remove(&sid);
    }
}

// ── Settings handshake ─────────────────────────────────────────────────────

/// Parsed client settings from the cmdSettings body.
pub struct ClientSettings {
    pub version: u32,
    pub client_name: String,
    #[allow(dead_code)]
    pub padding_md5: Option<String>,
}

/// Parse key=value\n lines from the settings body.
fn parse_settings(body: &[u8]) -> ClientSettings {
    let text = String::from_utf8_lossy(body);
    let mut version = 0u32;
    let mut client_name = String::from("unknown");
    let mut padding_md5 = None;

    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "v" => version = v.trim().parse().unwrap_or(0),
                "client" => client_name = v.trim().to_string(),
                "padding-md5" => padding_md5 = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    ClientSettings {
        version,
        client_name,
        padding_md5,
    }
}

/// Complete the sing-anytls settings handshake.
///
/// On entry, the first byte (0x04 = cmdSettings) has already been consumed.
/// This function takes direct ownership of conn/stream because it runs
/// before the session loop starts (no concurrent writers).
pub fn complete_settings_handshake(
    conn: &mut ServerConnection,
    stream: &mut TcpStream,
) -> Result<ClientSettings, AnyTlsError> {
    // Read remaining frame header: sid(4) + data_len(2)
    let mut hdr = [0u8; 6];
    read_exact(conn, stream, &mut hdr)?;
    let data_len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;

    let mut body = vec![0u8; data_len];
    if data_len > 0 {
        read_exact(conn, stream, &mut body)?;
    }

    let settings = parse_settings(&body);

    // If client v2+, send cmdServerSettings
    if settings.version >= 2 {
        write_frame(conn, stream, CMD_SERVER_SETTINGS, 0, b"v=2\n")?;
    }

    Ok(settings)
}

// ── Session reader loop ────────────────────────────────────────────────────

/// Run the session reader loop. Owns the TLS connection exclusively.
///
/// Stream relay threads send outgoing frames through the `write_rx` channel.
/// Between frame reads, the loop drains pending writes so stream threads
/// never deadlock waiting for the TLS connection.
///
/// For each incoming frame:
///   SYN  → create stream, call on_stream
///   PSH  → deliver data to stream
///   FIN  → close stream
///   Waste → discard
///   Alert → log and return
///   HeartRequest → respond HeartResponse
pub fn session_reader_loop<F>(
    mut conn: ServerConnection,
    mut stream: TcpStream,
    write_rx: Receiver<WriteJob>,
    writer: SessionWriter,
    on_stream: F,
) -> Result<(), AnyTlsError>
where
    F: Fn(SingStream, SessionWriter) + Send + Sync + 'static,
{
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok();

    let session = Arc::new(Mutex::new(SingSession::new(0, String::new())));
    let on_stream = Arc::new(on_stream);

    loop {
        // Try to read the next frame header
        let frame_result = {
            let mut hdr = [0u8; 7];
            match try_read_exact(&mut conn, &mut stream, &mut hdr) {
                Ok(()) => {
                    let cmd = hdr[0];
                    let sid =
                        u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
                    let data_len = u16::from_be_bytes([hdr[5], hdr[6]]);
                    Ok((cmd, sid, data_len))
                }
                Err(e) => Err(e),
            }
        };

        // Drain pending writes regardless of whether we got a frame
        while let Ok(job) = write_rx.try_recv() {
            write_frame(&mut conn, &mut stream, job.cmd, job.sid, &job.data)?;
        }

        // Now handle the frame (or lack thereof)
        let (cmd, sid, data_len) = match frame_result {
            Ok(h) => h,
            Err(AnyTlsError::Io(ref ioe)) if ioe.kind() == ErrorKind::WouldBlock => {
                // No data yet — sleep briefly and retry
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => return Err(e),
        };

        let mut data = vec![0u8; data_len as usize];
        if data_len > 0 {
            loop {
                match try_read_exact(&mut conn, &mut stream, &mut data) {
                    Ok(()) => break,
                    Err(AnyTlsError::Io(ref ioe)) if ioe.kind() == ErrorKind::WouldBlock => {
                        // Drain writes while waiting for frame data
                        while let Ok(job) = write_rx.try_recv() {
                            write_frame(
                                &mut conn,
                                &mut stream,
                                job.cmd,
                                job.sid,
                                &job.data,
                            )?;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        // Drain writes again after reading
        while let Ok(job) = write_rx.try_recv() {
            write_frame(&mut conn, &mut stream, job.cmd, job.sid, &job.data)?;
        }

        match cmd {
            CMD_SYN => {
                let mut sess = session.lock().unwrap();
                let sing_stream = sess.create_stream(sid);
                drop(sess);

                let w = writer.clone();
                let cb = Arc::clone(&on_stream);
                std::thread::spawn(move || {
                    cb(sing_stream, w);
                });
            }
            CMD_PSH => {
                let sess = session.lock().unwrap();
                sess.deliver_data(sid, data);
            }
            CMD_FIN => {
                let mut sess = session.lock().unwrap();
                sess.close_stream(sid);
            }
            CMD_WASTE => {
                // Padding — discard
            }
            CMD_ALERT => {
                let msg = String::from_utf8_lossy(&data);
                tracing::warn!("sing-anytls alert sid={sid}: {msg}");
                return Ok(());
            }
            CMD_HEART_REQ => {
                // Queue response through the write channel (handled on next
                // drain). For simplicity, write directly since we own conn.
                let _ = write_frame(
                    &mut conn,
                    &mut stream,
                    CMD_HEART_RESP,
                    sid,
                    &[],
                );
            }
            _ => {
                tracing::debug!("sing-anytls unknown cmd={cmd} sid={sid}");
            }
        }
    }
}
