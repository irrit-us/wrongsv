use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use tracing::{debug, trace};
use wrongsv_protocol::{RequestCommand, RequestHeader};
use wrongsv_vless::MemoryValidator;

use super::*;

#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestSessionRegistryConfig {
    pub max_response_bytes: usize,
    pub max_buffered_response_bytes: usize,
    pub idle_timeout: Duration,
}

pub(crate) struct RequestSessionRegistry {
    sessions: Mutex<HashMap<String, Arc<RequestSession>>>,
    config: RequestSessionRegistryConfig,
}

pub(crate) struct RequestSessionLease {
    pub session: Arc<RequestSession>,
    pub stream: Option<RequestSessionStream>,
}

impl RequestSessionRegistry {
    pub(crate) fn new(config: RequestSessionRegistryConfig) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            config,
        }
    }

    pub(crate) fn acquire(&self, session_id: &str) -> RequestSessionLease {
        let mut sessions = self.sessions.lock().unwrap();
        self.cleanup_locked(&mut sessions);

        if let Some(session) = sessions.get(session_id).cloned()
            && !session.is_closed()
        {
            return RequestSessionLease {
                session,
                stream: None,
            };
        }

        let (session, stream) = RequestSession::new(
            self.config.max_response_bytes,
            self.config.max_buffered_response_bytes,
        );
        sessions.insert(session_id.to_string(), Arc::clone(&session));
        RequestSessionLease {
            session,
            stream: Some(stream),
        }
    }

    pub(crate) fn remove(&self, session_id: &str) {
        if let Some(session) = self.sessions.lock().unwrap().remove(session_id) {
            session.close();
        }
    }

    fn cleanup_locked(&self, sessions: &mut HashMap<String, Arc<RequestSession>>) {
        if self.config.idle_timeout.is_zero() {
            sessions.retain(|_, session| !session.is_closed());
            return;
        }

        let idle_timeout = self.config.idle_timeout;
        sessions.retain(|_, session| {
            let expired = session.is_closed() || session.idle_for() >= idle_timeout;
            if expired {
                session.close();
                false
            } else {
                true
            }
        });
    }
}

struct OutgoingState {
    buffer: VecDeque<u8>,
}

pub(crate) struct RequestSession {
    incoming_tx: Mutex<Option<SyncSender<Vec<u8>>>>,
    outgoing: Mutex<OutgoingState>,
    outgoing_cv: Condvar,
    roundtrip_lock: Mutex<()>,
    closed: AtomicBool,
    last_activity: Mutex<Instant>,
    max_response_bytes: usize,
    max_buffered_response_bytes: usize,
}

impl RequestSession {
    fn new(
        max_response_bytes: usize,
        max_buffered_response_bytes: usize,
    ) -> (Arc<Self>, RequestSessionStream) {
        let (incoming_tx, incoming_rx) = mpsc::sync_channel::<Vec<u8>>(64);
        let session = Arc::new(Self {
            incoming_tx: Mutex::new(Some(incoming_tx)),
            outgoing: Mutex::new(OutgoingState {
                buffer: VecDeque::new(),
            }),
            outgoing_cv: Condvar::new(),
            roundtrip_lock: Mutex::new(()),
            closed: AtomicBool::new(false),
            last_activity: Mutex::new(Instant::now()),
            max_response_bytes: max_response_bytes.max(1),
            max_buffered_response_bytes: max_buffered_response_bytes.max(max_response_bytes).max(1),
        });
        let stream = RequestSessionStream {
            incoming_rx,
            pending: Vec::new(),
            eof: false,
            session: Arc::clone(&session),
        };
        (session, stream)
    }

    pub(crate) fn submit_roundtrip(
        &self,
        body: &[u8],
        wait_for_response: bool,
        poll_wait: Duration,
    ) -> io::Result<Vec<u8>> {
        let _guard = self.roundtrip_lock.lock().unwrap();
        self.touch();
        if !body.is_empty() {
            self.send_incoming(body)?;
        }
        self.read_outgoing(wait_for_response, poll_wait)
    }

    pub(crate) fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.touch();
        let _ = self.incoming_tx.lock().unwrap().take();
        self.outgoing_cv.notify_all();
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub(crate) fn idle_for(&self) -> Duration {
        self.last_activity.lock().unwrap().elapsed()
    }

    fn touch(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    fn send_incoming(&self, body: &[u8]) -> io::Result<()> {
        let sender = self
            .incoming_tx
            .lock()
            .unwrap()
            .as_ref()
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "request session closed"))?;
        sender
            .send(body.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "request session closed"))
    }

    fn read_outgoing(&self, wait_for_response: bool, poll_wait: Duration) -> io::Result<Vec<u8>> {
        let mut outgoing = self.outgoing.lock().unwrap();
        if outgoing.buffer.is_empty() && wait_for_response && poll_wait > Duration::ZERO && !self.is_closed() {
            let (next, _timeout) = self
                .outgoing_cv
                .wait_timeout_while(outgoing, poll_wait, |state| {
                    state.buffer.is_empty() && !self.is_closed()
                })
                .unwrap();
            outgoing = next;
        }
        let data = drain_buffer(&mut outgoing.buffer, self.max_response_bytes);
        self.outgoing_cv.notify_all();
        Ok(data)
    }

    fn push_outgoing(&self, buf: &[u8]) -> io::Result<usize> {
        let mut outgoing = self.outgoing.lock().unwrap();
        while outgoing.buffer.len() >= self.max_buffered_response_bytes && !self.is_closed() {
            outgoing = self.outgoing_cv.wait(outgoing).unwrap();
        }
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "request session closed",
            ));
        }
        self.touch();
        outgoing.buffer.extend(buf.iter().copied());
        self.outgoing_cv.notify_all();
        Ok(buf.len())
    }
}

fn drain_buffer(buffer: &mut VecDeque<u8>, max_len: usize) -> Vec<u8> {
    let len = buffer.len().min(max_len);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        if let Some(byte) = buffer.pop_front() {
            out.push(byte);
        }
    }
    out
}

pub(crate) struct RequestSessionStream {
    incoming_rx: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    eof: bool,
    session: Arc<RequestSession>,
}

pub(crate) struct RequestSessionReader {
    incoming_rx: Receiver<Vec<u8>>,
    pending: Vec<u8>,
    eof: bool,
}

#[derive(Clone)]
pub(crate) struct RequestSessionWriter {
    session: Arc<RequestSession>,
}

impl RequestSessionStream {
    pub(crate) fn split(self) -> (RequestSessionReader, RequestSessionWriter) {
        (
            RequestSessionReader {
                incoming_rx: self.incoming_rx,
                pending: self.pending,
                eof: self.eof,
            },
            RequestSessionWriter {
                session: Arc::clone(&self.session),
            },
        )
    }

    pub(crate) fn close(&self) {
        self.session.close();
    }

    fn session_handle(&self) -> Arc<RequestSession> {
        Arc::clone(&self.session)
    }
}

impl Read for RequestSessionReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }
        if self.eof {
            return Ok(0);
        }
        match self.incoming_rx.recv() {
            Ok(data) => {
                if data.len() <= buf.len() {
                    let n = data.len();
                    buf[..n].copy_from_slice(&data);
                    Ok(n)
                } else {
                    let n = buf.len();
                    buf[..n].copy_from_slice(&data[..n]);
                    self.pending.extend_from_slice(&data[n..]);
                    Ok(n)
                }
            }
            Err(_) => {
                self.eof = true;
                Ok(0)
            }
        }
    }
}

impl Read for RequestSessionStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }
        if self.eof {
            return Ok(0);
        }
        match self.incoming_rx.recv() {
            Ok(data) => {
                if data.len() <= buf.len() {
                    let n = data.len();
                    buf[..n].copy_from_slice(&data);
                    Ok(n)
                } else {
                    let n = buf.len();
                    buf[..n].copy_from_slice(&data[..n]);
                    self.pending.extend_from_slice(&data[n..]);
                    Ok(n)
                }
            }
            Err(_) => {
                self.eof = true;
                Ok(0)
            }
        }
    }
}

impl Write for RequestSessionWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.session.push_outgoing(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for RequestSessionStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.session.push_outgoing(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn handle_vless_over_request_stream(
    mut stream: RequestSessionStream,
    validator: Arc<MemoryValidator>,
    kyber_sk: Option<[u8; 64]>,
    peer_label: &str,
    metrics: Arc<wrongsv_metrics::Registry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut first = vec![0u8; 8192];
    let n = stream.read(&mut first)?;
    if n == 0 {
        return Err("request transport closed before VLESS header".into());
    }
    first.truncate(n);
    trace!("{peer_label} request transport read {} bytes VLESS header", first.len());

    let VlessRequest {
        decoded,
        remaining_body,
        use_vision,
    } = decode_vless_request(first, &validator, peer_label)?;

    let request = &decoded.header;
    let account = &request.user.account;

    log_vless_request(peer_label, request);
    trace!(
        "{peer_label} request transport flow={} use_vision={use_vision}",
        decoded.addons.flow
    );
    handle_kyber_addons(peer_label, &decoded, kyber_sk);
    validate_vless_command(request, use_vision)?;
    let tap = wrongsv_metrics::MetricsTap::new(metrics, request.user.email.clone());
    let _conn_guard = tap.track_connection();

    let resp_buf = response_header_buf(request)?;
    stream.write_all(&resp_buf)?;

    if request.command == RequestCommand::Udp {
        if !account.udp {
            return Err("UDP not enabled for this user".into());
        }
        relay_request_stream_udp(&mut stream, request, remaining_body, tap)?;
        debug!("{peer_label} request transport UDP relay finished");
        return Ok(());
    }

    let target = connect_tcp_target(&request.address, request.port)?;
    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_secs(300)))?;

    if use_vision {
        relay_request_stream_vision(
            &mut stream,
            target,
            &decoded.user_sent_id,
            &account.testseed,
            remaining_body,
            tap,
        )?;
    } else {
        relay_request_stream_raw(stream, target, remaining_body, tap)?;
    }
    debug!("{peer_label} request transport relay finished");
    Ok(())
}

fn relay_request_stream_raw(
    client: RequestSessionStream,
    mut target: TcpStream,
    initial_data: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    target.set_nodelay(true)?;
    if !initial_data.is_empty() {
        metrics.record_in(initial_data.len() as u64);
        target.write_all(&initial_data)?;
    }
    let session = client.session_handle();
    let (mut reader, mut writer) = client.split();
    let mut target_write = target.try_clone()?;
    let mut target_read = target;
    let metrics_up = metrics.clone();
    let metrics_down = metrics;

    let up = std::thread::spawn(move || {
        let mut buf = [0u8; 32768];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    metrics_up.record_in(n as u64);
                    if let Err(e) = target_write.write_all(&buf[..n]) {
                        debug!("request transport uplink write error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("request transport uplink read error: {e}");
                    break;
                }
            }
        }
        let _ = target_write.shutdown(std::net::Shutdown::Write);
    });

    let down = std::thread::spawn(move || {
        let mut buf = [0u8; 32768];
        loop {
            match target_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    metrics_down.record_out(n as u64);
                    if let Err(e) = writer.write_all(&buf[..n]) {
                        debug!("request transport downlink write error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("request transport downlink read error: {e}");
                    break;
                }
            }
        }
    });

    let _ = up.join();
    let _ = down.join();
    session.close();
    Ok(())
}

fn relay_request_stream_vision(
    client: &mut RequestSessionStream,
    mut target: TcpStream,
    user_sent_id: &[u8],
    testseed: &[u32],
    initial_data: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    let up_seed = if testseed.len() >= 4 {
        testseed.to_vec()
    } else {
        vec![900, 500, 900, 256]
    };
    let mut up_state = wrongsv_vless::vision::TrafficState::new(user_sent_id);
    let mut down_state = wrongsv_vless::vision::TrafficState::new(user_sent_id);
    let mut down_user_uuid: Option<[u8; 16]> = Some(down_state.user_uuid);

    target.set_nodelay(true)?;
    target.set_read_timeout(Some(Duration::from_millis(10)))?;
    let mut buf = [0u8; 32768];

    if !initial_data.is_empty() {
        let unpadded = wrongsv_vless::vision::xtls_unpadding(&initial_data, &mut up_state, true);
        if !unpadded.is_empty() {
            metrics.record_in(unpadded.len() as u64);
            target.write_all(&unpadded)?;
            target.set_read_timeout(Some(Duration::from_millis(10)))?;
        }
    }

    loop {
        let down_done = loop {
            match target.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => {
                    let mut encoded = Vec::with_capacity(n + 256);
                    {
                        struct BufWriter<'a>(&'a mut Vec<u8>);
                        impl Write for BufWriter<'_> {
                            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                                self.0.extend_from_slice(data);
                                Ok(data.len())
                            }
                            fn flush(&mut self) -> io::Result<()> {
                                Ok(())
                            }
                        }
                        let mut writer = wrongsv_vless::vision::VisionWriter::new(
                            BufWriter(&mut encoded),
                            down_state.clone(),
                            false,
                            up_seed.clone(),
                        );
                        writer.user_uuid = down_user_uuid.take();
                        writer.write(&buf[..n])?;
                        writer.flush()?;
                        down_state = writer.state;
                        down_user_uuid = writer.user_uuid;
                    }
                    if !encoded.is_empty() {
                        metrics.record_out(n as u64);
                        client.write_all(&encoded)?;
                    }
                    target.set_read_timeout(Some(Duration::from_millis(10)))?;
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    target.set_read_timeout(Some(Duration::from_millis(10)))?;
                    break false;
                }
                Err(e) => return Err(e.into()),
            }
        };

        let up_done = loop {
            match client.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => {
                    let unpadded =
                        wrongsv_vless::vision::xtls_unpadding(&buf[..n], &mut up_state, true);
                    if !unpadded.is_empty() {
                        metrics.record_in(unpadded.len() as u64);
                        target.write_all(&unpadded)?;
                        target.set_read_timeout(Some(Duration::from_millis(10)))?;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break false,
                Err(e) => return Err(e.into()),
            }
        };

        if up_done {
            let _ = target.shutdown(std::net::Shutdown::Write);
        }
        if down_done {
            break;
        }
        if up_done && down_done {
            break;
        }
    }

    client.close();
    Ok(())
}

fn relay_request_stream_udp(
    client: &mut RequestSessionStream,
    request: &RequestHeader,
    remaining: Vec<u8>,
    metrics: wrongsv_metrics::MetricsTap,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Cursor, ErrorKind};
    use wrongsv_vless_encoding::{LengthPacketReader, LengthPacketWriter, PacketReadError};

    let target_addr = format!("{}:{}", request.address, request.port);
    debug!("request transport UDP relay to {target_addr}");

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(&target_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut buf = [0u8; 65535];

    if !remaining.is_empty() {
        let mut reader = LengthPacketReader::new(Cursor::new(&remaining));
        while let Ok(pkt) = reader.read_packet() {
            metrics.record_in(pkt.len() as u64);
            socket.send(&pkt)?;
        }
    }

    loop {
        let request_data = {
            let mut tmp = [0u8; 65535];
            match client.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    let mut reader = LengthPacketReader::new(Cursor::new(&tmp[..n]));
                    let mut packets = Vec::new();
                    loop {
                        match reader.read_packet() {
                            Ok(pkt) => packets.push(pkt),
                            Err(PacketReadError::Io(ref e))
                                if e.kind() == ErrorKind::UnexpectedEof =>
                            {
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                    Some(packets)
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => None,
                Err(e) => return Err(e.into()),
            }
        };

        if let Some(packets) = request_data {
            for pkt in packets {
                metrics.record_in(pkt.len() as u64);
                socket.send(&pkt)?;
            }
        }

        match socket.recv(&mut buf) {
            Ok(n) => {
                metrics.record_out(n as u64);
                let mut out = Vec::with_capacity(n + 2);
                {
                    let mut writer = LengthPacketWriter::new(&mut out);
                    writer.write_packet(&buf[..n])?;
                }
                client.write_all(&out)?;
            }
            Err(ref e)
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(e.into()),
        }
    }

    client.close();
    Ok(())
}
