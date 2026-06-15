use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::io::IoSliceMut;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use blake2::digest::{Update, VariableOutput};
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use rand::RngCore;

const SALAMANDER_SALT_LEN: usize = 8;
const SALAMANDER_KEY_LEN: usize = 32;
const SALAMANDER_MIN_PASSWORD_LEN: usize = 4;
const QUIC_OBFS_BUFFER_SIZE: usize = 2048;
const GECKO_FLAG_FRAGMENT: u8 = 0x80;
const GECKO_HEADER_SIZE: usize = 5;
const GECKO_MIN_FRAGMENT_CHUNKS: usize = 2;
const GECKO_MAX_FRAGMENT_CHUNKS: usize = 8;
const GECKO_REASSEMBLY_TTL: Duration = Duration::from_secs(8);
const GECKO_MAX_REASSEMBLY: usize = 4096;
const GECKO_MAX_PER_SOURCE: usize = 8;
pub(crate) const GECKO_DEFAULT_MIN_PACKET_SIZE: usize = 512;
pub(crate) const GECKO_DEFAULT_MAX_PACKET_SIZE: usize = 1200;

#[derive(Clone, Debug)]
pub(crate) struct SalamanderConfig {
    pub password: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct GeckoConfig {
    pub password: Vec<u8>,
    pub min_packet_size: usize,
    pub max_packet_size: usize,
}

pub(crate) fn wrap_async_udp_socket_salamander(
    inner: Arc<dyn AsyncUdpSocket>,
    password: &[u8],
) -> Result<Arc<dyn AsyncUdpSocket>, String> {
    if password.len() < SALAMANDER_MIN_PASSWORD_LEN {
        return Err(format!(
            "salamander password must be at least {SALAMANDER_MIN_PASSWORD_LEN} bytes"
        ));
    }
    Ok(Arc::new(SalamanderAsyncUdpSocket {
        inner,
        password: password.to_vec(),
        recv_buf: Mutex::new(vec![0u8; QUIC_OBFS_BUFFER_SIZE]),
        send_buf: Mutex::new(vec![0u8; QUIC_OBFS_BUFFER_SIZE]),
        pending_recv: Mutex::new(VecDeque::new()),
    }))
}

pub(crate) fn wrap_async_udp_socket_gecko(
    inner: Arc<dyn AsyncUdpSocket>,
    password: &[u8],
    min_packet_size: usize,
    max_packet_size: usize,
) -> Result<Arc<dyn AsyncUdpSocket>, String> {
    if min_packet_size == 0
        || max_packet_size == 0
        || min_packet_size > max_packet_size
        || max_packet_size > QUIC_OBFS_BUFFER_SIZE
    {
        return Err("gecko packet-size range is invalid".into());
    }
    let inner = wrap_async_udp_socket_salamander(inner, password)?;
    Ok(Arc::new(GeckoAsyncUdpSocket::new(
        inner,
        min_packet_size,
        max_packet_size,
    )))
}

struct SalamanderAsyncUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    password: Vec<u8>,
    recv_buf: Mutex<Vec<u8>>,
    send_buf: Mutex<Vec<u8>>,
    pending_recv: Mutex<VecDeque<(Vec<u8>, RecvMeta)>>,
}

impl fmt::Debug for SalamanderAsyncUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderAsyncUdpSocket")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for SalamanderAsyncUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let mut send_buf = self
            .send_buf
            .lock()
            .expect("salamander send mutex poisoned");
        let required_len = if let Some(segment_size) = transmit.segment_size {
            let segment_count = transmit.contents.len().div_ceil(segment_size);
            transmit.contents.len() + segment_count * SALAMANDER_SALT_LEN
        } else {
            transmit.contents.len() + SALAMANDER_SALT_LEN
        };
        if send_buf.len() < required_len {
            send_buf.resize(required_len, 0);
        }
        let (encoded_len, segment_size) =
            salamander_obfuscate_transmit(&self.password, transmit, &mut send_buf);
        let wrapped = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &send_buf[..encoded_len],
            segment_size,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&wrapped)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if let Some((packet, packet_meta)) = self
            .pending_recv
            .lock()
            .expect("salamander pending recv mutex poisoned")
            .pop_front()
        {
            let out: &mut [u8] = &mut bufs[0];
            let copy_len = packet.len().min(out.len());
            out[..copy_len].copy_from_slice(&packet[..copy_len]);
            meta[0] = packet_meta;
            meta[0].len = copy_len;
            meta[0].stride = copy_len;
            return Poll::Ready(Ok(1));
        }

        loop {
            let mut recv_buf = self
                .recv_buf
                .lock()
                .expect("salamander recv mutex poisoned");
            let mut recv_meta = [RecvMeta::default()];
            let mut recv_slices = [IoSliceMut::new(recv_buf.as_mut_slice())];
            match self.inner.poll_recv(cx, &mut recv_slices, &mut recv_meta) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                Poll::Ready(Ok(_count)) => {
                    let raw_len = recv_meta[0].len;
                    let stride = recv_meta[0].stride.max(raw_len);
                    let mut pending = self
                        .pending_recv
                        .lock()
                        .expect("salamander pending recv mutex poisoned");
                    let mut offset = 0usize;
                    while offset < raw_len {
                        let packet_len = recv_meta[0].stride.max(1).min(raw_len - offset);
                        let packet = &recv_buf[offset..offset + packet_len];
                        let mut decoded = vec![0u8; packet_len];
                        if let Some(decoded_len) =
                            salamander_deobfuscate(&self.password, packet, &mut decoded)
                        {
                            decoded.truncate(decoded_len);
                            let mut packet_meta = recv_meta[0];
                            packet_meta.len = decoded_len;
                            packet_meta.stride = decoded_len;
                            pending.push_back((decoded, packet_meta));
                        }
                        offset += stride.min(raw_len - offset);
                    }
                    drop(pending);
                    if let Some((packet, packet_meta)) = self
                        .pending_recv
                        .lock()
                        .expect("salamander pending recv mutex poisoned")
                        .pop_front()
                    {
                        let out: &mut [u8] = &mut bufs[0];
                        let copy_len = packet.len().min(out.len());
                        out[..copy_len].copy_from_slice(&packet[..copy_len]);
                        meta[0] = packet_meta;
                        meta[0].len = copy_len;
                        meta[0].stride = copy_len;
                        return Poll::Ready(Ok(1));
                    }
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[derive(Clone, Copy)]
struct GeckoFrameHeader {
    pad_len: u16,
    msg_id: u8,
    chunk_idx: u8,
    total_chunks: u8,
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct GeckoReassemblyKey {
    addr: String,
    msg_id: u8,
}

struct GeckoReassemblyEntry {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    total: u8,
    deadline: Instant,
}

struct GeckoAsyncUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    min_packet_size: usize,
    max_packet_size: usize,
    recv_buf: Mutex<Vec<u8>>,
    send_buf: Mutex<Vec<u8>>,
    msg_id: AtomicU32,
    reassembly: Mutex<std::collections::HashMap<GeckoReassemblyKey, GeckoReassemblyEntry>>,
    per_source: Mutex<std::collections::HashMap<String, usize>>,
}

impl GeckoAsyncUdpSocket {
    fn new(inner: Arc<dyn AsyncUdpSocket>, min_packet_size: usize, max_packet_size: usize) -> Self {
        Self {
            inner,
            min_packet_size,
            max_packet_size,
            recv_buf: Mutex::new(vec![0u8; QUIC_OBFS_BUFFER_SIZE]),
            send_buf: Mutex::new(vec![0u8; QUIC_OBFS_BUFFER_SIZE * GECKO_MAX_FRAGMENT_CHUNKS]),
            msg_id: AtomicU32::new(0),
            reassembly: Mutex::new(std::collections::HashMap::new()),
            per_source: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn next_msg_id(&self) -> u8 {
        self.msg_id.fetch_add(1, Ordering::Relaxed) as u8
    }

    fn choose_fragment_target_size(&self, payload_len: usize, chunks: usize) -> usize {
        let chunk_payload_max = payload_len.div_ceil(chunks);
        let lower = self
            .min_packet_size
            .max(GECKO_HEADER_SIZE + chunk_payload_max);
        if lower >= self.max_packet_size {
            lower
        } else {
            lower + rand::thread_rng().next_u32() as usize % (self.max_packet_size - lower + 1)
        }
    }

    fn gc_reassembly_locked(
        reassembly: &mut std::collections::HashMap<GeckoReassemblyKey, GeckoReassemblyEntry>,
        per_source: &mut std::collections::HashMap<String, usize>,
    ) {
        let now = Instant::now();
        let expired: Vec<_> = reassembly
            .iter()
            .filter(|(_, entry)| now > entry.deadline)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            Self::drop_reassembly_entry_locked(reassembly, per_source, &key);
        }
        while reassembly.len() >= GECKO_MAX_REASSEMBLY {
            if let Some((oldest_key, _)) = reassembly
                .iter()
                .min_by_key(|(_, entry)| entry.deadline)
                .map(|(key, entry)| (key.clone(), entry.deadline))
            {
                Self::drop_reassembly_entry_locked(reassembly, per_source, &oldest_key);
            } else {
                break;
            }
        }
    }

    fn drop_reassembly_entry_locked(
        reassembly: &mut std::collections::HashMap<GeckoReassemblyKey, GeckoReassemblyEntry>,
        per_source: &mut std::collections::HashMap<String, usize>,
        key: &GeckoReassemblyKey,
    ) {
        if reassembly.remove(key).is_some()
            && let Some(count) = per_source.get_mut(&key.addr)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                per_source.remove(&key.addr);
            }
        }
    }
}

impl fmt::Debug for GeckoAsyncUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeckoAsyncUdpSocket")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for GeckoAsyncUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if transmit.contents.is_empty() || transmit.contents[0] & 0x80 == 0 {
            return self.inner.try_send(transmit);
        }

        let chunk_count = (GECKO_MIN_FRAGMENT_CHUNKS
            + (rand::thread_rng().next_u32() as usize
                % (GECKO_MAX_FRAGMENT_CHUNKS - GECKO_MIN_FRAGMENT_CHUNKS + 1)))
            .max(1);
        let chunk_count = chunk_count.min(transmit.contents.len().max(1));
        let target_size = self.choose_fragment_target_size(transmit.contents.len(), chunk_count);
        let payload_chunk_size = transmit.contents.len().div_ceil(chunk_count);
        let msg_id = self.next_msg_id();

        let mut send_buf = self.send_buf.lock().expect("gecko send mutex poisoned");
        for chunk_idx in 0..chunk_count {
            let start = chunk_idx * payload_chunk_size;
            let end = (start + payload_chunk_size).min(transmit.contents.len());
            if start >= end {
                break;
            }
            let payload = &transmit.contents[start..end];
            let pad_len = target_size
                .checked_sub(GECKO_HEADER_SIZE + payload.len())
                .unwrap_or_default();
            let header = GeckoFrameHeader {
                pad_len: pad_len as u16,
                msg_id,
                chunk_idx: chunk_idx as u8,
                total_chunks: chunk_count as u8,
            };
            let written = encode_gecko_frame(header, payload, &mut send_buf[..target_size])
                .map_err(io::Error::other)?;
            let fragment = Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &send_buf[..written],
                segment_size: None,
                src_ip: transmit.src_ip,
            };
            self.inner.try_send(&fragment)?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            let mut recv_buf = self.recv_buf.lock().expect("gecko recv mutex poisoned");
            let mut recv_meta = [RecvMeta::default()];
            let mut recv_slices = [IoSliceMut::new(recv_buf.as_mut_slice())];
            match self.inner.poll_recv(cx, &mut recv_slices, &mut recv_meta) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                Poll::Ready(Ok(_)) => {
                    let raw_len = recv_meta[0].len;
                    let packet = &recv_buf[..raw_len];
                    if packet.is_empty() || packet[0] & GECKO_FLAG_FRAGMENT == 0 {
                        let out: &mut [u8] = &mut bufs[0];
                        let copy_len = packet.len().min(out.len());
                        out[..copy_len].copy_from_slice(&packet[..copy_len]);
                        meta[0] = recv_meta[0];
                        meta[0].len = copy_len;
                        meta[0].stride = copy_len;
                        return Poll::Ready(Ok(1));
                    }
                    let Ok((header, payload)) = decode_gecko_frame(packet) else {
                        continue;
                    };
                    let source = recv_meta[0].addr.to_string();
                    let mut reassembly = self.reassembly.lock().expect("gecko reassembly poisoned");
                    let mut per_source = self.per_source.lock().expect("gecko per-source poisoned");
                    Self::gc_reassembly_locked(&mut reassembly, &mut per_source);
                    let key = GeckoReassemblyKey {
                        addr: source.clone(),
                        msg_id: header.msg_id,
                    };
                    if !reassembly.contains_key(&key) {
                        if per_source.get(&source).copied().unwrap_or_default()
                            >= GECKO_MAX_PER_SOURCE
                        {
                            continue;
                        }
                        per_source
                            .entry(source.clone())
                            .and_modify(|count| *count += 1)
                            .or_insert(1);
                        reassembly.insert(
                            key.clone(),
                            GeckoReassemblyEntry {
                                chunks: vec![None; header.total_chunks as usize],
                                received: 0,
                                total: header.total_chunks,
                                deadline: Instant::now() + GECKO_REASSEMBLY_TTL,
                            },
                        );
                    }
                    let entry = reassembly.get_mut(&key).expect("gecko entry should exist");
                    if entry.total != header.total_chunks
                        || header.chunk_idx as usize >= entry.chunks.len()
                        || entry.chunks[header.chunk_idx as usize].is_some()
                    {
                        continue;
                    }
                    entry.chunks[header.chunk_idx as usize] = Some(payload.to_vec());
                    entry.received += 1;
                    if entry.received < entry.total as usize {
                        continue;
                    }
                    let out: &mut [u8] = &mut bufs[0];
                    let total_len: usize = entry
                        .chunks
                        .iter()
                        .filter_map(|chunk| chunk.as_ref())
                        .map(Vec::len)
                        .sum();
                    if total_len > out.len() {
                        Self::drop_reassembly_entry_locked(&mut reassembly, &mut per_source, &key);
                        continue;
                    }
                    let mut cursor = 0usize;
                    for chunk in entry.chunks.iter().filter_map(|chunk| chunk.as_ref()) {
                        out[cursor..cursor + chunk.len()].copy_from_slice(chunk);
                        cursor += chunk.len();
                    }
                    Self::drop_reassembly_entry_locked(&mut reassembly, &mut per_source, &key);
                    meta[0] = recv_meta[0];
                    meta[0].len = total_len;
                    meta[0].stride = total_len;
                    return Poll::Ready(Ok(1));
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

fn salamander_obfuscate(password: &[u8], input: &[u8], out: &mut [u8]) -> usize {
    let salt = &mut out[..SALAMANDER_SALT_LEN];
    rand::thread_rng().fill_bytes(salt);
    let key = salamander_key(password, salt);
    for (idx, byte) in input.iter().enumerate() {
        out[SALAMANDER_SALT_LEN + idx] = byte ^ key[idx % SALAMANDER_KEY_LEN];
    }
    SALAMANDER_SALT_LEN + input.len()
}

fn salamander_obfuscate_transmit(
    password: &[u8],
    transmit: &Transmit,
    out: &mut [u8],
) -> (usize, Option<usize>) {
    if let Some(segment_size) = transmit.segment_size {
        let mut read_offset = 0usize;
        let mut write_offset = 0usize;
        while read_offset < transmit.contents.len() {
            let end = (read_offset + segment_size).min(transmit.contents.len());
            let written = salamander_obfuscate(
                password,
                &transmit.contents[read_offset..end],
                &mut out[write_offset..],
            );
            write_offset += written;
            read_offset = end;
        }
        (write_offset, Some(segment_size + SALAMANDER_SALT_LEN))
    } else {
        (salamander_obfuscate(password, transmit.contents, out), None)
    }
}

fn salamander_deobfuscate(password: &[u8], input: &[u8], out: &mut [u8]) -> Option<usize> {
    if input.len() <= SALAMANDER_SALT_LEN {
        return None;
    }
    let payload_len = input.len() - SALAMANDER_SALT_LEN;
    if out.len() < payload_len {
        return None;
    }
    let salt = &input[..SALAMANDER_SALT_LEN];
    let key = salamander_key(password, salt);
    for (idx, byte) in input[SALAMANDER_SALT_LEN..].iter().enumerate() {
        out[idx] = byte ^ key[idx % SALAMANDER_KEY_LEN];
    }
    Some(payload_len)
}

fn salamander_key(password: &[u8], salt: &[u8]) -> [u8; SALAMANDER_KEY_LEN] {
    let mut hasher =
        blake2::Blake2bVar::new(SALAMANDER_KEY_LEN).expect("salamander key length should be valid");
    hasher.update(password);
    hasher.update(salt);
    let mut key = [0u8; SALAMANDER_KEY_LEN];
    hasher
        .finalize_variable(&mut key)
        .expect("salamander key output buffer should be valid");
    key
}

fn encode_gecko_frame(
    header: GeckoFrameHeader,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, String> {
    if header.total_chunks < GECKO_MIN_FRAGMENT_CHUNKS as u8
        || header.total_chunks > GECKO_MAX_FRAGMENT_CHUNKS as u8
        || header.chunk_idx >= header.total_chunks
    {
        return Err("invalid gecko frame header".into());
    }
    let needed = GECKO_HEADER_SIZE + header.pad_len as usize + payload.len();
    if out.len() < needed {
        return Err("gecko frame buffer too small".into());
    }
    out[0] = GECKO_FLAG_FRAGMENT;
    out[1] = header.msg_id;
    out[2] = (header.chunk_idx << 4) | (header.total_chunks & 0x0f);
    out[3..5].copy_from_slice(&header.pad_len.to_be_bytes());
    rand::thread_rng()
        .fill_bytes(&mut out[GECKO_HEADER_SIZE..GECKO_HEADER_SIZE + header.pad_len as usize]);
    out[GECKO_HEADER_SIZE + header.pad_len as usize..needed].copy_from_slice(payload);
    Ok(needed)
}

fn decode_gecko_frame(input: &[u8]) -> Result<(GeckoFrameHeader, &[u8]), String> {
    if input.len() < GECKO_HEADER_SIZE || input[0] & GECKO_FLAG_FRAGMENT == 0 {
        return Err("invalid gecko frame".into());
    }
    let header = GeckoFrameHeader {
        msg_id: input[1],
        chunk_idx: input[2] >> 4,
        total_chunks: input[2] & 0x0f,
        pad_len: u16::from_be_bytes([input[3], input[4]]),
    };
    if header.total_chunks < GECKO_MIN_FRAGMENT_CHUNKS as u8
        || header.total_chunks > GECKO_MAX_FRAGMENT_CHUNKS as u8
        || header.chunk_idx >= header.total_chunks
    {
        return Err("invalid gecko chunk counters".into());
    }
    let payload_offset = GECKO_HEADER_SIZE + header.pad_len as usize;
    if payload_offset > input.len() {
        return Err("truncated gecko frame".into());
    }
    Ok((header, &input[payload_offset..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salamander_roundtrip() {
        let password = b"secret-psk";
        let mut obfuscated = vec![0u8; QUIC_OBFS_BUFFER_SIZE];
        let encoded_len = salamander_obfuscate(password, b"hello", &mut obfuscated);
        let mut decoded = [0u8; 16];
        let decoded_len =
            salamander_deobfuscate(password, &obfuscated[..encoded_len], &mut decoded).unwrap();
        assert_eq!(&decoded[..decoded_len], b"hello");
    }

    #[test]
    fn gecko_frame_roundtrip() {
        let header = GeckoFrameHeader {
            pad_len: 7,
            msg_id: 4,
            chunk_idx: 1,
            total_chunks: 3,
        };
        let mut encoded = vec![0u8; 64];
        let written = encode_gecko_frame(header, b"hello", &mut encoded).unwrap();
        let (decoded_header, payload) = decode_gecko_frame(&encoded[..written]).unwrap();
        assert_eq!(decoded_header.msg_id, 4);
        assert_eq!(decoded_header.chunk_idx, 1);
        assert_eq!(decoded_header.total_chunks, 3);
        assert_eq!(payload, b"hello");
    }
}
