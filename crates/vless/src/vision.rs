/// XTLS Vision (xtls-rprx-vision) — padding/unpadding layer for VLESS traffic.
///
/// Vision adds random-length padding to TLS application data records to
/// eliminate packet-length fingerprinting. It also monitors the connection
/// for TLS 1.3 handshake detection so it can switch to direct-copy mode
/// (splice) once the TLS layer is confirmed.
///
/// Wire format for each padded frame:
///   [user_uuid(16)] command(1) content_len(2) padding_len(2) content(var) padding(var)
///
/// The user_uuid is only written on the very first frame per direction.
use rand::Rng;
use std::io::{Read, Write};

// ── Constants ──────────────────────────────────────────────────────────────

/// TLS 1.3 application data record start bytes.
const TLS_APP_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
/// TLS ClientHello start.
const TLS_CLIENT_HELLO: [u8; 2] = [0x16, 0x03];
/// TLS ServerHello start.
const TLS_SERVER_HELLO: [u8; 3] = [0x16, 0x03, 0x03];
/// TLS 1.3 supported versions extension.
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

/// Handshake types.
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;

/// Padding commands.
pub const CMD_PADDING_CONTINUE: u8 = 0x00;
pub const CMD_PADDING_END: u8 = 0x01;
pub const CMD_PADDING_DIRECT: u8 = 0x02;

pub const TLS13_CIPHER_SUITES: &[(u16, &str)] = &[
    (0x1301, "TLS_AES_128_GCM_SHA256"),
    (0x1302, "TLS_AES_256_GCM_SHA384"),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
    (0x1304, "TLS_AES_128_CCM_SHA256"),
    (0x1305, "TLS_AES_128_CCM_8_SHA256"),
];

// ── Traffic State ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrafficState {
    pub user_uuid: [u8; 16],
    /// How many initial packets to filter for TLS detection.
    pub number_of_packet_to_filter: i32,
    /// Whether XTLS direct-copy (splice) mode is enabled.
    pub enable_xtls: bool,
    /// True if the connection is TLS 1.2 or above.
    pub is_tls12_or_above: bool,
    /// True if the connection is TLS (any version).
    pub is_tls: bool,
    /// Detected cipher suite.
    pub cipher: u16,
    /// Bytes remaining in ServerHello message.
    pub remaining_server_hello: i32,
    /// Inbound direction state.
    pub inbound: DirectionState,
    /// Outbound direction state.
    pub outbound: DirectionState,
}

#[derive(Debug, Clone, Default)]
pub struct DirectionState {
    pub within_padding_buffers: bool,
    pub direct_copy: bool,
    pub remaining_command: i32,
    pub remaining_content: i32,
    pub remaining_padding: i32,
    pub current_command: i32,
    pub is_padding: bool,
}

impl TrafficState {
    pub fn new(user_uuid: &[u8]) -> Self {
        let mut uuid = [0u8; 16];
        let len = user_uuid.len().min(16);
        uuid[..len].copy_from_slice(&user_uuid[..len]);
        TrafficState {
            user_uuid: uuid,
            number_of_packet_to_filter: 8,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: -1,
            inbound: DirectionState {
                within_padding_buffers: true,
                direct_copy: false,
                remaining_command: -1,
                remaining_content: -1,
                remaining_padding: -1,
                current_command: 0,
                is_padding: true,
            },
            outbound: DirectionState {
                within_padding_buffers: true,
                direct_copy: false,
                remaining_command: -1,
                remaining_content: -1,
                remaining_padding: -1,
                current_command: 0,
                is_padding: true,
            },
        }
    }
}

// ── Padding ────────────────────────────────────────────────────────────────

/// Add XTLS Vision padding to a buffer.
///
/// `command` - one of CMD_PADDING_CONTINUE, CMD_PADDING_END, CMD_PADDING_DIRECT.
/// `user_uuid` - if Some, written once at the start (consumed).
/// `long_padding` - use larger random padding range.
/// `testseed` - [short_min, short_range, long_min, long_range] for padding sizes.
pub fn xtls_padding(
    buf: &[u8],
    command: u8,
    user_uuid: &mut Option<[u8; 16]>,
    long_padding: bool,
    testseed: &[u32],
) -> Vec<u8> {
    let testseed = if testseed.len() < 4 {
        &[900, 500, 900, 256][..]
    } else {
        testseed
    };

    let content_len = buf.len() as i32;
    let mut rng = rand::thread_rng();

    let padding_len: i32 = if content_len < testseed[0] as i32 && long_padding {
        let extra = rng.gen_range(0..testseed[1]) as i32;
        (extra + testseed[2] as i32 - content_len).max(0)
    } else {
        rng.gen_range(0..testseed[3]) as i32
    };

    let max_content = 65536 - 21 - content_len;
    let padding_len = padding_len.min(max_content);

    let uuid_len = if user_uuid.is_some() { 16 } else { 0 };
    let frame_size = uuid_len + 5 + content_len as usize + padding_len as usize;
    let mut frame = Vec::with_capacity(frame_size);

    // Write user_uuid once
    if let Some(uuid) = user_uuid.take() {
        frame.extend_from_slice(&uuid);
    }

    frame.push(command);
    frame.extend_from_slice(&(content_len as u16).to_be_bytes());
    frame.extend_from_slice(&(padding_len as u16).to_be_bytes());
    if !buf.is_empty() {
        frame.extend_from_slice(buf);
    }
    if padding_len > 0 {
        let pad_start = frame.len();
        frame.resize(pad_start + padding_len as usize, 0);
        rng.fill(&mut frame[pad_start..]);
    }

    frame
}

// ── Unpadding ──────────────────────────────────────────────────────────────

/// Remove XTLS Vision padding from a buffer. Returns the extracted content.
pub fn xtls_unpadding(buf: &[u8], state: &mut TrafficState, is_uplink: bool) -> Vec<u8> {
    let dir = if is_uplink {
        &mut state.inbound
    } else {
        &mut state.outbound
    };

    // Initial state: check for user_uuid prefix
    if dir.remaining_command == -1 && dir.remaining_content == -1 && dir.remaining_padding == -1 {
        if buf.len() >= 21 && state.user_uuid[..] == buf[..16] {
            let buf = &buf[16..]; // consume uuid, process rest below
            dir.remaining_command = 5;
            return unpadding_loop(buf, dir);
        } else {
            return buf.to_vec();
        }
    }

    unpadding_loop(buf, dir)
}

fn unpadding_loop(mut buf: &[u8], dir: &mut DirectionState) -> Vec<u8> {
    let mut output = Vec::with_capacity(buf.len());

    while !buf.is_empty() {
        if dir.remaining_command > 0 {
            let (byte, rest) = buf.split_at(1);
            buf = rest;
            match dir.remaining_command {
                5 => dir.current_command = byte[0] as i32,
                4 => dir.remaining_content = (byte[0] as i32) << 8,
                3 => dir.remaining_content |= byte[0] as i32,
                2 => dir.remaining_padding = (byte[0] as i32) << 8,
                1 => {
                    dir.remaining_padding |= byte[0] as i32;
                }
                _ => {}
            }
            dir.remaining_command -= 1;
        } else if dir.remaining_content > 0 {
            let len = (dir.remaining_content as usize).min(buf.len());
            output.extend_from_slice(&buf[..len]);
            buf = &buf[len..];
            dir.remaining_content -= len as i32;
        } else if dir.remaining_padding > 0 {
            // Skip padding bytes
            let len = (dir.remaining_padding as usize).min(buf.len());
            buf = &buf[len..];
            dir.remaining_padding -= len as i32;
        }

        // Block complete
        if dir.remaining_command <= 0 && dir.remaining_content <= 0 && dir.remaining_padding <= 0 {
            if dir.current_command == 0 {
                dir.remaining_command = 5; // next block
            } else {
                // End or Direct: reset to initial
                dir.remaining_command = -1;
                dir.remaining_content = -1;
                dir.remaining_padding = -1;
                if !buf.is_empty() {
                    output.extend_from_slice(buf);
                }
                break;
            }
        }
    }

    output
}

// ── TLS Filter ─────────────────────────────────────────────────────────────

/// Inspect buffer for TLS handshake characteristics.
/// Called for the first ~8 packets to detect TLS version and cipher.
pub fn xtls_filter_tls(buf: &[u8], state: &mut TrafficState) {
    state.number_of_packet_to_filter -= 1;
    if buf.len() < 6 {
        return;
    }

    let start = &buf[..6];

    if start[..3] == TLS_SERVER_HELLO && start[5] == TLS_HANDSHAKE_SERVER_HELLO {
        let record_len = ((start[3] as i32) << 8) | (start[4] as i32);
        state.remaining_server_hello = record_len + 5;
        state.is_tls12_or_above = true;
        state.is_tls = true;

        if buf.len() >= 79 && state.remaining_server_hello >= 79 {
            let session_id_len = buf[43] as usize;
            let cs_start = 43 + session_id_len + 1;
            if cs_start + 1 < buf.len() {
                state.cipher = ((buf[cs_start] as u16) << 8) | (buf[cs_start + 1] as u16);
            }
        }
    } else if start[..2] == TLS_CLIENT_HELLO && start[5] == TLS_HANDSHAKE_CLIENT_HELLO {
        state.is_tls = true;
    }

    if state.remaining_server_hello > 0 {
        let end = (state.remaining_server_hello as usize).min(buf.len());
        state.remaining_server_hello -= buf.len() as i32;

        if buf[..end].windows(6).any(|w| w == TLS13_SUPPORTED_VERSIONS) {
            let cipher_name = TLS13_CIPHER_SUITES
                .iter()
                .find(|(cs, _)| *cs == state.cipher)
                .map(|(_, name)| *name)
                .unwrap_or("unknown");

            // Enable XTLS for non-CCM ciphers
            if cipher_name != "TLS_AES_128_CCM_8_SHA256" {
                state.enable_xtls = true;
            }
            state.number_of_packet_to_filter = 0;
        } else if state.remaining_server_hello <= 0 {
            state.number_of_packet_to_filter = 0;
        }
    }
}

// ── TLS Record Validation ──────────────────────────────────────────────────

/// Check whether a buffer of bytes constitutes a complete sequence of TLS
/// application data records.
pub fn is_complete_record(buf: &[u8]) -> bool {
    let total = buf.len();
    let mut i = 0;
    let mut header_remaining = 5;
    let mut record_remaining = 0;

    while i < total {
        if header_remaining > 0 {
            let byte = buf[i];
            i += 1;
            match header_remaining {
                5 => {
                    if byte != 0x17 {
                        return false;
                    }
                }
                4 => {
                    if byte != 0x03 {
                        return false;
                    }
                }
                3 => {
                    if byte != 0x03 {
                        return false;
                    }
                }
                2 => record_remaining = (byte as usize) << 8,
                1 => record_remaining |= byte as usize,
                _ => {}
            }
            header_remaining -= 1;
        } else if record_remaining > 0 {
            let remaining = total - i;
            if remaining < record_remaining {
                return false;
            }
            i += record_remaining;
            record_remaining = 0;
            header_remaining = 5;
        } else {
            return false;
        }
    }
    header_remaining == 5 && record_remaining == 0
}

// ── Vision Reader ──────────────────────────────────────────────────────────

/// Wraps a Read source, applying XTLS unpadding to incoming data.
pub struct VisionReader<R: Read> {
    inner: R,
    state: TrafficState,
    is_uplink: bool,
    /// Whether to pass through directly (splice mode).
    pub direct: bool,
    /// Reusable read buffer to avoid per-read allocations.
    raw_buf: Vec<u8>,
}

impl<R: Read> VisionReader<R> {
    pub fn new(inner: R, state: TrafficState, is_uplink: bool) -> Self {
        VisionReader {
            inner,
            state,
            is_uplink,
            direct: false,
            raw_buf: vec![0u8; 32768],
        }
    }

    /// Read data, applying unpadding and TLS filtering.
    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.raw_buf.len() < buf.len() {
            self.raw_buf.resize(buf.len(), 0);
        }
        let n = self.inner.read(&mut self.raw_buf[..buf.len()])?;
        if n == 0 {
            return Ok(0);
        }

        if self.direct {
            let copy_len = n.min(buf.len());
            buf[..copy_len].copy_from_slice(&self.raw_buf[..copy_len]);
            return Ok(copy_len);
        }

        // Check within-buffers state before borrowing raw_buf slice
        let within = {
            let dir = self.direction();
            dir.within_padding_buffers || self.state.number_of_packet_to_filter > 0
        };
        if !within {
            let copy_len = n.min(buf.len());
            buf[..copy_len].copy_from_slice(&self.raw_buf[..copy_len]);
            return Ok(copy_len);
        }

        let is_uplink = self.is_uplink;
        let unpadded = xtls_unpadding(&self.raw_buf[..n], &mut self.state, is_uplink);

        {
            let dir = self.direction();
            if dir.remaining_content > 0 || dir.remaining_padding > 0 || dir.current_command == 0 {
                dir.within_padding_buffers = true;
            } else if dir.current_command == 1 {
                dir.within_padding_buffers = false;
            } else if dir.current_command == 2 {
                dir.within_padding_buffers = false;
                dir.direct_copy = true;
                self.direct = true;
            }
        }

        if self.state.number_of_packet_to_filter > 0 {
            xtls_filter_tls(&unpadded, &mut self.state);
        }

        let copy_len = unpadded.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&unpadded[..copy_len]);
        Ok(copy_len)
    }

    #[inline]
    fn direction(&mut self) -> &mut DirectionState {
        if self.is_uplink {
            &mut self.state.inbound
        } else {
            &mut self.state.outbound
        }
    }

    /// Consume the reader, returning the inner state for reuse across
    /// keep-alive requests where the Vision frame sequence must persist.
    pub fn into_state(self) -> TrafficState {
        self.state
    }
}

impl<R: Read> Read for VisionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read(buf)
    }
}

// ── Vision Writer ──────────────────────────────────────────────────────────

/// Wraps a Write sink, applying XTLS padding to outgoing data.
pub struct VisionWriter<W: Write> {
    inner: W,
    state: TrafficState,
    is_uplink: bool,
    user_uuid: Option<[u8; 16]>,
    testseed: Vec<u32>,
    /// Whether to pass through directly.
    pub direct: bool,
}

impl<W: Write> VisionWriter<W> {
    pub fn new(inner: W, state: TrafficState, is_uplink: bool, testseed: Vec<u32>) -> Self {
        let user_uuid = Some(state.user_uuid);
        VisionWriter {
            inner,
            state,
            is_uplink,
            user_uuid,
            testseed,
            direct: false,
        }
    }

    /// Write data, applying XTLS padding.
    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.direct {
            return self.inner.write(buf);
        }

        if self.state.number_of_packet_to_filter > 0 {
            xtls_filter_tls(buf, &mut self.state);
        }

        let is_padding = self.writer_direction().is_padding;

        if is_padding {
            if buf.is_empty() {
                // Padding-only frame (VLESS header camouflage)
                let frame = xtls_padding(
                    &[],
                    CMD_PADDING_CONTINUE,
                    &mut self.user_uuid,
                    true,
                    &self.testseed,
                );
                self.inner.write_all(&frame)?;
                return Ok(0);
            }

            let is_complete = is_complete_record(buf);
            let long_padding = self.state.is_tls;

            if self.state.is_tls && buf.len() >= 6 && buf[..3] == TLS_APP_DATA_START && is_complete
            {
                let command = if self.state.enable_xtls {
                    CMD_PADDING_DIRECT
                } else {
                    CMD_PADDING_END
                };
                if self.state.enable_xtls {
                    self.writer_direction().direct_copy = true;
                    self.direct = true;
                }
                let frame = xtls_padding(buf, command, &mut self.user_uuid, false, &self.testseed);
                self.writer_direction().is_padding = false;
                self.inner.write_all(&frame)?;
            } else {
                let command = CMD_PADDING_CONTINUE;
                let frame = xtls_padding(
                    buf,
                    command,
                    &mut self.user_uuid,
                    long_padding,
                    &self.testseed,
                );
                self.inner.write_all(&frame)?;
            }
        } else {
            self.inner.write_all(buf)?;
        }

        Ok(buf.len())
    }

    fn writer_direction(&mut self) -> &mut DirectionState {
        if self.is_uplink {
            &mut self.state.outbound
        } else {
            &mut self.state.inbound
        }
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_unpadding_roundtrip() {
        let content = b"hello this is test content for vision padding";
        let mut uuid = Some([0xAAu8; 16]);
        let mut state = TrafficState::new(&[0xAAu8; 16]);

        let frame = xtls_padding(
            content,
            CMD_PADDING_END,
            &mut uuid,
            false,
            &[900, 500, 900, 256],
        );
        assert!(frame.len() > content.len(), "frame should have padding");

        let recovered = xtls_unpadding(&frame, &mut state, true);
        assert_eq!(recovered, content.to_vec());
        assert_eq!(state.inbound.current_command, 1); // END
    }

    #[test]
    fn test_padding_continue_sequence() {
        let mut uuid = Some([0xBBu8; 16]);
        let mut state = TrafficState::new(&[0xBBu8; 16]);

        let f1 = xtls_padding(
            b"first",
            CMD_PADDING_CONTINUE,
            &mut uuid,
            false,
            &[900, 500, 900, 256],
        );
        let f2 = xtls_padding(
            b"second",
            CMD_PADDING_END,
            &mut uuid,
            false,
            &[900, 500, 900, 256],
        );

        let mut combined = Vec::new();
        combined.extend_from_slice(&f1);
        combined.extend_from_slice(&f2);

        let r1 = xtls_unpadding(&combined, &mut state, false);
        assert_eq!(&r1[..5], b"first", "first unpadded chunk");
    }

    #[test]
    fn test_unpadding_no_uuid_match_passes_through() {
        let mut state = TrafficState::new(&[0xCCu8; 16]);
        let data = b"some random data without uuid prefix";
        let result = xtls_unpadding(data, &mut state, true);
        assert_eq!(result, data.to_vec());
    }

    #[test]
    fn test_padding_uses_random_bytes() {
        let mut uuid = Some([0xDDu8; 16]);
        let frame = xtls_padding(
            b"test",
            CMD_PADDING_END,
            &mut uuid,
            false,
            &[900, 500, 900, 256],
        );
        // Content is 4 bytes. Frame has: UUID(16) + cmd(1) + len(2) + padlen(2) + content(4) + padding.
        // Find the padding section after the content
        let content_start = 21; // 16 + 1 + 2 + 2
        let padding_start = content_start + 4;
        assert!(frame.len() > padding_start, "frame should have padding");
        // The padding bytes should NOT all be zero (they're random)
        let padding = &frame[padding_start..];
        let sum: u32 = padding.iter().map(|b| *b as u32).sum();
        assert!(
            sum > 0 || padding.is_empty(),
            "padding should contain non-zero bytes"
        );
    }

    #[test]
    fn test_is_complete_record_valid() {
        // Single TLS app data record: 0x17 0x03 0x03 len_hi len_lo + payload
        let payload = vec![0u8; 100];
        let mut record = vec![0x17, 0x03, 0x03, 0x00, 100];
        record.extend_from_slice(&payload);
        assert!(is_complete_record(&record));
    }

    #[test]
    fn test_is_complete_record_truncated() {
        let mut record = vec![0x17, 0x03, 0x03, 0x00, 100];
        record.extend_from_slice(&[0u8; 50]); // only 50 bytes, should be 100
        assert!(!is_complete_record(&record));
    }

    #[test]
    fn test_xtls_filter_tls_detects_server_hello() {
        let mut state = TrafficState::new(&[0u8; 16]);
        // Full TLS 1.3 ServerHello: 5-byte record header + 74-byte handshake payload
        // ServerHello type(1) + length(3) + server_version(2) + random(32) +
        // session_id_len(1) + session_id(0) + cipher_suite(2) + compression(1) +
        // extensions_len(2) + 0x002b version extension(6) = 56 bytes minimum
        let payload_len = 74usize;
        let mut buf = vec![0u8; 5 + payload_len];
        buf[0] = 0x16; // handshake record
        buf[1] = 0x03;
        buf[2] = 0x03;
        buf[3] = ((payload_len >> 8) & 0xff) as u8;
        buf[4] = (payload_len & 0xff) as u8;
        buf[5] = 0x02; // ServerHello type
        buf[6] = 0x00;
        buf[7] = 0x00;
        buf[8] = (payload_len - 4) as u8; // remaining length
        buf[9] = 0x03; // TLS 1.2 version
        buf[10] = 0x03;
        // session_id is at offset 44 (5 + 1 + 3 + 2 + 32 + 1) + session_len
        // We set session_id_len = 0 at offset 43
        buf[43] = 0x00; // session_id_len = 0
        // cipher_suite at offset 44-45
        // Insert TLS 1.3 supported_versions extension later in the buffer
        let sv_start = 5 + 1 + 3 + 2 + 32 + 1 + 2 + 1 + 2; // after all fixed fields (session_id_len=0 omitted)
        buf[sv_start] = 0x00;
        buf[sv_start + 1] = 0x04; // 4 bytes extension
        buf[sv_start + 2] = 0x00;
        buf[sv_start + 3] = 0x2b; // supported_versions
        buf[sv_start + 4] = 0x00;
        buf[sv_start + 5] = 0x02; // 2 bytes
        buf[sv_start + 6] = 0x03; // TLS 1.3
        buf[sv_start + 7] = 0x04;

        xtls_filter_tls(&buf, &mut state);
        assert!(state.is_tls, "should detect TLS");
        assert!(state.is_tls12_or_above, "should detect TLS 1.2+");
        assert_eq!(
            state.number_of_packet_to_filter, 0,
            "filtering should be done"
        );
    }
}
