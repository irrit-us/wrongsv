use std::collections::{HashMap, VecDeque};

pub(super) const DATA_SEGMENT_OVERHEAD: usize = 18;
const ACK_NUMBER_LIMIT: usize = 128;
const STARTUP_REMOTE_WINDOW: u32 = 32;
const MAX_RTO: u32 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SessionState {
    Active,
    ReadyToClose,
    PeerClosed,
    Terminating,
    PeerTerminating,
    Terminated,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SessionConfig {
    pub conv: u16,
    pub mtu: usize,
    pub tti: u32,
    pub uplink_capacity: usize,
    pub downlink_capacity: usize,
    pub write_buffer_size: usize,
    pub packet_overhead: usize,
}

#[derive(Clone, Copy, Debug)]
struct RoundTripInfo {
    variation: u32,
    srtt: u32,
    rto: u32,
    min_rtt: u32,
    updated_timestamp: u32,
}

impl RoundTripInfo {
    fn new(min_rtt: u32) -> Self {
        Self {
            variation: 0,
            srtt: 0,
            rto: 100,
            min_rtt,
            updated_timestamp: 0,
        }
    }

    fn update_peer_rto(&mut self, rto: u32, current: u32) {
        if current.wrapping_sub(self.updated_timestamp) < 3000 {
            return;
        }
        self.updated_timestamp = current;
        self.rto = rto.max(self.min_rtt);
    }

    fn update(&mut self, rtt: u32, current: u32) {
        if rtt > 0x7fff_ffff {
            return;
        }

        if self.srtt == 0 {
            self.srtt = rtt;
            self.variation = rtt / 2;
        } else {
            let delta = rtt.abs_diff(self.srtt);
            self.variation = (3 * self.variation + delta) / 4;
            self.srtt = (7 * self.srtt + rtt) / 8;
            if self.srtt < self.min_rtt {
                self.srtt = self.min_rtt;
            }
        }

        let mut rto = if self.min_rtt < 4 * self.variation {
            self.srtt + 4 * self.variation
        } else {
            self.srtt + self.variation
        };
        if rto > MAX_RTO {
            rto = MAX_RTO;
        }
        self.rto = (rto * 5 / 4).max(self.min_rtt);
        self.updated_timestamp = current;
    }

    fn timeout(self) -> u32 {
        self.rto.max(self.min_rtt)
    }
}

#[derive(Clone, Debug)]
struct PendingAck {
    number: u32,
    timestamp: u32,
}

#[derive(Clone, Debug)]
struct SendingSegment {
    number: u32,
    payload: Vec<u8>,
    timeout: u32,
    transmit: u32,
}

#[derive(Clone, Debug)]
struct DataSegment {
    option: u8,
    timestamp: u32,
    number: u32,
    payload: Vec<u8>,
}

#[derive(Clone, Debug)]
struct AckSegment {
    option: u8,
    receiving_window: u32,
    receiving_next: u32,
    timestamp: u32,
    numbers: Vec<u32>,
}

#[derive(Clone, Debug)]
struct CmdSegment {
    cmd: u8,
    option: u8,
    receiving_next: u32,
    peer_rto: u32,
}

#[derive(Clone, Debug)]
enum Segment {
    Data(DataSegment),
    Ack(AckSegment),
    Cmd(CmdSegment),
}

pub(super) struct XrayKcpSession {
    conv: u16,
    state: SessionState,
    state_begin: u32,
    last_incoming: u32,
    last_ping: u32,
    round_trip: RoundTripInfo,
    recv_next_number: u32,
    recv_window_size: u32,
    recv_packets: HashMap<u32, Vec<u8>>,
    recv_ready: VecDeque<Vec<u8>>,
    pending_acks: VecDeque<PendingAck>,
    pending_send_chunks: VecDeque<Vec<u8>>,
    send_window: VecDeque<SendingSegment>,
    next_send_number: u32,
    first_unacked: u32,
    remote_next_number: u32,
    send_inflight_size: u32,
    send_buffer_size: usize,
    control_window: u32,
    app_write_closed: bool,
    mss: usize,
}

impl XrayKcpSession {
    pub(super) fn new(config: SessionConfig) -> Self {
        let tti = config.tti.max(1);
        let mtu = config.mtu.max(DATA_SEGMENT_OVERHEAD + 1);
        let packet_overhead = config.packet_overhead;
        let mss = mtu.saturating_sub(packet_overhead + DATA_SEGMENT_OVERHEAD).max(1);
        let send_inflight_size =
            inflight_size(config.uplink_capacity.max(1), mtu as u32, tti).max(8);
        let recv_window_size =
            inflight_size(config.downlink_capacity.max(1), mtu as u32, tti).max(8);
        let send_buffer_size = (config.write_buffer_size / mtu).max(1);

        Self {
            conv: config.conv,
            state: SessionState::Active,
            state_begin: 0,
            last_incoming: 0,
            last_ping: 0,
            round_trip: RoundTripInfo::new(tti),
            recv_next_number: 0,
            recv_window_size,
            recv_packets: HashMap::new(),
            recv_ready: VecDeque::new(),
            pending_acks: VecDeque::new(),
            pending_send_chunks: VecDeque::new(),
            send_window: VecDeque::new(),
            next_send_number: 0,
            first_unacked: 0,
            remote_next_number: STARTUP_REMOTE_WINDOW,
            send_inflight_size,
            send_buffer_size,
            control_window: send_inflight_size,
            app_write_closed: false,
            mss,
        }
    }

    pub(super) fn enqueue_application_data(&mut self, data: &[u8]) {
        if !self.can_accept_application_data() || data.is_empty() {
            return;
        }

        for chunk in data.chunks(self.mss) {
            self.pending_send_chunks.push_back(chunk.to_vec());
        }
    }

    pub(super) fn can_accept_application_data(&self) -> bool {
        matches!(self.state, SessionState::Active | SessionState::ReadyToClose)
    }

    pub(super) fn mark_application_write_closed(&mut self, current: u32) {
        self.app_write_closed = true;
        match self.state {
            SessionState::Active => self.set_state(SessionState::ReadyToClose, current),
            SessionState::PeerClosed => self.set_state(SessionState::Terminating, current),
            SessionState::PeerTerminating => self.set_state(SessionState::Terminated, current),
            _ => {}
        }
    }

    #[allow(dead_code)]
    pub(super) fn state(&self) -> SessionState {
        self.state
    }

    pub(super) fn input(&mut self, packet: &[u8], current: u32) {
        self.last_incoming = current;
        let mut rest = packet;

        while let Some((segment, next)) = read_segment(rest) {
            match segment {
                Segment::Data(seg) => self.process_data_segment(seg, current),
                Segment::Ack(seg) => self.process_ack_segment(seg, current),
                Segment::Cmd(seg) => self.process_cmd_segment(seg, current),
            }

            rest = next;
        }
    }

    pub(super) fn flush(&mut self, current: u32) -> Vec<Vec<u8>> {
        let mut output = Vec::new();

        if self.state == SessionState::Terminated {
            return output;
        }

        if self.state == SessionState::Active && current.wrapping_sub(self.last_incoming) >= 30_000 {
            self.mark_application_write_closed(current);
        }
        if self.app_write_closed
            && self.pending_send_chunks.is_empty()
            && self.send_window.is_empty()
            && self.state == SessionState::ReadyToClose
        {
            self.set_state(SessionState::Terminating, current);
        }

        if self.state == SessionState::PeerTerminating
            && current.wrapping_sub(self.state_begin) > 4000
        {
            self.set_state(SessionState::Terminating, current);
        }
        if self.state == SessionState::ReadyToClose
            && current.wrapping_sub(self.state_begin) > 15_000
        {
            self.set_state(SessionState::Terminating, current);
        }

        self.fill_send_window();

        if self.state == SessionState::Terminating {
            output.push(self.serialize_cmd(2, current));
            if current.wrapping_sub(self.state_begin) > 8000 {
                self.set_state(SessionState::Terminated, current);
            }
            return output;
        }

        self.flush_pending_acks(&mut output);
        self.flush_send_window(current, &mut output);

        if current.wrapping_sub(self.last_ping) >= 3000 {
            output.push(self.serialize_cmd(3, current));
            self.last_ping = current;
        }

        output
    }

    pub(super) fn take_received(&mut self) -> Option<Vec<u8>> {
        self.recv_ready.pop_front()
    }

    fn process_data_segment(&mut self, seg: DataSegment, current: u32) {
        self.handle_option(seg.option, current);

        let idx = seg.number.wrapping_sub(self.recv_next_number);
        if idx >= self.recv_window_size {
            return;
        }

        self.pending_acks.push_back(PendingAck {
            number: seg.number,
            timestamp: seg.timestamp,
        });

        self.recv_packets
            .entry(seg.number)
            .or_insert(seg.payload);
        self.promote_received();
    }

    fn process_ack_segment(&mut self, seg: AckSegment, current: u32) {
        self.handle_option(seg.option, current);

        if self.remote_next_number < seg.receiving_window {
            self.remote_next_number = seg.receiving_window;
        }
        self.remove_sent_before(seg.receiving_next);

        let mut max_ack = 0u32;
        let mut removed = false;
        for number in seg.numbers {
            if self.remove_sent_number(number) {
                removed = true;
                if max_ack < number {
                    max_ack = number;
                }
            }
        }

        if removed && current.wrapping_sub(seg.timestamp) < MAX_RTO {
            self.round_trip.update(current.wrapping_sub(seg.timestamp), current);
        }
        self.update_first_unacked();
    }

    fn process_cmd_segment(&mut self, seg: CmdSegment, current: u32) {
        self.handle_option(seg.option, current);

        if seg.cmd == 2 {
            match self.state {
                SessionState::Active | SessionState::PeerClosed => {
                    self.set_state(SessionState::PeerTerminating, current)
                }
                SessionState::ReadyToClose => {
                    self.set_state(SessionState::Terminating, current)
                }
                SessionState::Terminating => self.set_state(SessionState::Terminated, current),
                _ => {}
            }
        }

        self.remove_sent_before(seg.receiving_next);
        self.round_trip.update_peer_rto(seg.peer_rto, current);
    }

    fn handle_option(&mut self, option: u8, current: u32) {
        if (option & 1) != 0 {
            match self.state {
                SessionState::ReadyToClose => self.set_state(SessionState::Terminating, current),
                SessionState::Active => self.set_state(SessionState::PeerClosed, current),
                _ => {}
            }
        }
    }

    fn set_state(&mut self, state: SessionState, current: u32) {
        self.state = state;
        self.state_begin = current;
    }

    fn promote_received(&mut self) {
        while let Some(payload) = self.recv_packets.remove(&self.recv_next_number) {
            self.recv_ready.push_back(payload);
            self.recv_next_number = self.recv_next_number.wrapping_add(1);
        }
    }

    fn fill_send_window(&mut self) {
        while self.send_window.len() < self.send_buffer_size {
            let Some(payload) = self.pending_send_chunks.pop_front() else {
                break;
            };
            let number = self.next_send_number;
            self.next_send_number = self.next_send_number.wrapping_add(1);
            self.send_window.push_back(SendingSegment {
                number,
                payload,
                timeout: 0,
                transmit: 0,
            });
        }
        self.update_first_unacked();
    }

    fn flush_pending_acks(&mut self, output: &mut Vec<Vec<u8>>) {
        while !self.pending_acks.is_empty() {
            let mut numbers = Vec::with_capacity(ACK_NUMBER_LIMIT);
            let mut timestamp = 0u32;

            while numbers.len() < ACK_NUMBER_LIMIT {
                let Some(ack) = self.pending_acks.pop_front() else {
                    break;
                };
                if timestamp < ack.timestamp {
                    timestamp = ack.timestamp;
                }
                numbers.push(ack.number);
            }

            output.push(serialize_ack(
                self.conv,
                if self.state == SessionState::ReadyToClose { 1 } else { 0 },
                self.recv_next_number.wrapping_add(self.recv_window_size),
                self.recv_next_number,
                timestamp,
                &numbers,
            ));
        }
    }

    fn flush_send_window(&mut self, current: u32, output: &mut Vec<Vec<u8>>) {
        let mut cwnd = self.send_inflight_size;
        let remote_room = self.remote_next_number.wrapping_sub(self.first_unacked);
        if cwnd > remote_room {
            cwnd = remote_room;
        }
        if cwnd > self.control_window {
            cwnd = self.control_window;
        }
        if cwnd == 0 {
            return;
        }
        cwnd = cwnd.saturating_mul(20);

        let mut in_flight = 0u32;
        let sending_next = self.first_unacked;
        for seg in &mut self.send_window {
            if in_flight >= cwnd {
                break;
            }
            if seg.transmit > 0 && current.wrapping_sub(seg.timeout) < 0x7fff_ffff {
                continue;
            }

            seg.timeout = current.wrapping_add(self.round_trip.timeout());
            seg.transmit = seg.transmit.saturating_add(1);
            output.push(serialize_data(
                self.conv,
                if self.state == SessionState::ReadyToClose { 1 } else { 0 },
                current,
                seg.number,
                sending_next,
                &seg.payload,
            ));
            in_flight = in_flight.saturating_add(1);
        }
    }

    fn remove_sent_before(&mut self, next: u32) {
        while let Some(front) = self.send_window.front() {
            if !seq_lt(front.number, next) {
                break;
            }
            self.send_window.pop_front();
        }
        self.update_first_unacked();
    }

    fn remove_sent_number(&mut self, number: u32) -> bool {
        if let Some(index) = self.send_window.iter().position(|seg| seg.number == number) {
            self.send_window.remove(index);
            self.update_first_unacked();
            return true;
        }
        false
    }

    fn update_first_unacked(&mut self) {
        self.first_unacked = self
            .send_window
            .front()
            .map(|seg| seg.number)
            .unwrap_or(self.next_send_number);
    }

    fn serialize_cmd(&mut self, cmd: u8, current: u32) -> Vec<u8> {
        self.last_ping = current;
        serialize_cmd(
            self.conv,
            cmd,
            if self.state == SessionState::ReadyToClose { 1 } else { 0 },
            self.first_unacked,
            self.recv_next_number,
            self.round_trip.timeout(),
        )
    }
}

fn inflight_size(capacity_mib: usize, mtu: u32, tti: u32) -> u32 {
    let interval = (1000 / tti.max(1)).max(1);
    let size = capacity_mib as u32 * 1024 * 1024 / mtu.max(1) / interval;
    size.max(8)
}

fn seq_lt(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) > 0x7fff_ffff
}

pub(super) fn peek_conv(packet: &[u8]) -> Option<u16> {
    if packet.len() < 2 {
        None
    } else {
        Some(u16::from_be_bytes([packet[0], packet[1]]))
    }
}

fn read_segment(buf: &[u8]) -> Option<(Segment, &[u8])> {
    let conv = peek_conv(buf)?;
    if buf.len() < 4 {
        return None;
    }

    let cmd = buf[2];
    let option = buf[3];
    let rest = &buf[4..];

    match cmd {
        1 => parse_data(conv, option, rest),
        0 => parse_ack(conv, option, rest),
        2 | 3 => parse_cmd(conv, cmd, option, rest),
        _ => parse_cmd(conv, cmd, option, rest),
    }
}

fn parse_data(_conv: u16, option: u8, buf: &[u8]) -> Option<(Segment, &[u8])> {
    if buf.len() < 14 {
        return None;
    }
    let timestamp = u32::from_be_bytes(buf[0..4].try_into().ok()?);
    let number = u32::from_be_bytes(buf[4..8].try_into().ok()?);
    let _sending_next = u32::from_be_bytes(buf[8..12].try_into().ok()?);
    let data_len = u16::from_be_bytes(buf[12..14].try_into().ok()?) as usize;
    if buf.len() < 14 + data_len {
        return None;
    }
    let payload = buf[14..14 + data_len].to_vec();
    Some((
        Segment::Data(DataSegment {
            option,
            timestamp,
            number,
            payload,
        }),
        &buf[14 + data_len..],
    ))
}

fn parse_ack(_conv: u16, option: u8, buf: &[u8]) -> Option<(Segment, &[u8])> {
    if buf.len() < 13 {
        return None;
    }
    let receiving_window = u32::from_be_bytes(buf[0..4].try_into().ok()?);
    let receiving_next = u32::from_be_bytes(buf[4..8].try_into().ok()?);
    let timestamp = u32::from_be_bytes(buf[8..12].try_into().ok()?);
    let count = buf[12] as usize;
    if buf.len() < 13 + count * 4 {
        return None;
    }

    let mut numbers = Vec::with_capacity(count);
    let mut offset = 13usize;
    for _ in 0..count {
        numbers.push(u32::from_be_bytes(buf[offset..offset + 4].try_into().ok()?));
        offset += 4;
    }

    Some((
        Segment::Ack(AckSegment {
            option,
            receiving_window,
            receiving_next,
            timestamp,
            numbers,
        }),
        &buf[offset..],
    ))
}

fn parse_cmd(_conv: u16, cmd: u8, option: u8, buf: &[u8]) -> Option<(Segment, &[u8])> {
    if buf.len() < 12 {
        return None;
    }
    Some((
        Segment::Cmd(CmdSegment {
            cmd,
            option,
            receiving_next: u32::from_be_bytes(buf[4..8].try_into().ok()?),
            peer_rto: u32::from_be_bytes(buf[8..12].try_into().ok()?),
        }),
        &buf[12..],
    ))
}

fn serialize_data(
    conv: u16,
    option: u8,
    timestamp: u32,
    number: u32,
    sending_next: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_SEGMENT_OVERHEAD + payload.len());
    out.extend_from_slice(&conv.to_be_bytes());
    out.push(1);
    out.push(option);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&number.to_be_bytes());
    out.extend_from_slice(&sending_next.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn serialize_ack(
    conv: u16,
    option: u8,
    receiving_window: u32,
    receiving_next: u32,
    timestamp: u32,
    numbers: &[u32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(17 + numbers.len() * 4);
    out.extend_from_slice(&conv.to_be_bytes());
    out.push(0);
    out.push(option);
    out.extend_from_slice(&receiving_window.to_be_bytes());
    out.extend_from_slice(&receiving_next.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.push(numbers.len() as u8);
    for number in numbers {
        out.extend_from_slice(&number.to_be_bytes());
    }
    out
}

fn serialize_cmd(
    conv: u16,
    cmd: u8,
    option: u8,
    sending_next: u32,
    receiving_next: u32,
    peer_rto: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&conv.to_be_bytes());
    out.push(cmd);
    out.push(option);
    out.extend_from_slice(&sending_next.to_be_bytes());
    out.extend_from_slice(&receiving_next.to_be_bytes());
    out.extend_from_slice(&peer_rto.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(conv: u16) -> SessionConfig {
        SessionConfig {
            conv,
            mtu: 1350,
            tti: 10,
            uplink_capacity: 5,
            downlink_capacity: 20,
            write_buffer_size: 2 * 1024 * 1024,
            packet_overhead: 16,
        }
    }

    fn exchange(a: &mut XrayKcpSession, b: &mut XrayKcpSession, start: u32, rounds: u32) {
        let mut current = start;
        for _ in 0..rounds {
            let a_out = a.flush(current);
            for packet in a_out {
                b.input(&packet, current);
            }
            let b_out = b.flush(current);
            for packet in b_out {
                a.input(&packet, current);
            }
            current += 10;
        }
    }

    #[test]
    fn segment_roundtrip() {
        let data = serialize_data(7, 0, 10, 2, 1, b"hello");
        let (segment, rest) = read_segment(&data).unwrap();
        assert!(rest.is_empty());
        match segment {
            Segment::Data(seg) => {
                assert_eq!(seg.number, 2);
                assert_eq!(seg.payload, b"hello");
            }
            _ => panic!("expected data segment"),
        }
    }

    #[test]
    fn session_delivers_application_data() {
        let mut client = XrayKcpSession::new(test_config(9));
        let mut server = XrayKcpSession::new(test_config(9));

        client.enqueue_application_data(b"ping over mkcp");
        exchange(&mut client, &mut server, 10, 20);

        assert_eq!(server.take_received().unwrap(), b"ping over mkcp");
    }

    #[test]
    fn session_acknowledges_and_clears_send_window() {
        let mut client = XrayKcpSession::new(test_config(11));
        let mut server = XrayKcpSession::new(test_config(11));

        client.enqueue_application_data(b"payload");
        exchange(&mut client, &mut server, 10, 20);

        assert!(client.send_window.is_empty());
        assert!(server.recv_ready.pop_front().is_some());
    }
}
