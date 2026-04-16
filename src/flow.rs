//! Flow aggregation.
//!
//! Groups decoded packets into session flows and tracks TCP/SMTP state.

use std::collections::HashMap;

use smallvec::SmallVec;

use crate::model::{DecodedPacket, Direction, SessionKey, SmtpState, TcpState};

/// Aggregated flow table keyed by normalized session identity.
pub struct FlowTable {
    /// Whether VLAN tags should be ignored when building the session key.
    ignore_vlan: bool,
    flows: HashMap<SessionKey, FlowData>,
}

impl FlowTable {
    pub fn new(ignore_vlan: bool) -> Self {
        Self {
            ignore_vlan,
            flows: HashMap::new(),
        }
    }

    pub fn add_packet(&mut self, packet: &DecodedPacket) {
        let key = self.build_session_key(packet);

        let flow = self.flows.entry(key).or_insert_with(|| {
            FlowData::new(
                packet.src_ip.clone(),
                packet.src_port,
                packet.dst_ip.clone(),
                packet.dst_port,
                packet.vlan_stack.clone(),
            )
        });

        flow.add_packet(packet);
    }

    fn build_session_key(&self, packet: &DecodedPacket) -> SessionKey {
        let vlan_stack = if self.ignore_vlan {
            SmallVec::new()
        } else {
            packet.vlan_stack.clone()
        };

        SessionKey::new(
            vlan_stack,
            packet.protocol,
            packet.src_ip.clone(),
            packet.src_port,
            packet.dst_ip.clone(),
            packet.dst_port,
        )
    }

    pub fn flows(&self) -> &HashMap<SessionKey, FlowData> {
        &self.flows
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }
}

/// Per-session state derived from the decoded packet stream.
#[derive(Debug, Clone)]
pub struct FlowData {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub observed_vlan_stacks: Vec<SmallVec<[u16; 2]>>,
    pub tcp: TcpState,
    pub smtp: SmtpState,
}

impl FlowData {
    pub fn new(
        src_ip: String,
        src_port: u16,
        dst_ip: String,
        dst_port: u16,
        vlan_stack: SmallVec<[u16; 2]>,
    ) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            observed_vlan_stacks: vec![vlan_stack],
            tcp: TcpState::default(),
            smtp: SmtpState::default(),
        }
    }

    pub fn add_packet(&mut self, packet: &DecodedPacket) {
        let direction = packet.direction;
        let payload_len = packet.payload.len() as u64;

        self.observe_vlan_stack(packet.vlan_stack.clone());

        if self.tcp.first_ts_micros.is_none() {
            self.tcp.first_ts_micros = Some(packet.timestamp_micros);
        }
        self.tcp.last_ts_micros = Some(packet.timestamp_micros);

        match direction {
            Direction::AtoB => {
                self.tcp.packets_ab += 1;
                self.tcp.bytes_ab += payload_len;
                update_u32_min_max(
                    &mut self.tcp.seq_start_ab,
                    &mut self.tcp.seq_end_ab,
                    packet.seq_num,
                );
                update_u32_min_max(
                    &mut self.tcp.ack_start_ab,
                    &mut self.tcp.ack_end_ab,
                    packet.ack_num,
                );

                if packet.tcp_flags.syn && !packet.tcp_flags.ack {
                    self.tcp.syn_seen_ab = true;
                }

                if packet.tcp_flags.ack && self.tcp.syn_seen_ab && self.tcp.syn_ack_seen {
                    self.tcp.handshake_ack_seen = true;
                    self.tcp.handshake_complete = true;
                }

                if packet.tcp_flags.fin || packet.tcp_flags.rst {
                    self.tcp.fin_or_rst_seen = true;
                }

                if payload_len > 0 && !packet.tcp_flags.is_pure_ack() {
                    self.tcp.has_payload_ab = true;
                }
            }
            Direction::BtoA => {
                self.tcp.packets_ba += 1;
                self.tcp.bytes_ba += payload_len;
                update_u32_min_max(
                    &mut self.tcp.seq_start_ba,
                    &mut self.tcp.seq_end_ba,
                    packet.seq_num,
                );
                update_u32_min_max(
                    &mut self.tcp.ack_start_ba,
                    &mut self.tcp.ack_end_ba,
                    packet.ack_num,
                );

                if packet.tcp_flags.syn && packet.tcp_flags.ack {
                    self.tcp.syn_ack_seen = true;
                }

                if packet.tcp_flags.fin || packet.tcp_flags.rst {
                    self.tcp.fin_or_rst_seen = true;
                }

                if payload_len > 0 && !packet.tcp_flags.is_pure_ack() {
                    self.tcp.has_payload_ba = true;
                }
            }
        }

        if self.dst_port == 25 || self.dst_port == 587 {
            self.update_smtp_state(packet);
        } else if self.dst_port == 465 {
            self.smtp.is_implicit_tls = true;
        }
    }

    fn observe_vlan_stack(&mut self, vlan_stack: SmallVec<[u16; 2]>) {
        if !self
            .observed_vlan_stacks
            .iter()
            .any(|existing| existing == &vlan_stack)
        {
            self.observed_vlan_stacks.push(vlan_stack);
        }
    }

    fn update_smtp_state(&mut self, packet: &DecodedPacket) {
        let payload = &packet.payload;
        if payload.is_empty() {
            return;
        }

        let mut ready_lines = Vec::new();
        {
            let buffer = match packet.direction {
                Direction::AtoB => &mut self.smtp.pending_line_ab,
                Direction::BtoA => &mut self.smtp.pending_line_ba,
            };

            buffer.extend_from_slice(payload);

            while let Some(line) = take_next_smtp_line(buffer) {
                ready_lines.push(line);
            }
        }

        for line in ready_lines {
            self.process_smtp_line(packet.direction, &line);
        }
    }

    fn process_smtp_line(&mut self, direction: Direction, raw_line: &[u8]) {
        let line = trim_smtp_line(raw_line);
        if line.is_empty() {
            return;
        }

        match direction {
            Direction::AtoB => self.process_client_smtp_line(line),
            Direction::BtoA => self.process_server_smtp_line(line),
        }
    }

    fn process_client_smtp_line(&mut self, line: &[u8]) {
        // After the server replies 354, client -> server traffic is message body
        // until the terminator line "." arrives.
        if self.smtp.data_started && !self.smtp.data_finished {
            if line == b"." {
                self.smtp.data_finished = true;
                self.add_stage("data_end");
            }
            return;
        }

        let line = String::from_utf8_lossy(line);
        let line = line.as_ref();

        if starts_with_ascii_case_insensitive(line, "EHLO ")
            || starts_with_ascii_case_insensitive(line, "HELO ")
        {
            self.smtp.helo_seen = true;
            self.add_stage("helo");
        }

        if starts_with_ascii_case_insensitive(line, "MAIL FROM:") {
            self.smtp.mail_from_seen = true;
            self.add_stage("mail_from");
        }

        if starts_with_ascii_case_insensitive(line, "RCPT TO:") {
            self.smtp.rcpt_to_seen = true;
            self.add_stage("rcpt_to");
        }

        if eq_ascii_case_insensitive(line, "DATA") {
            self.smtp.awaiting_data_response = true;
            self.add_stage("data");
        }

        if eq_ascii_case_insensitive(line, "QUIT") {
            self.smtp.quit_seen = true;
            self.add_stage("quit");
        }

        if eq_ascii_case_insensitive(line, "STARTTLS") {
            self.smtp.starttls_seen = true;
            self.add_stage("starttls");
        }
    }

    fn process_server_smtp_line(&mut self, line: &[u8]) {
        let line = String::from_utf8_lossy(line);
        let line = line.as_ref();

        if line.starts_with("220") && !self.smtp.banner_seen {
            self.smtp.banner_seen = true;
            self.add_stage("banner");
        }

        if self.smtp.awaiting_data_response && line.starts_with("354") {
            self.smtp.awaiting_data_response = false;
            self.smtp.data_started = true;
        }
    }

    fn add_stage(&mut self, stage: &str) {
        if !self.smtp.stages.iter().any(|existing| existing == stage) {
            self.smtp.stages.push(stage.to_string());
        }
    }

    pub fn primary_vlan(&self) -> Option<u16> {
        if self.observed_vlan_stacks.len() == 1 {
            self.observed_vlan_stacks[0].first().copied()
        } else {
            None
        }
    }

    pub fn observed_vlans(&self) -> Vec<String> {
        self.observed_vlan_stacks
            .iter()
            .map(|stack| {
                if stack.is_empty() {
                    "untagged".to_string()
                } else {
                    stack.iter().map(u16::to_string).collect::<Vec<_>>().join("/")
                }
            })
            .collect()
    }
}

fn starts_with_ascii_case_insensitive(input: &str, prefix: &str) -> bool {
    input
        .get(..prefix.len())
        .map(|candidate| candidate.eq_ignore_ascii_case(prefix))
        .unwrap_or(false)
}

fn eq_ascii_case_insensitive(input: &str, expected: &str) -> bool {
    input.eq_ignore_ascii_case(expected)
}

fn take_next_smtp_line(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    let newline_index = buffer.iter().position(|byte| *byte == b'\n')?;
    Some(buffer.drain(..=newline_index).collect())
}

fn trim_smtp_line(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && matches!(line[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    &line[..end]
}

fn update_u32_min_max(min_slot: &mut Option<u32>, max_slot: &mut Option<u32>, value: u32) {
    match min_slot {
        Some(current) if value >= *current => {}
        _ => *min_slot = Some(value),
    }

    match max_slot {
        Some(current) if value <= *current => {}
        _ => *max_slot = Some(value),
    }
}

#[cfg(test)]
mod tests {
    use super::FlowData;
    use crate::model::{DecodedPacket, Direction, TcpFlags};
    use smallvec::SmallVec;

    fn create_packet(direction: Direction, payload: &[u8]) -> DecodedPacket {
        DecodedPacket {
            vlan_stack: SmallVec::new(),
            src_ip: "10.0.0.10".to_string(),
            src_port: 43210,
            dst_ip: "10.0.0.20".to_string(),
            dst_port: 25,
            protocol: 6,
            direction,
            seq_num: if direction == Direction::AtoB { 1000 } else { 5000 },
            ack_num: if direction == Direction::AtoB { 5001 } else { 1001 },
            tcp_flags: TcpFlags {
                fin: false,
                syn: false,
                rst: false,
                psh: !payload.is_empty(),
                ack: true,
            },
            payload: payload.to_vec(),
            timestamp_micros: 0,
        }
    }

    #[test]
    fn smtp_data_end_is_detected_when_terminator_spans_packets() {
        let mut flow = FlowData::new(
            "10.0.0.10".to_string(),
            43210,
            "10.0.0.20".to_string(),
            25,
            SmallVec::new(),
        );

        let packets = vec![
            create_packet(Direction::BtoA, b"220 mail.test\r\n"),
            create_packet(Direction::AtoB, b"EHLO client\r\n"),
            create_packet(Direction::AtoB, b"MAIL FROM:<sender@test>\r\n"),
            create_packet(Direction::AtoB, b"RCPT TO:<rcpt@test>\r\n"),
            create_packet(Direction::AtoB, b"DATA\r\n"),
            create_packet(Direction::BtoA, b"354 Ok Send data ending with <CRLF>.<CRLF>\r\n"),
            create_packet(
                Direction::AtoB,
                b"------=_NextPart_000_013D_01A0C443.14EBABF0--\r\n.",
            ),
            create_packet(Direction::AtoB, b"\r\n"),
        ];

        for packet in &packets {
            flow.add_packet(packet);
        }

        assert!(flow.smtp.data_started);
        assert!(flow.smtp.data_finished);
        assert!(flow.smtp.stages.iter().any(|stage| stage == "data_end"));
    }

    #[test]
    fn smtp_command_is_detected_when_split_across_packets() {
        let mut flow = FlowData::new(
            "10.0.0.10".to_string(),
            43210,
            "10.0.0.20".to_string(),
            25,
            SmallVec::new(),
        );

        flow.add_packet(&create_packet(Direction::AtoB, b"EH"));
        flow.add_packet(&create_packet(Direction::AtoB, b"LO client\r\n"));

        assert!(flow.smtp.helo_seen);
        assert!(flow.smtp.stages.iter().any(|stage| stage == "helo"));
    }

    #[test]
    fn smtp_data_end_is_detected_for_pipelined_mail_rcpt_data_sequence() {
        let mut flow = FlowData::new(
            "10.0.0.10".to_string(),
            43210,
            "10.0.0.20".to_string(),
            25,
            SmallVec::new(),
        );

        let packets = vec![
            create_packet(Direction::BtoA, b"220 server ready\r\n"),
            create_packet(Direction::AtoB, b"EHLO mailgw4.pipechina.com.cn\r\n"),
            create_packet(Direction::BtoA, b"250-PIPELINING\r\n250 8BITMIME\r\n"),
            create_packet(
                Direction::AtoB,
                b"MAIL FROM:<system.reminder@caschina.cn>\r\nRCPT TO:<wangfj@pipechina.com.cn>\r\nDATA\r\n",
            ),
            create_packet(
                Direction::BtoA,
                b"250 2.1.0 Sender OK\r\n250 2.1.5 Recipient OK\r\n354 Ok Send data ending with <CRLF>.<CRLF>\r\n",
            ),
            create_packet(Direction::AtoB, b"Received: from upstream.example\r\n"),
            create_packet(Direction::AtoB, b"Content-Transfer-Encoding: base64\r\n"),
            create_packet(Direction::AtoB, b"U29tZSBiYXNlNjQgYm9keQ==\r\n.\r"),
            create_packet(Direction::AtoB, b"\n"),
            create_packet(Direction::BtoA, b"250 2.6.0 Message received\r\n"),
            create_packet(Direction::AtoB, b"QUIT\r\n"),
        ];

        for packet in &packets {
            flow.add_packet(packet);
        }

        assert!(flow.smtp.mail_from_seen);
        assert!(flow.smtp.rcpt_to_seen);
        assert!(flow.smtp.data_started);
        assert!(flow.smtp.data_finished);
        assert!(flow.smtp.quit_seen);
        assert!(!flow.smtp.awaiting_data_response);
    }
}
