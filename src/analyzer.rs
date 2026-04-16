//! Analysis logic for aggregated flows.

use std::collections::HashMap;

use crate::flow::{FlowData, FlowTable};
use crate::model::{
    Completeness, Diagnostic, Directionality, FlowResult, Report, SmtpState, Summary, TcpState,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowIdentity {
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
}

impl FlowIdentity {
    fn from_flow(flow: &FlowData) -> Self {
        Self {
            src_ip: flow.src_ip.clone(),
            src_port: flow.src_port,
            dst_ip: flow.dst_ip.clone(),
            dst_port: flow.dst_port,
        }
    }

    fn from_diagnostic(diagnostic: &Diagnostic) -> Self {
        Self {
            src_ip: diagnostic.src_ip.clone(),
            src_port: diagnostic.src_port,
            dst_ip: diagnostic.dst_ip.clone(),
            dst_port: diagnostic.dst_port,
        }
    }

    fn from_result(flow: &FlowResult) -> Self {
        Self {
            src_ip: flow.src_ip.clone(),
            src_port: flow.src_port,
            dst_ip: flow.dst_ip.clone(),
            dst_port: flow.dst_port,
        }
    }
}

pub struct Analyzer;

impl Analyzer {
    pub fn analyze(
        primary_view: &FlowTable,
        strict_view: &FlowTable,
        merged_view: &FlowTable,
        skipped_packets: u64,
    ) -> Report {
        let mut diagnostics = Self::detect_vlan_asymmetry(strict_view, merged_view);
        let diagnostic_map: HashMap<FlowIdentity, &Diagnostic> = diagnostics
            .iter()
            .map(|diagnostic| (FlowIdentity::from_diagnostic(diagnostic), diagnostic))
            .collect();

        let mut summary = Summary::default();
        let mut flows = Vec::new();

        for flow_data in primary_view.flows().values() {
            let identity = FlowIdentity::from_flow(flow_data);
            let diagnostic = diagnostic_map.get(&identity).copied();
            let result = Self::analyze_flow(flow_data, diagnostic);

            summary.total_flows += 1;
            match (&result.completeness, &result.directionality) {
                (Completeness::Complete, Directionality::Bidirectional) => {
                    summary.complete_bidirectional += 1;
                }
                (Completeness::Complete, Directionality::Unidirectional) => {
                    summary.complete_unidirectional += 1;
                }
                (Completeness::Incomplete, Directionality::Bidirectional) => {
                    summary.incomplete_bidirectional += 1;
                }
                (Completeness::Incomplete, Directionality::Unidirectional) => {
                    summary.incomplete_unidirectional += 1;
                }
            }

            flows.push(result);
        }

        summary.skipped_packets = skipped_packets;
        summary.suspected_vlan_asymmetry_sessions = diagnostics.len() as u64;

        Self::sort_flows(&mut flows);
        Self::attach_diagnostic_summaries(&mut flows, &mut diagnostics);

        Report {
            summary,
            flows,
            diagnostics,
        }
    }

    fn analyze_flow(flow_data: &FlowData, diagnostic: Option<&Diagnostic>) -> FlowResult {
        let tcp = &flow_data.tcp;
        let smtp = &flow_data.smtp;

        let completeness = Self::determine_completeness(tcp, smtp);
        let directionality = Self::determine_directionality(tcp);
        let mut anomaly_tags = Self::generate_anomaly_tags(tcp, smtp);

        if diagnostic.is_some()
            && !anomaly_tags
                .iter()
                .any(|tag| tag == "vlan_asymmetry_likely")
        {
            anomaly_tags.push("vlan_asymmetry_likely".to_string());
        }

        FlowResult {
            flow_index: 0,
            src_ip: flow_data.src_ip.clone(),
            src_port: flow_data.src_port,
            dst_ip: flow_data.dst_ip.clone(),
            dst_port: flow_data.dst_port,
            vlan: flow_data.primary_vlan(),
            observed_vlans: flow_data.observed_vlans(),
            completeness,
            directionality,
            packets_ab: tcp.packets_ab,
            packets_ba: tcp.packets_ba,
            bytes_ab: tcp.bytes_ab,
            bytes_ba: tcp.bytes_ba,
            seq_start_ab: tcp.seq_start_ab,
            seq_end_ab: tcp.seq_end_ab,
            seq_start_ba: tcp.seq_start_ba,
            seq_end_ba: tcp.seq_end_ba,
            ack_start_ab: tcp.ack_start_ab,
            ack_end_ab: tcp.ack_end_ab,
            ack_start_ba: tcp.ack_start_ba,
            ack_end_ba: tcp.ack_end_ba,
            tcp_handshake_complete: tcp.handshake_complete,
            tcp_close_complete: tcp.fin_or_rst_seen,
            smtp_stages: smtp.stages.clone(),
            anomaly_tags,
            diagnostic_notes: Vec::new(),
        }
    }

    fn sort_flows(flows: &mut [FlowResult]) {
        flows.sort_by(|a, b| {
            a.src_ip
                .cmp(&b.src_ip)
                .then(a.src_port.cmp(&b.src_port))
                .then(a.dst_ip.cmp(&b.dst_ip))
                .then(a.dst_port.cmp(&b.dst_port))
                .then(a.observed_vlans.join("|").cmp(&b.observed_vlans.join("|")))
        });
    }

    fn attach_diagnostic_summaries(flows: &mut [FlowResult], diagnostics: &mut [Diagnostic]) {
        let mut indices_by_identity: HashMap<FlowIdentity, Vec<usize>> = HashMap::new();
        for (index, flow) in flows.iter_mut().enumerate() {
            flow.flow_index = index + 1;
            indices_by_identity
                .entry(FlowIdentity::from_result(flow))
                .or_default()
                .push(flow.flow_index);
        }

        for diagnostic in diagnostics.iter_mut() {
            let identity = FlowIdentity::from_diagnostic(diagnostic);
            diagnostic.flow_indices = indices_by_identity
                .get(&identity)
                .cloned()
                .unwrap_or_default();
            diagnostic.summary =
                Self::format_diagnostic_summary(&diagnostic.kind, &diagnostic.flow_indices);
        }

        diagnostics.sort_by(|a, b| {
            let left = a.flow_indices.first().copied().unwrap_or(usize::MAX);
            let right = b.flow_indices.first().copied().unwrap_or(usize::MAX);
            left.cmp(&right)
                .then(a.src_ip.cmp(&b.src_ip))
                .then(a.src_port.cmp(&b.src_port))
        });

        let label_by_identity: HashMap<FlowIdentity, String> = diagnostics
            .iter()
            .map(|diagnostic| {
                (
                    FlowIdentity::from_diagnostic(diagnostic),
                    Self::diagnostic_kind_label(&diagnostic.kind).to_string(),
                )
            })
            .collect();

        for flow in flows.iter_mut() {
            let identity = FlowIdentity::from_result(flow);
            flow.diagnostic_notes = label_by_identity
                .get(&identity)
                .cloned()
                .map(|label| vec![format!("第{}个流：{}", flow.flow_index, label)])
                .unwrap_or_default();
        }
    }

    fn format_diagnostic_summary(kind: &str, flow_indices: &[usize]) -> String {
        let label = Self::diagnostic_kind_label(kind);
        if flow_indices.is_empty() {
            label.to_string()
        } else {
            format!("第{}个流：{}", Self::format_flow_ranges(flow_indices), label)
        }
    }

    fn diagnostic_kind_label(kind: &str) -> &'static str {
        match kind {
            "vlan_asymmetry" => "疑似 VLAN 不对称",
            _ => "存在异常",
        }
    }

    fn format_flow_ranges(flow_indices: &[usize]) -> String {
        if flow_indices.is_empty() {
            return String::new();
        }

        let mut normalized = flow_indices.to_vec();
        normalized.sort_unstable();
        normalized.dedup();

        let mut ranges = Vec::new();
        let mut start = normalized[0];
        let mut end = normalized[0];

        for &value in normalized.iter().skip(1) {
            if value == end + 1 {
                end = value;
            } else {
                ranges.push(Self::format_single_range(start, end));
                start = value;
                end = value;
            }
        }

        ranges.push(Self::format_single_range(start, end));
        ranges.join("、")
    }

    fn format_single_range(start: usize, end: usize) -> String {
        if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        }
    }

    fn determine_completeness(tcp: &TcpState, _smtp: &SmtpState) -> Completeness {
        if !tcp.handshake_complete {
            return Completeness::Incomplete;
        }

        if !tcp.has_payload_ab && !tcp.has_payload_ba {
            return Completeness::Incomplete;
        }

        Completeness::Complete
    }

    fn determine_directionality(tcp: &TcpState) -> Directionality {
        if tcp.has_payload_ab && tcp.has_payload_ba {
            Directionality::Bidirectional
        } else {
            Directionality::Unidirectional
        }
    }

    fn generate_anomaly_tags(tcp: &TcpState, smtp: &SmtpState) -> Vec<String> {
        let mut tags = Vec::new();

        if !tcp.handshake_complete {
            tags.push("tcp_no_handshake".to_string());
        }

        if tcp.syn_ack_seen && !tcp.syn_seen_ab {
            tags.push("tcp_midstream".to_string());
        }

        if !tcp.has_payload_ab && !tcp.has_payload_ba {
            tags.push("tcp_no_payload".to_string());
        } else if !tcp.has_payload_ab || !tcp.has_payload_ba {
            tags.push("tcp_one_way".to_string());
        }

        if smtp.is_implicit_tls {
            tags.push("smtp_implicit_tls".to_string());
        } else {
            if !smtp.banner_seen {
                tags.push("smtp_missing_banner".to_string());
            }

            if !smtp.helo_seen {
                tags.push("smtp_missing_helo".to_string());
            }

            if smtp.data_started && !smtp.data_finished {
                tags.push("smtp_data_incomplete".to_string());
            }
        }

        tags
    }

    fn detect_vlan_asymmetry(strict_view: &FlowTable, merged_view: &FlowTable) -> Vec<Diagnostic> {
        let mut strict_groups: HashMap<FlowIdentity, Vec<&FlowData>> = HashMap::new();
        for flow in strict_view.flows().values() {
            strict_groups
                .entry(FlowIdentity::from_flow(flow))
                .or_default()
                .push(flow);
        }

        let merged_groups: HashMap<FlowIdentity, &FlowData> = merged_view
            .flows()
            .values()
            .map(|flow| (FlowIdentity::from_flow(flow), flow))
            .collect();

        let mut diagnostics = Vec::new();

        for (identity, siblings) in strict_groups {
            if siblings.len() < 2 {
                continue;
            }

            let Some(merged_flow) = merged_groups.get(&identity).copied() else {
                continue;
            };

            let observed_vlans = Self::collect_vlan_labels(&siblings);
            if observed_vlans.len() < 2 {
                continue;
            }

            let direction_split = Self::has_direction_split(&siblings);
            let handshake_split = Self::has_handshake_split(&siblings);
            let merged_recovers_handshake = merged_flow.tcp.handshake_complete
                && !siblings.iter().any(|flow| flow.tcp.handshake_complete);
            let merged_recovers_bidirectional = merged_flow.tcp.has_payload_ab
                && merged_flow.tcp.has_payload_ba
                && !siblings
                    .iter()
                    .any(|flow| flow.tcp.has_payload_ab && flow.tcp.has_payload_ba);
            let merged_recovers_smtp_banner =
                merged_flow.smtp.banner_seen && siblings.iter().all(|flow| !flow.smtp.banner_seen);

            if !(direction_split || handshake_split) {
                continue;
            }

            if !(merged_recovers_handshake
                || merged_recovers_bidirectional
                || merged_recovers_smtp_banner)
            {
                continue;
            }

            diagnostics.push(Diagnostic {
                kind: "vlan_asymmetry".to_string(),
                flow_indices: Vec::new(),
                summary: String::new(),
                src_ip: identity.src_ip,
                src_port: identity.src_port,
                dst_ip: identity.dst_ip,
                dst_port: identity.dst_port,
                observed_vlans: observed_vlans.clone(),
                evidence: Self::build_vlan_asymmetry_evidence(
                    &siblings,
                    &observed_vlans,
                    merged_flow,
                    direction_split,
                    handshake_split,
                    merged_recovers_handshake,
                    merged_recovers_bidirectional,
                    merged_recovers_smtp_banner,
                ),
            });
        }

        diagnostics
    }

    fn collect_vlan_labels(flows: &[&FlowData]) -> Vec<String> {
        let mut labels = Vec::new();

        for flow in flows {
            for label in flow.observed_vlans() {
                if !labels.iter().any(|existing| existing == &label) {
                    labels.push(label);
                }
            }
        }

        labels.sort_by(|a, b| match (a.as_str(), b.as_str()) {
            ("untagged", "untagged") => std::cmp::Ordering::Equal,
            ("untagged", _) => std::cmp::Ordering::Less,
            (_, "untagged") => std::cmp::Ordering::Greater,
            _ => a.cmp(b),
        });
        labels
    }

    fn has_direction_split(flows: &[&FlowData]) -> bool {
        let has_client_to_server_only = flows
            .iter()
            .any(|flow| flow.tcp.has_payload_ab && !flow.tcp.has_payload_ba);
        let has_server_to_client_only = flows
            .iter()
            .any(|flow| flow.tcp.has_payload_ba && !flow.tcp.has_payload_ab);

        has_client_to_server_only && has_server_to_client_only
    }

    fn has_handshake_split(flows: &[&FlowData]) -> bool {
        let has_syn = flows.iter().any(|flow| flow.tcp.syn_seen_ab);
        let has_syn_ack = flows.iter().any(|flow| flow.tcp.syn_ack_seen);
        let has_complete_handshake = flows.iter().any(|flow| flow.tcp.handshake_complete);

        has_syn && has_syn_ack && !has_complete_handshake
    }

    fn build_vlan_asymmetry_evidence(
        siblings: &[&FlowData],
        observed_vlans: &[String],
        merged_flow: &FlowData,
        direction_split: bool,
        handshake_split: bool,
        merged_recovers_handshake: bool,
        merged_recovers_bidirectional: bool,
        merged_recovers_smtp_banner: bool,
    ) -> Vec<String> {
        let mut evidence = Vec::new();

        evidence.push(format!(
            "严格 VLAN 视图下，同一五元组被拆成 {} 条 sibling flow，VLAN 上下文为: {}。",
            siblings.len(),
            observed_vlans.join(", ")
        ));

        if direction_split {
            let sibling_summaries = siblings
                .iter()
                .map(|flow| {
                    format!(
                        "{} => {}",
                        flow.observed_vlans().join("+"),
                        Self::payload_direction_label(flow)
                    )
                })
                .collect::<Vec<_>>();
            evidence.push(format!(
                "不同 VLAN sibling 出现方向分裂: {}。",
                sibling_summaries.join("; ")
            ));
        }

        if handshake_split {
            evidence.push(
                "SYN 与 SYN-ACK 分散在不同 VLAN sibling 上，严格视图里没有任何一条 sibling 完成 TCP 握手。"
                    .to_string(),
            );
        }

        if merged_recovers_handshake && merged_recovers_bidirectional {
            evidence.push("忽略 VLAN 后，合并视图恢复为握手完整且双向都有有效载荷的单条流。".to_string());
        } else if merged_recovers_handshake {
            evidence.push("忽略 VLAN 后，合并视图恢复了完整 TCP 三次握手。".to_string());
        } else if merged_recovers_bidirectional {
            evidence.push("忽略 VLAN 后，合并视图恢复为双向都有有效载荷的流。".to_string());
        }

        if merged_recovers_smtp_banner {
            evidence.push("SMTP Banner 只在忽略 VLAN 的合并视图中完整可见。".to_string());
        }

        if merged_flow.smtp.starttls_seen {
            evidence.push("合并视图中还能看到 STARTTLS 阶段，说明应用层阶段信息也受拆流影响。".to_string());
        }

        evidence
    }

    fn payload_direction_label(flow: &FlowData) -> &'static str {
        match (flow.tcp.has_payload_ab, flow.tcp.has_payload_ba) {
            (true, true) => "双向载荷",
            (true, false) => "仅 client->server 载荷",
            (false, true) => "仅 server->client 载荷",
            (false, false) => "无有效载荷",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::SmallVec;

    use crate::model::{DecodedPacket, Direction, TcpFlags};

    fn create_test_tcp_state(
        syn: bool,
        syn_ack: bool,
        handshake_ack: bool,
        has_payload_ab: bool,
        has_payload_ba: bool,
        fin_or_rst: bool,
    ) -> TcpState {
        TcpState {
            syn_seen_ab: syn,
            syn_ack_seen: syn_ack,
            handshake_ack_seen: handshake_ack,
            handshake_complete: handshake_ack,
            fin_or_rst_seen: fin_or_rst,
            has_payload_ab,
            has_payload_ba,
            packets_ab: 10,
            packets_ba: 8,
            bytes_ab: 1000,
            bytes_ba: 500,
            seq_start_ab: Some(100),
            seq_end_ab: Some(200),
            seq_start_ba: Some(300),
            seq_end_ba: Some(400),
            ack_start_ab: Some(0),
            ack_end_ab: Some(350),
            ack_start_ba: Some(101),
            ack_end_ba: Some(201),
            first_ts_micros: Some(0),
            last_ts_micros: Some(1000),
        }
    }

    fn create_packet(
        vlan_stack: &[u16],
        direction: Direction,
        syn: bool,
        ack: bool,
        payload: &[u8],
    ) -> DecodedPacket {
        DecodedPacket {
            vlan_stack: vlan_stack.iter().copied().collect::<SmallVec<[u16; 2]>>(),
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
                syn,
                rst: false,
                psh: !payload.is_empty(),
                ack,
            },
            payload: payload.to_vec(),
            timestamp_micros: 0,
        }
    }

    #[test]
    fn test_complete_bidirectional() {
        let tcp = create_test_tcp_state(true, true, true, true, true, true);
        let smtp = SmtpState::default();

        let completeness = Analyzer::determine_completeness(&tcp, &smtp);
        let directionality = Analyzer::determine_directionality(&tcp);

        assert_eq!(completeness, Completeness::Complete);
        assert_eq!(directionality, Directionality::Bidirectional);
    }

    #[test]
    fn test_complete_unidirectional() {
        let tcp = create_test_tcp_state(true, true, true, true, false, true);
        let smtp = SmtpState::default();

        let completeness = Analyzer::determine_completeness(&tcp, &smtp);
        let directionality = Analyzer::determine_directionality(&tcp);

        assert_eq!(completeness, Completeness::Complete);
        assert_eq!(directionality, Directionality::Unidirectional);
    }

    #[test]
    fn test_incomplete_no_handshake() {
        let tcp = create_test_tcp_state(false, false, false, true, true, false);
        let smtp = SmtpState::default();

        let completeness = Analyzer::determine_completeness(&tcp, &smtp);

        assert_eq!(completeness, Completeness::Incomplete);
    }

    #[test]
    fn test_incomplete_no_payload() {
        let tcp = create_test_tcp_state(true, true, true, false, false, true);
        let smtp = SmtpState::default();

        let completeness = Analyzer::determine_completeness(&tcp, &smtp);
        let directionality = Analyzer::determine_directionality(&tcp);

        assert_eq!(completeness, Completeness::Incomplete);
        assert_eq!(directionality, Directionality::Unidirectional);
    }

    #[test]
    fn test_detects_vlan_asymmetry_when_merged_view_recovers_the_flow() {
        let mut strict_view = FlowTable::new(false);
        let mut merged_view = FlowTable::new(true);

        let packets = vec![
            create_packet(&[], Direction::AtoB, true, false, b""),
            create_packet(&[100], Direction::BtoA, true, true, b""),
            create_packet(&[], Direction::AtoB, false, true, b""),
            create_packet(&[], Direction::AtoB, false, true, b"EHLO client\r\n"),
            create_packet(&[100], Direction::BtoA, false, true, b"220 banner\r\n"),
        ];

        for packet in &packets {
            strict_view.add_packet(packet);
            merged_view.add_packet(packet);
        }

        let report = Analyzer::analyze(&strict_view, &strict_view, &merged_view, 0);

        assert_eq!(report.summary.suspected_vlan_asymmetry_sessions, 1);
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].flow_indices, vec![1, 2]);
        assert_eq!(report.diagnostics[0].summary, "第1-2个流：疑似 VLAN 不对称");
        assert!(report
            .flows
            .iter()
            .all(|flow| flow.anomaly_tags.iter().any(|tag| tag == "vlan_asymmetry_likely")));
        assert_eq!(report.flows[0].flow_index, 1);
        assert_eq!(report.flows[1].flow_index, 2);
        assert_eq!(
            report.flows[0].diagnostic_notes,
            vec!["第1个流：疑似 VLAN 不对称".to_string()]
        );
        assert_eq!(
            report.flows[1].diagnostic_notes,
            vec!["第2个流：疑似 VLAN 不对称".to_string()]
        );
    }

    #[test]
    fn test_does_not_flag_multiple_vlan_contexts_without_recovery_signal() {
        let mut strict_view = FlowTable::new(false);
        let mut merged_view = FlowTable::new(true);

        let packets = vec![
            create_packet(&[], Direction::AtoB, true, false, b""),
            create_packet(&[], Direction::BtoA, true, true, b""),
            create_packet(&[], Direction::AtoB, false, true, b"MAIL FROM:<a@test>\r\n"),
            create_packet(&[], Direction::BtoA, false, true, b"220 banner\r\n"),
            create_packet(&[100], Direction::AtoB, true, false, b""),
            create_packet(&[100], Direction::BtoA, true, true, b""),
            create_packet(&[100], Direction::AtoB, false, true, b"MAIL FROM:<b@test>\r\n"),
            create_packet(&[100], Direction::BtoA, false, true, b"220 banner\r\n"),
        ];

        for packet in &packets {
            strict_view.add_packet(packet);
            merged_view.add_packet(packet);
        }

        let report = Analyzer::analyze(&strict_view, &strict_view, &merged_view, 0);

        assert_eq!(report.summary.suspected_vlan_asymmetry_sessions, 0);
        assert!(report.diagnostics.is_empty());
    }
}
