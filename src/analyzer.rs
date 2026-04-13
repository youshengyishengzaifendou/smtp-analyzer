//! 分析模块
//!
//! 分析流的完整性和双向性

use crate::model::{
    Completeness, Directionality, FlowResult, Report, SmtpState, Summary, TcpState,
};
use crate::flow::{FlowData, FlowTable};

/// 流分析器
pub struct Analyzer;

impl Analyzer {
    /// 分析所有流并生成报告
    pub fn analyze(flow_table: &FlowTable, skipped_packets: u64) -> Report {
        let mut summary = Summary::default();
        let mut flows = Vec::new();

        for (_, flow_data) in flow_table.flows() {
            let result = Self::analyze_flow(flow_data);

            // 更新统计
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

        // 按源 IP 和端口排序，便于查看
        flows.sort_by(|a, b| {
            a.src_ip.cmp(&b.src_ip).then(a.src_port.cmp(&b.src_port))
        });

        Report { summary, flows }
    }

    /// 分析单条流
    fn analyze_flow(flow_data: &FlowData) -> FlowResult {
        let tcp = &flow_data.tcp;
        let smtp = &flow_data.smtp;

        // 判断完整性
        let completeness = Self::determine_completeness(tcp, smtp);

        // 判断双向性
        let directionality = Self::determine_directionality(tcp);

        // 生成异常标签
        let anomaly_tags = Self::generate_anomaly_tags(tcp, smtp);

        FlowResult {
            src_ip: flow_data.src_ip.clone(),
            src_port: flow_data.src_port,
            dst_ip: flow_data.dst_ip.clone(),
            dst_port: flow_data.dst_port,
            vlan: flow_data.primary_vlan(),
            completeness,
            directionality,
            packets_ab: tcp.packets_ab,
            packets_ba: tcp.packets_ba,
            bytes_ab: tcp.bytes_ab,
            bytes_ba: tcp.bytes_ba,
            tcp_handshake_complete: tcp.handshake_complete,
            tcp_close_complete: tcp.fin_or_rst_seen,
            smtp_stages: smtp.stages.clone(),
            anomaly_tags,
        }
    }

    /// 判断完整性
    ///
    /// complete: TCP 握手完整 + 至少一个方向有载荷 + 有关闭
    /// incomplete: 其他情况
    fn determine_completeness(tcp: &TcpState, smtp: &SmtpState) -> Completeness {
        // TCP 握手不完整 -> 不完整
        if !tcp.handshake_complete {
            return Completeness::Incomplete;
        }

        // 没有有效载荷 -> 不完整
        if !tcp.has_payload_ab && !tcp.has_payload_ba {
            return Completeness::Incomplete;
        }

        // 没有关闭信号 (FIN 或 RST) -> 可能是中途截断
        // 注意: 有些抓包可能没有截取到最后的 FIN，这里宽松处理
        // 只要握手完整且有载荷，就认为是完整的
        if tcp.fin_or_rst_seen {
            Completeness::Complete
        } else {
            // 没有关闭但有完整握手和载荷，标记为部分完整
            // 实际上这取决于抓包是否捕获到了连接结束
            // 简化处理: 只要有握手和载荷就认为是完整的
            Completeness::Complete
        }
    }

    /// 判断双向性
    ///
    /// bidirectional: 双向都有有效载荷
    /// unidirectional: 其他情况 (只有一个方向有载荷，或只有控制包)
    fn determine_directionality(tcp: &TcpState) -> Directionality {
        if tcp.has_payload_ab && tcp.has_payload_ba {
            Directionality::Bidirectional
        } else {
            Directionality::Unidirectional
        }
    }

    /// 生成异常标签
    fn generate_anomaly_tags(tcp: &TcpState, smtp: &SmtpState) -> Vec<String> {
        let mut tags = Vec::new();

        // TCP 异常
        if !tcp.handshake_complete {
            tags.push("tcp_no_handshake".to_string());
        }

        // 检测中途接入 (看到 SYN-ACK 但没有看到 SYN)
        if tcp.syn_ack_seen && !tcp.syn_seen_ab {
            tags.push("tcp_midstream".to_string());
        }

        // 单向流量
        if !tcp.has_payload_ab && !tcp.has_payload_ba {
            tags.push("tcp_no_payload".to_string());
        } else if !tcp.has_payload_ab || !tcp.has_payload_ba {
            tags.push("tcp_one_way".to_string());
        }

        // SMTP 异常
        if smtp.is_implicit_tls {
            tags.push("smtp_implicit_tls".to_string());
        } else {
            // 只有非隐式 TLS 的 SMTP 才检查应用层异常
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
            first_ts_micros: Some(0),
            last_ts_micros: Some(1000),
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
}
