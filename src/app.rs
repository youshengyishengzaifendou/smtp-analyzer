//! 复用的分析入口

use serde::Serialize;

use crate::analyzer::Analyzer;
use crate::capture::CaptureReader;
use crate::error::Result;
use crate::flow::FlowTable;
use crate::model::Report;

pub const DEFAULT_PORTS: [u16; 3] = [25, 587, 465];

#[derive(Debug, Clone)]
pub struct AnalysisRequest {
    pub file: String,
    pub ports: Vec<u16>,
    pub ignore_vlan: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisResponse {
    pub file: String,
    pub ports: Vec<u16>,
    pub ignore_vlan: bool,
    pub packet_count: u64,
    pub strict_flow_count: usize,
    pub merged_flow_count: usize,
    pub report: Report,
}

pub fn parse_ports(ports: &str) -> Vec<u16> {
    let parsed: Vec<u16> = ports
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    normalize_ports(parsed)
}

pub fn normalize_ports(mut ports: Vec<u16>) -> Vec<u16> {
    if ports.is_empty() {
        DEFAULT_PORTS.to_vec()
    } else {
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

pub fn analyze_capture(request: &AnalysisRequest) -> Result<AnalysisResponse> {
    let ports = normalize_ports(request.ports.clone());
    let mut reader = CaptureReader::open(&request.file, ports.clone())?;

    let mut strict_flow_table = FlowTable::new(false);
    let mut merged_flow_table = FlowTable::new(true);

    let mut packet_count = 0;
    for packet_result in reader.iter() {
        match packet_result {
            Ok(packet) => {
                strict_flow_table.add_packet(&packet);
                merged_flow_table.add_packet(&packet);
                packet_count += 1;
            }
            Err(_) => {
                // 当前实现里 CaptureReader 已经会统计并吞掉无法解析的原始包。
            }
        }
    }

    let skipped_count = reader.skipped_count();
    let strict_flow_count = strict_flow_table.len();
    let merged_flow_count = merged_flow_table.len();
    let report = if request.ignore_vlan {
        Analyzer::analyze(
            &merged_flow_table,
            &strict_flow_table,
            &merged_flow_table,
            skipped_count,
        )
    } else {
        Analyzer::analyze(
            &strict_flow_table,
            &strict_flow_table,
            &merged_flow_table,
            skipped_count,
        )
    };

    Ok(AnalysisResponse {
        file: request.file.clone(),
        ports,
        ignore_vlan: request.ignore_vlan,
        packet_count,
        strict_flow_count,
        merged_flow_count,
        report,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{analyze_capture, normalize_ports, parse_ports, AnalysisRequest, DEFAULT_PORTS};
    use crate::model::{Completeness, Directionality};

    fn sample_capture_path() -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("service_test_sample.pcap")
            .to_string_lossy()
            .to_string()
    }

    #[test]
    fn normalize_ports_sorts_deduplicates_and_defaults() {
        assert_eq!(normalize_ports(vec![587, 25, 587, 465]), vec![25, 465, 587]);
        assert_eq!(normalize_ports(Vec::new()), DEFAULT_PORTS.to_vec());
    }

    #[test]
    fn parse_ports_skips_invalid_values() {
        assert_eq!(parse_ports("587, bad, 25, 587"), vec![25, 587]);
    }

    #[test]
    fn analyze_capture_reports_vlan_asymmetry_for_sample() {
        let response = analyze_capture(&AnalysisRequest {
            file: sample_capture_path(),
            ports: vec![25, 587, 465],
            ignore_vlan: false,
        })
        .expect("sample capture should analyze successfully");

        assert_eq!(response.packet_count, 8);
        assert_eq!(response.strict_flow_count, 2);
        assert_eq!(response.merged_flow_count, 1);
        assert_eq!(response.report.summary.total_flows, 2);
        assert_eq!(response.report.summary.suspected_vlan_asymmetry_sessions, 1);
        assert_eq!(response.report.diagnostics.len(), 1);
        assert!(response.report.flows.iter().all(|flow| flow
            .anomaly_tags
            .iter()
            .any(|tag| tag == "vlan_asymmetry_likely")));
    }

    #[test]
    fn analyze_capture_merges_sample_when_vlan_is_ignored() {
        let response = analyze_capture(&AnalysisRequest {
            file: sample_capture_path(),
            ports: vec![25, 587, 465],
            ignore_vlan: true,
        })
        .expect("sample capture should analyze successfully");

        assert_eq!(response.report.summary.total_flows, 1);
        assert_eq!(response.report.summary.complete_bidirectional, 1);
        assert_eq!(response.report.summary.incomplete_unidirectional, 0);
        assert_eq!(response.report.summary.suspected_vlan_asymmetry_sessions, 1);

        let flow = response
            .report
            .flows
            .first()
            .expect("merged sample should produce one flow");
        assert_eq!(flow.completeness, Completeness::Complete);
        assert_eq!(flow.directionality, Directionality::Bidirectional);
        assert_eq!(
            flow.observed_vlans,
            vec!["untagged".to_string(), "100".to_string()]
        );
        assert_eq!(flow.anomaly_tags, vec!["vlan_asymmetry_likely".to_string()]);
    }
}
