//! Report output helpers.

use std::fs::File;
use std::io::BufWriter;

use crate::error::{AnalyzerError, Result};
use crate::model::{Completeness, Diagnostic, Directionality, FlowResult, Report};

pub struct ReportWriter;

impl ReportWriter {
    pub fn print_summary(report: &Report) {
        let summary = &report.summary;
        let total_width = 45;

        println!();
        println!("{}", "=".repeat(total_width));
        println!("{:^width$}", "SMTP 流量分析摘要", width = total_width);
        println!("{}", "=".repeat(total_width));
        println!();
        println!("{:<20} {:>10}", "总流数", summary.total_flows);
        println!(
            "{:<20} {:>10}",
            "完整双向流", summary.complete_bidirectional
        );
        println!(
            "{:<20} {:>10}",
            "完整单向流", summary.complete_unidirectional
        );
        println!(
            "{:<20} {:>10}",
            "残缺双向流", summary.incomplete_bidirectional
        );
        println!(
            "{:<20} {:>10}",
            "残缺单向流", summary.incomplete_unidirectional
        );
        println!("{:<20} {:>10}", "跳过的包", summary.skipped_packets);
        println!(
            "{:<20} {:>10}",
            "疑似 VLAN 不对称",
            summary.suspected_vlan_asymmetry_sessions
        );
        println!();
        println!("{}", "-".repeat(total_width));
        println!();

        if !report.flows.is_empty() {
            Self::print_flows_table(&report.flows);
        }

        if !report.diagnostics.is_empty() {
            Self::print_diagnostics(&report.diagnostics);
        }
    }

    fn print_flows_table(flows: &[FlowResult]) {
        let header = format!(
            "{:<15} {:>6} {:<15} {:>6} {:>5} {:>12} {:>14} {:>10}",
            "源 IP", "端口", "目标 IP", "端口", "VLAN", "完整性", "双向性", "SMTP 阶段"
        );
        println!("{}", header);
        println!("{}", "-".repeat(95));

        for flow in flows {
            let vlan_str = Self::display_vlan(flow);

            let completeness_str = match flow.completeness {
                Completeness::Complete => "完整",
                Completeness::Incomplete => "残缺",
            };

            let directionality_str = match flow.directionality {
                Directionality::Bidirectional => "双向",
                Directionality::Unidirectional => "单向",
            };

            let stages_str = if flow.smtp_stages.is_empty() {
                "-".to_string()
            } else {
                flow.smtp_stages.join(";")
            };

            println!(
                "{:<15} {:>6} {:<15} {:>6} {:>5} {:>12} {:>14} {:>10}",
                flow.src_ip,
                flow.src_port,
                flow.dst_ip,
                flow.dst_port,
                vlan_str,
                completeness_str,
                directionality_str,
                stages_str
            );

            if !flow.anomaly_tags.is_empty() {
                println!("    异常: {}", flow.anomaly_tags.join(", "));
            }

            if !flow.diagnostic_notes.is_empty() {
                println!("    诊断: {}", flow.diagnostic_notes.join(" | "));
            }
        }

        println!();
    }

    fn print_diagnostics(diagnostics: &[Diagnostic]) {
        let grouped = Self::group_diagnostics(diagnostics);
        println!("诊断结论");
        println!("{}", "-".repeat(95));

        for summary in grouped {
            println!("{}", summary);
        }

        println!();
    }

    pub fn write_json(report: &Report, path: &str) -> Result<()> {
        let file = File::create(path)
            .map_err(|e| AnalyzerError::FileOpen(format!("{}: {}", path, e)))?;

        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, report)?;

        Ok(())
    }

    pub fn write_csv(report: &Report, path: &str) -> Result<()> {
        let file = File::create(path)
            .map_err(|e| AnalyzerError::FileOpen(format!("{}: {}", path, e)))?;

        let mut writer = csv::Writer::from_writer(file);

        writer.write_record(&[
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "vlan",
            "observed_vlans",
            "completeness",
            "directionality",
            "packets_ab",
            "packets_ba",
            "bytes_ab",
            "bytes_ba",
            "seq_start_ab",
            "seq_end_ab",
            "seq_start_ba",
            "seq_end_ba",
            "ack_start_ab",
            "ack_end_ab",
            "ack_start_ba",
            "ack_end_ba",
            "tcp_handshake_complete",
            "tcp_close_complete",
            "smtp_stages",
            "anomaly_tags",
            "diagnostic_notes",
        ])?;

        for flow in &report.flows {
            let src_port = flow.src_port.to_string();
            let dst_port = flow.dst_port.to_string();
            let vlan = flow.vlan.map(|v| v.to_string()).unwrap_or_default();
            let observed_vlans = flow.observed_vlans.join(";");
            let packets_ab = flow.packets_ab.to_string();
            let packets_ba = flow.packets_ba.to_string();
            let bytes_ab = flow.bytes_ab.to_string();
            let bytes_ba = flow.bytes_ba.to_string();
            let seq_start_ab = flow.seq_start_ab.map(|v| v.to_string()).unwrap_or_default();
            let seq_end_ab = flow.seq_end_ab.map(|v| v.to_string()).unwrap_or_default();
            let seq_start_ba = flow.seq_start_ba.map(|v| v.to_string()).unwrap_or_default();
            let seq_end_ba = flow.seq_end_ba.map(|v| v.to_string()).unwrap_or_default();
            let ack_start_ab = flow.ack_start_ab.map(|v| v.to_string()).unwrap_or_default();
            let ack_end_ab = flow.ack_end_ab.map(|v| v.to_string()).unwrap_or_default();
            let ack_start_ba = flow.ack_start_ba.map(|v| v.to_string()).unwrap_or_default();
            let ack_end_ba = flow.ack_end_ba.map(|v| v.to_string()).unwrap_or_default();
            let tcp_handshake_complete = flow.tcp_handshake_complete.to_string();
            let tcp_close_complete = flow.tcp_close_complete.to_string();
            let smtp_stages = flow.smtp_stages.join(";");
            let anomaly_tags = flow.anomaly_tags.join(";");
            let diagnostic_notes = flow.diagnostic_notes.join(" | ");

            writer.write_record(&[
                flow.src_ip.as_str(),
                src_port.as_str(),
                flow.dst_ip.as_str(),
                dst_port.as_str(),
                vlan.as_str(),
                observed_vlans.as_str(),
                Self::completeness_to_str(&flow.completeness),
                Self::directionality_to_str(&flow.directionality),
                packets_ab.as_str(),
                packets_ba.as_str(),
                bytes_ab.as_str(),
                bytes_ba.as_str(),
                seq_start_ab.as_str(),
                seq_end_ab.as_str(),
                seq_start_ba.as_str(),
                seq_end_ba.as_str(),
                ack_start_ab.as_str(),
                ack_end_ab.as_str(),
                ack_start_ba.as_str(),
                ack_end_ba.as_str(),
                tcp_handshake_complete.as_str(),
                tcp_close_complete.as_str(),
                smtp_stages.as_str(),
                anomaly_tags.as_str(),
                diagnostic_notes.as_str(),
            ])?;
        }

        writer.flush()?;

        Ok(())
    }

    fn completeness_to_str(c: &Completeness) -> &'static str {
        match c {
            Completeness::Complete => "complete",
            Completeness::Incomplete => "incomplete",
        }
    }

    fn directionality_to_str(d: &Directionality) -> &'static str {
        match d {
            Directionality::Bidirectional => "bidirectional",
            Directionality::Unidirectional => "unidirectional",
        }
    }

    fn display_vlan(flow: &FlowResult) -> String {
        if flow.observed_vlans.len() > 1 {
            "mixed".to_string()
        } else {
            match flow.vlan {
                Some(v) => v.to_string(),
                None => "-".to_string(),
            }
        }
    }

    fn group_diagnostics(diagnostics: &[Diagnostic]) -> Vec<String> {
        let mut grouped: Vec<(String, Vec<usize>, String)> = Vec::new();

        for diagnostic in diagnostics {
            let label = Self::diagnostic_label(diagnostic);
            if let Some(existing) = grouped.iter_mut().find(|item| item.0 == label) {
                existing.1.extend_from_slice(&diagnostic.flow_indices);
                if existing.2.is_empty() {
                    existing.2 = diagnostic.summary.clone();
                }
            } else {
                grouped.push((
                    label,
                    diagnostic.flow_indices.clone(),
                    diagnostic.summary.clone(),
                ));
            }
        }

        let mut result = grouped
            .into_iter()
            .map(|(label, flow_indices, fallback_summary)| {
                let first_index = flow_indices.iter().copied().min().unwrap_or(usize::MAX);
                let summary = if flow_indices.is_empty() {
                    if fallback_summary.is_empty() {
                        label
                    } else {
                        fallback_summary
                    }
                } else {
                    format!("第{}个流：{}", Self::format_flow_ranges(&flow_indices), label)
                };
                (first_index, summary)
            })
            .collect::<Vec<_>>();

        result.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        result.into_iter().map(|(_, summary)| summary).collect()
    }

    fn diagnostic_label(diagnostic: &Diagnostic) -> String {
        match diagnostic.kind.as_str() {
            "vlan_asymmetry" => "疑似 VLAN 不对称".to_string(),
            _ if !diagnostic.kind.is_empty() => diagnostic.kind.clone(),
            _ => "存在异常".to_string(),
        }
    }

    fn format_flow_ranges(flow_indices: &[usize]) -> String {
        let mut normalized = flow_indices.to_vec();
        normalized.sort_unstable();
        normalized.dedup();

        if normalized.is_empty() {
            return String::new();
        }

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
}
