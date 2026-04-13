//! 报告输出模块
//!
//! 支持终端摘要、JSON、CSV 三种输出格式

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::error::{AnalyzerError, Result};
use crate::model::{Completeness, Directionality, FlowResult, Report, Summary};

/// 报告输出器
pub struct ReportWriter;

impl ReportWriter {
    /// 输出终端摘要
    pub fn print_summary(report: &Report) {
        let summary = &report.summary;
        let total_width = 45;

        println!();
        println!("{}", "=".repeat(total_width));
        println!("{:^width$}", "SMTP 流量分析摘要", width = total_width);
        println!("{}", "=".repeat(total_width));
        println!();
        println!("{:<20} {:>10}", "总流数:", summary.total_flows);
        println!("{:<20} {:>10}", "完整双向流:", summary.complete_bidirectional);
        println!("{:<20} {:>10}", "完整单向流:", summary.complete_unidirectional);
        println!("{:<20} {:>10}", "残缺双向流:", summary.incomplete_bidirectional);
        println!("{:<20} {:>10}", "残缺单向流:", summary.incomplete_unidirectional);
        println!("{:<20} {:>10}", "跳过的包:", summary.skipped_packets);
        println!();
        println!("{}", "-".repeat(total_width));
        println!();

        // 输出每条流的详细信息
        if !report.flows.is_empty() {
            Self::print_flows_table(&report.flows);
        }
    }

    /// 打印流详情表格
    fn print_flows_table(flows: &[FlowResult]) {
        let header = format!(
            "{:<15} {:>6} {:<15} {:>6} {:>5} {:>12} {:>14} {:>10}",
            "源 IP", "端口", "目标 IP", "端口", "VLAN", "完整性", "双向性", "SMTP 阶段"
        );
        println!("{}", header);
        println!("{}", "-".repeat(95));

        for flow in flows {
            let vlan_str = match flow.vlan {
                Some(v) => v.to_string(),
                None => "-".to_string(),
            };

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
                flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
                vlan_str, completeness_str, directionality_str, stages_str
            );

            // 如果有异常标签，打印出来
            if !flow.anomaly_tags.is_empty() {
                println!("    异常: {}", flow.anomaly_tags.join(", "));
            }
        }

        println!();
    }

    /// 输出 JSON 格式报告
    pub fn write_json(report: &Report, path: &str) -> Result<()> {
        let file = File::create(path)
            .map_err(|e| AnalyzerError::FileOpen(format!("{}: {}", path, e)))?;

        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, report)?;

        Ok(())
    }

    /// 输出 CSV 格式报告
    pub fn write_csv(report: &Report, path: &str) -> Result<()> {
        let file = File::create(path)
            .map_err(|e| AnalyzerError::FileOpen(format!("{}: {}", path, e)))?;

        let mut writer = csv::Writer::from_writer(file);

        // 写入表头
        writer.write_record(&[
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "vlan",
            "completeness",
            "directionality",
            "packets_ab",
            "packets_ba",
            "bytes_ab",
            "bytes_ba",
            "tcp_handshake_complete",
            "tcp_close_complete",
            "smtp_stages",
            "anomaly_tags",
        ])?;

        // 写入每条流
        for flow in &report.flows {
            writer.write_record(&[
                &flow.src_ip,
                &flow.src_port.to_string(),
                &flow.dst_ip,
                &flow.dst_port.to_string(),
                &flow.vlan.map(|v| v.to_string()).unwrap_or_default(),
                &Self::completeness_to_str(&flow.completeness),
                &Self::directionality_to_str(&flow.directionality),
                &flow.packets_ab.to_string(),
                &flow.packets_ba.to_string(),
                &flow.bytes_ab.to_string(),
                &flow.bytes_ba.to_string(),
                &flow.tcp_handshake_complete.to_string(),
                &flow.tcp_close_complete.to_string(),
                &flow.smtp_stages.join(";"),
                &flow.anomaly_tags.join(";"),
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
}
