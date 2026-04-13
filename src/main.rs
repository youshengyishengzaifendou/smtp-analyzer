//! SMTP 流量完整性分析工具
//!
//! 分析 pcap/pcapng 文件中的 SMTP 流量，判断每条流是否完整、是否双向

mod analyzer;
mod capture;
mod decoder;
mod error;
mod flow;
mod model;
mod report;

use clap::Parser;
use log::{debug, info, LevelFilter};
use env_logger::Builder;
use std::io::Write;

use crate::analyzer::Analyzer;
use crate::capture::CaptureReader;
use crate::decoder::Decoder;
use crate::flow::FlowTable;
use crate::report::ReportWriter;

/// 命令行参数
#[derive(Parser, Debug)]
#[command(
    name = "smtp-analyzer",
    about = "SMTP 流量完整性分析工具",
    long_about = None
)]
struct Args {
    /// 要分析的文件路径
    #[command(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    /// 分析 pcap/pcapng 文件
    Analyze {
        /// pcap/pcapng 文件路径
        #[arg(value_name = "FILE")]
        file: String,

        /// 监控端口 (逗号分隔)
        #[arg(short, long, default_value = "25,587,465")]
        ports: String,

        /// JSON 输出路径
        #[arg(short, long)]
        json: Option<String>,

        /// CSV 输出路径
        #[arg(short, long)]
        csv: Option<String>,

        /// 忽略 VLAN 差异
        #[arg(long)]
        ignore_vlan: bool,

        /// 详细日志输出
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Command::Analyze {
            file,
            ports,
            json,
            csv,
            ignore_vlan,
            verbose,
        } => {
            // 初始化日志
            let level = if verbose {
                LevelFilter::Debug
            } else {
                LevelFilter::Info
            };

            Builder::new()
                .filter_level(level)
                .format(|buf, record| {
                    writeln!(buf, "{}", record.args())
                })
                .init();

            // 解析端口
            let port_list: Vec<u16> = ports
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();

            info!("分析文件: {}", file);
            info!("监控端口: {:?}", port_list);
            info!("忽略 VLAN: {}", ignore_vlan);

            // 创建解码器
            let mut decoder = Decoder::new();
            decoder.set_ports(port_list);

            // 打开抓包文件
            let mut reader = CaptureReader::open(&file)?;

            // 创建流表
            let mut flow_table = FlowTable::new(ignore_vlan);

            // 迭代处理每个包
            let mut packet_count = 0;
            for packet_result in reader.iter() {
                match packet_result {
                    Ok(packet) => {
                        flow_table.add_packet(&packet);
                        packet_count += 1;

                        if verbose && packet_count % 10000 == 0 {
                            info!("已处理 {} 个数据包...", packet_count);
                        }
                    }
                    Err(e) => {
                        debug!("处理数据包时出错: {}", e);
                    }
                }
            }

            info!("分析完成，共处理 {} 个数据包", packet_count);
            info!("发现 {} 条 SMTP 流", flow_table.len());

            // 分析并生成报告
            let skipped_count = reader.skipped_count();
            let report = Analyzer::analyze(&flow_table, skipped_count);

            // 输出报告
            ReportWriter::print_summary(&report);

            // 输出 JSON
            if let Some(json_path) = json {
                ReportWriter::write_json(&report, &json_path)?;
                info!("JSON 报告已保存到: {}", json_path);
            }

            // 输出 CSV
            if let Some(csv_path) = csv {
                ReportWriter::write_csv(&report, &csv_path)?;
                info!("CSV 报告已保存到: {}", csv_path);
            }

            Ok(())
        }
    }
}
