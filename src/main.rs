//! SMTP 流量完整性分析工具
//!
//! 分析 pcap/pcapng 文件中的 SMTP 流量，判断每条流是否完整、是否双向。

mod analyzer;
mod app;
mod capture;
mod decoder;
mod error;
mod flow;
mod model;
mod report;
mod service;

use clap::Parser;
use env_logger::Builder;
use log::{info, LevelFilter};
use std::io::Write;

use crate::app::{analyze_capture, parse_ports, AnalysisRequest};
use crate::report::ReportWriter;

/// 命令行参数
#[derive(Parser, Debug)]
#[command(
    name = "smtp-analyzer",
    about = "SMTP 流量完整性分析工具",
    long_about = None
)]
struct Args {
    /// 要执行的命令
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

    /// 启动本地 HTTP 服务，供页面调用分析接口
    Serve {
        /// 监听地址
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// 监听端口
        #[arg(short, long, default_value_t = 8080)]
        port: u16,

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
            init_logging(verbose);

            let port_list = parse_ports(&ports);
            info!("分析文件: {}", file);
            info!("监控端口: {:?}", port_list);
            info!("忽略 VLAN: {}", ignore_vlan);

            let response = analyze_capture(&AnalysisRequest {
                file: file.clone(),
                ports: port_list,
                ignore_vlan,
            })?;

            info!("分析完成，共处理 {} 个数据包", response.packet_count);
            info!(
                "严格 VLAN 视图发现 {} 条 SMTP 流",
                response.strict_flow_count
            );
            info!(
                "忽略 VLAN 视图发现 {} 条 SMTP 流",
                response.merged_flow_count
            );

            ReportWriter::print_summary(&response.report);

            if let Some(json_path) = json {
                ReportWriter::write_json(&response.report, &json_path)?;
                info!("JSON 报告已保存到: {}", json_path);
            }

            if let Some(csv_path) = csv {
                ReportWriter::write_csv(&response.report, &csv_path)?;
                info!("CSV 报告已保存到: {}", csv_path);
            }

            Ok(())
        }
        Command::Serve { host, port, verbose } => {
            init_logging(verbose);
            service::serve(&host, port)?;
            Ok(())
        }
    }
}

fn init_logging(verbose: bool) {
    let level = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let mut builder = Builder::new();
    builder
        .filter_level(level)
        .format(|buf, record| writeln!(buf, "{}", record.args()));

    let _ = builder.try_init();
}
