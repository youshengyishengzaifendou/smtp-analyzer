//! 错误类型定义

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnalyzerError {
    #[error("无效输入: {0}")]
    InvalidInput(String),

    #[error("无法打开文件: {0}")]
    FileOpen(String),

    #[error("pcap 解析错误: {0}")]
    PcapParse(String),

    #[error("协议解码错误: {0}")]
    Decode(String),

    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON 序列化错误: {0}")]
    Json(#[from] serde_json::Error),

    #[error("CSV 写入错误: {0}")]
    Csv(#[from] csv::Error),
}

pub type Result<T> = std::result::Result<T, AnalyzerError>;
