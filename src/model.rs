//! 数据模型定义

use smallvec::SmallVec;
use serde::{Deserialize, Serialize};

/// 流向枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    AtoB,  // 第一个看到的源 → 目标
    BtoA,  // 第一个看到的目标 → 源
}

impl Default for Direction {
    fn default() -> Self {
        Direction::AtoB
    }
}

/// 完整性结论
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Completeness {
    Complete,   // 完整
    Incomplete,  // 残缺
}

/// 双向性结论
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Directionality {
    Bidirectional,   // 双向
    Unidirectional,  // 单向
}

/// 端点信息
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
}

impl Endpoint {
    pub fn new(ip: String, port: u16) -> Self {
        Self { ip, port }
    }
}

/// 会话键 - 用于唯一标识一条流
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    /// VLAN 标签栈 (支持单层和双层 VLAN)
    pub vlan_stack: SmallVec<[u16; 2]>,
    /// 协议类型 (6 = TCP)
    pub protocol: u8,
    /// 端点 A
    pub a: Endpoint,
    /// 端点 B
    pub b: Endpoint,
}

impl SessionKey {
    /// 创建会话键，自动规范化方向
    pub fn new(
        vlan_stack: SmallVec<[u16; 2]>,
        protocol: u8,
        src_ip: String,
        src_port: u16,
        dst_ip: String,
        dst_port: u16,
    ) -> Self {
        let a = Endpoint::new(src_ip, src_port);
        let b = Endpoint::new(dst_ip, dst_port);
        Self { vlan_stack, protocol, a, b }
    }
}

/// TCP 连接状态
#[derive(Debug, Clone, Default)]
pub struct TcpState {
    /// 是否见过 SYN (A → B)
    pub syn_seen_ab: bool,
    /// 是否见过 SYN-ACK (B → A)
    pub syn_ack_seen: bool,
    /// 是否见过三次握手的最后一个 ACK (A → B)
    pub handshake_ack_seen: bool,
    /// 握手是否完整
    pub handshake_complete: bool,

    /// 是否见过 FIN 或 RST (任一方向)
    pub fin_or_rst_seen: bool,
    /// A → B 方向是否有有效载荷
    pub has_payload_ab: bool,
    /// B → A 方向是否有有效载荷
    pub has_payload_ba: bool,

    /// A → B 方向的包数
    pub packets_ab: u64,
    /// B → A 方向的包数
    pub packets_ba: u64,
    /// A → B 方向的字节数
    pub bytes_ab: u64,
    /// B → A 方向的字节数
    pub bytes_ba: u64,
    /// A → B 方向观察到的最小 SEQ
    pub seq_start_ab: Option<u32>,
    /// A → B 方向观察到的最大 SEQ
    pub seq_end_ab: Option<u32>,
    /// B → A 方向观察到的最小 SEQ
    pub seq_start_ba: Option<u32>,
    /// B → A 方向观察到的最大 SEQ
    pub seq_end_ba: Option<u32>,
    /// A → B 方向观察到的最小 ACK
    pub ack_start_ab: Option<u32>,
    /// A → B 方向观察到的最大 ACK
    pub ack_end_ab: Option<u32>,
    /// B → A 方向观察到的最小 ACK
    pub ack_start_ba: Option<u32>,
    /// B → A 方向观察到的最大 ACK
    pub ack_end_ba: Option<u32>,

    /// 第一个包的时间戳 (微秒)
    pub first_ts_micros: Option<i64>,
    /// 最后一个包的时间戳 (微秒)
    pub last_ts_micros: Option<i64>,
}

/// SMTP 状态
#[derive(Debug, Clone, Default)]
pub struct SmtpState {
    /// 是否见过 Banner (220)
    pub banner_seen: bool,
    /// 是否见过 EHLO/HELO
    pub helo_seen: bool,
    /// 是否见过 MAIL FROM
    pub mail_from_seen: bool,
    /// 是否见过 RCPT TO
    pub rcpt_to_seen: bool,
    /// 是否进入 DATA 阶段
    pub data_started: bool,
    /// DATA 是否正常结束 (以 \r\n.\r\n 结束)
    pub data_finished: bool,
    /// 是否见过 QUIT
    pub quit_seen: bool,
    /// 是否是隐式 TLS (465 端口)
    pub is_implicit_tls: bool,
    /// 是否见过 STARTTLS
    pub starttls_seen: bool,
    /// 经过的 SMTP 阶段列表
    pub stages: Vec<String>,
    /// Whether the client has sent DATA and we are still waiting for 354.
    pub awaiting_data_response: bool,
    /// Per-direction line assembly buffer for client -> server traffic.
    pub pending_line_ab: Vec<u8>,
    /// Per-direction line assembly buffer for server -> client traffic.
    pub pending_line_ba: Vec<u8>,
}

/// 原始数据包 (解码后)
#[derive(Debug, Clone)]
pub struct DecodedPacket {
    /// VLAN 标签栈
    pub vlan_stack: SmallVec<[u16; 2]>,
    /// 源 IP
    pub src_ip: String,
    /// 源端口
    pub src_port: u16,
    /// 目标 IP
    pub dst_ip: String,
    /// 目标端口
    pub dst_port: u16,
    /// TCP 协议号
    pub protocol: u8,
    /// 流向
    pub direction: Direction,
    /// TCP 序列号
    pub seq_num: u32,
    /// TCP 确认号
    pub ack_num: u32,
    /// TCP 标志位
    pub tcp_flags: TcpFlags,
    /// TCP 载荷
    pub payload: Vec<u8>,
    /// 时间戳 (微秒)
    pub timestamp_micros: i64,
}

/// TCP 标志位
#[derive(Debug, Clone, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
}

impl TcpFlags {
    /// 是否是纯 ACK 包 (只有 ACK 标志，没有载荷)
    pub fn is_pure_ack(&self) -> bool {
        self.ack && !self.syn && !self.fin && !self.rst && !self.psh
    }
}

/// 单条流分析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowResult {
    pub flow_index: usize,
    /// 源 IP
    pub src_ip: String,
    /// 源端口
    pub src_port: u16,
    /// 目标 IP
    pub dst_ip: String,
    /// 目标端口
    pub dst_port: u16,
    /// 主 VLAN 标签 (仅在该流只观察到单一带标签 VLAN 时设置)
    pub vlan: Option<u16>,
    /// 该流观察到的 VLAN 上下文
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_vlans: Vec<String>,
    /// 完整性结论
    pub completeness: Completeness,
    /// 双向性结论
    pub directionality: Directionality,
    /// A → B 包数
    pub packets_ab: u64,
    /// B → A 包数
    pub packets_ba: u64,
    /// A → B 字节数
    pub bytes_ab: u64,
    /// B → A 字节数
    pub bytes_ba: u64,
    /// A → B 方向观察到的 SEQ 起始
    pub seq_start_ab: Option<u32>,
    /// A → B 方向观察到的 SEQ 结束
    pub seq_end_ab: Option<u32>,
    /// B → A 方向观察到的 SEQ 起始
    pub seq_start_ba: Option<u32>,
    /// B → A 方向观察到的 SEQ 结束
    pub seq_end_ba: Option<u32>,
    /// A → B 方向观察到的 ACK 起始
    pub ack_start_ab: Option<u32>,
    /// A → B 方向观察到的 ACK 结束
    pub ack_end_ab: Option<u32>,
    /// B → A 方向观察到的 ACK 起始
    pub ack_start_ba: Option<u32>,
    /// B → A 方向观察到的 ACK 结束
    pub ack_end_ba: Option<u32>,
    /// TCP 握手是否完整
    pub tcp_handshake_complete: bool,
    /// TCP 连接是否正常关闭
    pub tcp_close_complete: bool,
    /// 经过的 SMTP 阶段
    pub smtp_stages: Vec<String>,
    /// 异常标签
    pub anomaly_tags: Vec<String>,
    /// 额外诊断说明
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostic_notes: Vec<String>,
}

/// 诊断结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    /// 诊断类型
    pub kind: String,
    /// 受影响的流号（从 1 开始）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flow_indices: Vec<usize>,
    /// 面向展示的简洁诊断结论
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    /// 源 IP
    pub src_ip: String,
    /// 源端口
    pub src_port: u16,
    /// 目标 IP
    pub dst_ip: String,
    /// 目标端口
    pub dst_port: u16,
    /// 观察到的 VLAN 上下文
    pub observed_vlans: Vec<String>,
    /// 诊断证据
    pub evidence: Vec<String>,
}

/// 分析报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// 汇总统计
    pub summary: Summary,
    /// 每条流的分析结果
    pub flows: Vec<FlowResult>,
    /// 额外诊断结果
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

/// 汇总统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Summary {
    /// 总流数
    pub total_flows: u64,
    /// 完整双向流数
    pub complete_bidirectional: u64,
    /// 完整单向流数
    pub complete_unidirectional: u64,
    /// 残缺双向流数
    pub incomplete_bidirectional: u64,
    /// 残缺单向流数
    pub incomplete_unidirectional: u64,
    /// 跳过的无法解析的包数
    pub skipped_packets: u64,
    /// 疑似 VLAN 不对称导致拆流的会话数
    pub suspected_vlan_asymmetry_sessions: u64,
}
