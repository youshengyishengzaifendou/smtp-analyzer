//! 流聚合模块
//!
//! 将数据包按五元组聚合到流中

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use smallvec::SmallVec;

use crate::model::{
    DecodedPacket, Direction, Endpoint, SessionKey, SmtpState, TcpState,
};

/// 流表
pub struct FlowTable {
    /// 是否忽略 VLAN
    ignore_vlan: bool,
    /// 流数据
    flows: HashMap<SessionKey, FlowData>,
}

impl FlowTable {
    /// 创建流表
    pub fn new(ignore_vlan: bool) -> Self {
        Self {
            ignore_vlan,
            flows: HashMap::new(),
        }
    }

    /// 添加数据包到流
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

    /// 构建会话键
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

    /// 获取所有流
    pub fn flows(&self) -> &HashMap<SessionKey, FlowData> {
        &self.flows
    }

    /// 获取流数量
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

/// 单条流的数据
#[derive(Debug, Clone)]
pub struct FlowData {
    /// 源 IP
    pub src_ip: String,
    /// 源端口
    pub src_port: u16,
    /// 目标 IP
    pub dst_ip: String,
    /// 目标端口
    pub dst_port: u16,
    /// VLAN 标签栈
    pub vlan_stack: SmallVec<[u16; 2]>,
    /// TCP 状态
    pub tcp: TcpState,
    /// SMTP 状态
    pub smtp: SmtpState,
}

impl FlowData {
    pub fn new(src_ip: String, src_port: u16, dst_ip: String, dst_port: u16, vlan_stack: SmallVec<[u16; 2]>) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            vlan_stack,
            tcp: TcpState::default(),
            smtp: SmtpState::default(),
        }
    }

    /// 添加数据包
    pub fn add_packet(&mut self, packet: &DecodedPacket) {
        let direction = packet.direction;
        let payload_len = packet.payload.len() as u64;

        // 更新第一个包的时间戳
        if self.tcp.first_ts_micros.is_none() {
            self.tcp.first_ts_micros = Some(packet.timestamp_micros);
        }
        self.tcp.last_ts_micros = Some(packet.timestamp_micros);

        // 更新 TCP 状态
        match direction {
            Direction::AtoB => {
                self.tcp.packets_ab += 1;
                self.tcp.bytes_ab += payload_len;

                // 检测 SYN
                if packet.tcp_flags.syn && !packet.tcp_flags.ack {
                    self.tcp.syn_seen_ab = true;
                }

                // 检测握手 ACK (三次握手中的第三个 ACK)
                if packet.tcp_flags.ack && self.tcp.syn_seen_ab && self.tcp.syn_ack_seen {
                    self.tcp.handshake_ack_seen = true;
                    self.tcp.handshake_complete = true;
                }

                // 检测 FIN/RST
                if packet.tcp_flags.fin || packet.tcp_flags.rst {
                    self.tcp.fin_or_rst_seen = true;
                }

                // 检测有效载荷
                if payload_len > 0 && !packet.tcp_flags.is_pure_ack() {
                    self.tcp.has_payload_ab = true;
                }
            }
            Direction::BtoA => {
                self.tcp.packets_ba += 1;
                self.tcp.bytes_ba += payload_len;

                // 检测 SYN-ACK
                if packet.tcp_flags.syn && packet.tcp_flags.ack {
                    self.tcp.syn_ack_seen = true;
                }

                // 检测 FIN/RST
                if packet.tcp_flags.fin || packet.tcp_flags.rst {
                    self.tcp.fin_or_rst_seen = true;
                }

                // 检测有效载荷
                if payload_len > 0 && !packet.tcp_flags.is_pure_ack() {
                    self.tcp.has_payload_ba = true;
                }
            }
        }

        // 更新 SMTP 状态 (如果是明文 SMTP 且有载荷)
        if self.src_port == 25 || self.src_port == 587 {
            self.update_smtp_state(packet);
        } else if self.dst_port == 465 {
            // 465 端口是隐式 TLS
            self.smtp.is_implicit_tls = true;
        }
    }

    /// 更新 SMTP 状态
    fn update_smtp_state(&mut self, packet: &DecodedPacket) {
        let payload = &packet.payload;
        if payload.is_empty() {
            return;
        }

        // 尝试解析 SMTP 行
        if let Ok(text) = std::str::from_utf8(payload) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                // 解析服务端响应
                if line.starts_with("220") && !self.smtp.banner_seen {
                    self.smtp.banner_seen = true;
                    self.add_stage("banner");
                }

                // 解析客户端命令
                if line.starts_with("EHLO ") || line.starts_with("HELO ") {
                    self.smtp.helo_seen = true;
                    if !self.smtp.stages.contains(&"helo".to_string()) {
                        self.add_stage("helo");
                    }
                }

                if line.starts_with("MAIL FROM:") {
                    self.smtp.mail_from_seen = true;
                    self.add_stage("mail_from");
                }

                if line.starts_with("RCPT TO:") {
                    self.smtp.rcpt_to_seen = true;
                    if !self.smtp.stages.contains(&"rcpt_to".to_string()) {
                        self.add_stage("rcpt_to");
                    }
                }

                if line == "DATA" {
                    self.smtp.data_started = true;
                    self.add_stage("data");
                }

                if line == "." || line.ends_with("\r\n.\r\n") {
                    if self.smtp.data_started && !self.smtp.data_finished {
                        self.smtp.data_finished = true;
                        self.add_stage("data_end");
                    }
                }

                if line == "QUIT" {
                    self.smtp.quit_seen = true;
                    self.add_stage("quit");
                }

                if line == "STARTTLS" {
                    self.smtp.starttls_seen = true;
                    self.add_stage("starttls");
                }
            }
        }
    }

    /// 添加 SMTP 阶段
    fn add_stage(&mut self, stage: &str) {
        if !self.smtp.stages.contains(&stage.to_string()) {
            self.smtp.stages.push(stage.to_string());
        }
    }

    /// 获取主 VLAN ID (如果有)
    pub fn primary_vlan(&self) -> Option<u16> {
        self.vlan_stack.first().copied()
    }
}
