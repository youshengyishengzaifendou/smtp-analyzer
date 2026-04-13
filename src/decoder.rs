//! 协议解码模块
//!
//! 支持: Ethernet, 802.1Q VLAN, IPv4, IPv6, TCP

use etherparse::{IpHeader, SlicedPacket, TcpHeader};
use smallvec::SmallVec;
use pcap_parser::Linktype;

use crate::error::{AnalyzerError, Result};
use crate::model::{DecodedPacket, Direction, TcpFlags};

/// 协议解码器
pub struct Decoder {
    /// 监控端口列表
    ports: Vec<u16>,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            ports: vec![25, 587, 465],
        }
    }

    /// 设置监控端口
    pub fn set_ports(&mut self, ports: Vec<u16>) {
        self.ports = ports;
    }

    /// 解码数据包 (使用默认链路层类型 ETHERNET)
    pub fn decode(&self, data: &[u8], timestamp: i64) -> Result<Vec<DecodedPacket>> {
        self.decode_with_linktype(data, timestamp, Linktype::ETHERNET)
    }

    /// 解码数据包 (指定链路层类型)
    pub fn decode_with_linktype(
        &self,
        data: &[u8],
        timestamp: i64,
        link_type: Linktype,
    ) -> Result<Vec<DecodedPacket>> {
        let mut packets = Vec::new();

        // 根据链路层类型进行解码
        match link_type {
            Linktype::ETHERNET => {
                self.decode_ethernet(data, timestamp, &mut packets)?;
            }
            _ => {
                // 对于未知链路层类型，尝试当作原始 IP 数据处理
                self.decode_ip(data, timestamp, SmallVec::new(), &mut packets)?;
            }
        }

        Ok(packets)
    }

    /// 解码以太网帧
    fn decode_ethernet(
        &self,
        data: &[u8],
        timestamp: i64,
        packets: &mut Vec<DecodedPacket>,
    ) -> Result<()> {
        // 至少需要以太网头 (14 字节)
        if data.len() < 14 {
            return Err(AnalyzerError::Decode("数据太短，不是有效的以太网帧".into()));
        }

        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        let mut vlan_stack: SmallVec<[u16; 2]> = SmallVec::new();

        let mut offset = 12;

        // 处理 VLAN 标签
        match ethertype {
            0x8100 => {
                // 单层 VLAN
                if data.len() < 18 {
                    return Err(AnalyzerError::Decode("数据太短，无法解析 VLAN 标签".into()));
                }
                let vlan_id = u16::from_be_bytes([data[14], data[15]]) & 0x0FFF;
                vlan_stack.push(vlan_id);
                offset = 16;

                // 检查是否还有内层 VLAN (QinQ)
                if offset + 2 <= data.len() {
                    let inner_ethertype = u16::from_be_bytes([data[offset], data[offset + 1]]);
                    if inner_ethertype == 0x8100 {
                        if offset + 6 <= data.len() {
                            let inner_vlan_id = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) & 0x0FFF;
                            vlan_stack.insert(0, inner_vlan_id);
                            offset += 4;
                        }
                    }
                }
            }
            0x9100 | 0x9200 | 0x9300 => {
                // 双层 VLAN (QinQ/802.1ad)
                if data.len() < 22 {
                    return Err(AnalyzerError::Decode("数据太短，无法解析双层 VLAN".into()));
                }
                let outer_vlan = u16::from_be_bytes([data[14], data[15]]) & 0x0FFF;
                let inner_vlan = u16::from_be_bytes([data[18], data[19]]) & 0x0FFF;
                vlan_stack.push(outer_vlan);
                vlan_stack.push(inner_vlan);
                offset = 20;
            }
            _ => {
                // 无 VLAN
            }
        }

        // 解码 IP 层
        self.decode_ip(&data[offset..], timestamp, vlan_stack, packets)?;

        Ok(())
    }

    /// 解码 IP 层
    fn decode_ip(
        &self,
        data: &[u8],
        timestamp: i64,
        vlan_stack: SmallVec<[u16; 2]>,
        packets: &mut Vec<DecodedPacket>,
    ) -> Result<()> {
        match SlicedPacket::from_ip(data) {
            Ok(sliced) => {
                match sliced.ip {
                    IpHeader::Version4(header, payload) => {
                        self.decode_tcp(
                            header.protocol,
                            header.source,
                            header.destination,
                            payload,
                            timestamp,
                            vlan_stack,
                            packets,
                        )?;
                    }
                    IpHeader::Version6(header, payload) => {
                        // IPv6: next_header 字段就是协议号
                        self.decode_tcp(
                            header.next_header,
                            header.source,
                            header.destination,
                            payload,
                            timestamp,
                            vlan_stack,
                            packets,
                        )?;
                    }
                    _ => {
                        return Err(AnalyzerError::Decode("未知的 IP 版本".into()));
                    }
                }
            }
            Err(e) => {
                return Err(AnalyzerError::Decode(format!("IP 解析失败: {:?}", e)));
            }
        }

        Ok(())
    }

    /// 解码 TCP 层
    fn decode_tcp(
        &self,
        protocol: u8,
        src_ip: etherparse::IpAddress,
        dst_ip: etherparse::IpAddress,
        transport_data: &[u8],
        timestamp: i64,
        mut vlan_stack: SmallVec<[u16; 2]>,
        packets: &mut Vec<DecodedPacket>,
    ) -> Result<()> {
        // 只处理 TCP 协议
        if protocol != 6 {
            return Ok(());
        }

        match TcpHeader::slice(transport_data, 0) {
            Ok((tcp_header, payload)) => {
                let src_port = tcp_header.source_port;
                let dst_port = tcp_header.destination_port;

                // 过滤端口 - 只保留 SMTP 相关端口
                if !self.ports.contains(&src_port) && !self.ports.contains(&dst_port) {
                    return Ok(());
                }

                // 判断方向
                let direction = if self.ports.contains(&src_port) {
                    Direction::BtoA
                } else {
                    Direction::AtoB
                };

                // 交换 IP 和端口，使 A 始终是客户端
                let (src_ip_str, dst_ip_str, src_port_u16, dst_port_u16) =
                    if direction == Direction::AtoB {
                        (src_ip.to_string(), dst_ip.to_string(), src_port, dst_port)
                    } else {
                        (dst_ip.to_string(), src_ip.to_string(), dst_port, src_port)
                    };

                let tcp_flags = TcpFlags::from_bits(tcp_header.psh_ack_fin);

                let packet = DecodedPacket {
                    vlan_stack,
                    src_ip: src_ip_str,
                    src_port: src_port_u16,
                    dst_ip: dst_ip_str,
                    dst_port: dst_port_u16,
                    protocol: 6,
                    direction,
                    seq_num: tcp_header.sequence_number,
                    ack_num: tcp_header.acknowledgment_number,
                    tcp_flags,
                    payload: payload.to_vec(),
                    timestamp_micros: timestamp,
                };

                packets.push(packet);
            }
            Err(e) => {
                return Err(AnalyzerError::Decode(format!("TCP 解析失败: {:?}", e)));
            }
        }

        Ok(())
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
