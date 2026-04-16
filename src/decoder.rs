//! 协议解码模块
//!
//! 支持: Ethernet, Linux SLL, VLAN, IPv4, IPv6, TCP

use etherparse::{NetSlice, SlicedPacket, TransportSlice, VlanSlice};
use pcap_parser::Linktype;
use smallvec::SmallVec;

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

    /// 解码数据包 (指定链路层类型)
    pub fn decode_with_linktype(
        &self,
        data: &[u8],
        timestamp: i64,
        link_type: Linktype,
    ) -> Result<Vec<DecodedPacket>> {
        let sliced = match link_type {
            Linktype::ETHERNET => SlicedPacket::from_ethernet(data),
            Linktype::LINUX_SLL => SlicedPacket::from_linux_sll(data),
            Linktype::RAW | Linktype::IPV4 | Linktype::IPV6 => SlicedPacket::from_ip(data),
            _ => SlicedPacket::from_ip(data),
        }
        .map_err(|e| AnalyzerError::Decode(format!("报文解析失败: {:?}", e)))?;

        self.decode_sliced_packet(sliced, timestamp)
    }

    fn decode_sliced_packet(
        &self,
        sliced: SlicedPacket<'_>,
        timestamp: i64,
    ) -> Result<Vec<DecodedPacket>> {
        let transport = match sliced.transport {
            Some(TransportSlice::Tcp(tcp)) => tcp,
            _ => return Ok(Vec::new()),
        };

        let (src_ip, dst_ip) = match sliced.net {
            Some(NetSlice::Ipv4(ipv4)) => (
                ipv4.header().source_addr().to_string(),
                ipv4.header().destination_addr().to_string(),
            ),
            Some(NetSlice::Ipv6(ipv6)) => (
                ipv6.header().source_addr().to_string(),
                ipv6.header().destination_addr().to_string(),
            ),
            None => return Ok(Vec::new()),
        };

        let src_port = transport.source_port();
        let dst_port = transport.destination_port();
        let src_is_service = self.ports.contains(&src_port);
        let dst_is_service = self.ports.contains(&dst_port);

        if !src_is_service && !dst_is_service {
            return Ok(Vec::new());
        }

        let direction = Self::determine_direction(src_port, dst_port, src_is_service, dst_is_service);

        let (client_ip, client_port, server_ip, server_port) = if direction == Direction::AtoB {
            (src_ip, src_port, dst_ip, dst_port)
        } else {
            (dst_ip, dst_port, src_ip, src_port)
        };

        let tcp_flags = TcpFlags {
            fin: transport.fin(),
            syn: transport.syn(),
            rst: transport.rst(),
            psh: transport.psh(),
            ack: transport.ack(),
        };

        let packet = DecodedPacket {
            vlan_stack: Self::extract_vlan_stack(sliced.vlan.as_ref()),
            src_ip: client_ip,
            src_port: client_port,
            dst_ip: server_ip,
            dst_port: server_port,
            protocol: 6,
            direction,
            seq_num: transport.sequence_number(),
            ack_num: transport.acknowledgment_number(),
            tcp_flags,
            payload: transport.payload().to_vec(),
            timestamp_micros: timestamp,
        };

        Ok(vec![packet])
    }

    fn determine_direction(
        src_port: u16,
        dst_port: u16,
        src_is_service: bool,
        dst_is_service: bool,
    ) -> Direction {
        match (src_is_service, dst_is_service) {
            (false, true) => Direction::AtoB,
            (true, false) => Direction::BtoA,
            (true, true) => {
                if dst_port <= src_port {
                    Direction::AtoB
                } else {
                    Direction::BtoA
                }
            }
            (false, false) => Direction::AtoB,
        }
    }

    fn extract_vlan_stack(vlan: Option<&VlanSlice<'_>>) -> SmallVec<[u16; 2]> {
        let mut vlan_stack = SmallVec::new();

        if let Some(vlan) = vlan {
            match vlan {
                VlanSlice::SingleVlan(single) => {
                    vlan_stack.push(single.vlan_identifier().value());
                }
                VlanSlice::DoubleVlan(double) => {
                    vlan_stack.push(double.outer().vlan_identifier().value());
                    vlan_stack.push(double.inner().vlan_identifier().value());
                }
            }
        }

        vlan_stack
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
