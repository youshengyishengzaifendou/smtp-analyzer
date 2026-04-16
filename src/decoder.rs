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
    ) -> Result<Option<DecodedPacket>> {
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
    ) -> Result<Option<DecodedPacket>> {
        let transport = match sliced.transport {
            Some(TransportSlice::Tcp(tcp)) => tcp,
            _ => return Ok(None),
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
            None => return Ok(None),
        };

        let src_port = transport.source_port();
        let dst_port = transport.destination_port();
        let src_is_service = self.ports.contains(&src_port);
        let dst_is_service = self.ports.contains(&dst_port);

        if !src_is_service && !dst_is_service {
            return Ok(None);
        }

        let direction =
            Self::determine_direction(src_port, dst_port, src_is_service, dst_is_service);

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

        Ok(Some(packet))
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

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;

    use super::Decoder;
    use crate::model::Direction;
    use pcap_parser::Linktype;

    fn build_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2(
            [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            [0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0],
        )
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, 1000, 4096)
        .ack(5000)
        .psh();

        let mut bytes = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut bytes, payload)
            .expect("test packet should serialize");
        bytes
    }

    #[test]
    fn decode_with_linktype_returns_client_to_server_packet() {
        let decoder = Decoder::default();
        let packet = build_tcp_packet(
            [192, 0, 2, 10],
            [198, 51, 100, 25],
            43210,
            25,
            b"EHLO example.test\r\n",
        );

        let decoded = decoder
            .decode_with_linktype(&packet, 123, Linktype::ETHERNET)
            .expect("decode should succeed")
            .expect("SMTP packet should be kept");

        assert_eq!(decoded.direction, Direction::AtoB);
        assert_eq!(decoded.src_ip, "192.0.2.10");
        assert_eq!(decoded.src_port, 43210);
        assert_eq!(decoded.dst_ip, "198.51.100.25");
        assert_eq!(decoded.dst_port, 25);
        assert_eq!(decoded.payload, b"EHLO example.test\r\n");
    }

    #[test]
    fn decode_with_linktype_normalizes_server_to_client_packet() {
        let decoder = Decoder::default();
        let packet = build_tcp_packet(
            [198, 51, 100, 25],
            [192, 0, 2, 10],
            25,
            43210,
            b"220 mail.example.test\r\n",
        );

        let decoded = decoder
            .decode_with_linktype(&packet, 456, Linktype::ETHERNET)
            .expect("decode should succeed")
            .expect("SMTP packet should be kept");

        assert_eq!(decoded.direction, Direction::BtoA);
        assert_eq!(decoded.src_ip, "192.0.2.10");
        assert_eq!(decoded.src_port, 43210);
        assert_eq!(decoded.dst_ip, "198.51.100.25");
        assert_eq!(decoded.dst_port, 25);
        assert_eq!(decoded.payload, b"220 mail.example.test\r\n");
    }

    #[test]
    fn decode_with_linktype_filters_untracked_ports() {
        let decoder = Decoder::default();
        let packet = build_tcp_packet(
            [192, 0, 2, 10],
            [198, 51, 100, 25],
            43210,
            2525,
            b"not smtp",
        );

        let decoded = decoder
            .decode_with_linktype(&packet, 789, Linktype::ETHERNET)
            .expect("decode should succeed");

        assert!(decoded.is_none());
    }
}
