//! pcap/pcapng 文件读取模块

use std::fs::File;

use log::{debug, warn};
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
use pcap_parser::{
    create_reader, Block, InterfaceDescriptionBlock, Linktype, PcapBlockOwned, PcapError,
    PcapHeader,
};

use crate::decoder::Decoder;
use crate::error::{AnalyzerError, Result};
use crate::model::DecodedPacket;

const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
struct InterfaceState {
    linktype: Linktype,
    ts_resolution: u64,
    ts_offset: i64,
}

impl InterfaceState {
    fn from_idb(idb: &InterfaceDescriptionBlock<'_>) -> Self {
        Self {
            linktype: idb.linktype,
            ts_resolution: idb.ts_resolution().unwrap_or(1_000_000).max(1),
            ts_offset: idb.ts_offset(),
        }
    }
}

/// pcap 文件读取器
pub struct CaptureReader {
    reader: Box<dyn PcapReaderIterator>,
    decoder: Decoder,
    skipped_count: u64,
    legacy_linktype: Linktype,
    legacy_ns_precision: bool,
    interfaces: Vec<InterfaceState>,
}

impl CaptureReader {
    /// 打开 pcap/pcapng 文件
    pub fn open(path: &str, ports: Vec<u16>) -> Result<Self> {
        let file = File::open(path).map_err(|e| AnalyzerError::FileOpen(format!("{}: {}", path, e)))?;
        let reader = create_reader(DEFAULT_BUFFER_SIZE, file)
            .map_err(|e| AnalyzerError::PcapParse(format!("无法创建抓包读取器: {:?}", e)))?;

        let mut decoder = Decoder::new();
        decoder.set_ports(ports);

        Ok(Self {
            reader,
            decoder,
            skipped_count: 0,
            legacy_linktype: Linktype::ETHERNET,
            legacy_ns_precision: false,
            interfaces: Vec::new(),
        })
    }

    /// 获取跳过的包数量
    pub fn skipped_count(&self) -> u64 {
        self.skipped_count
    }

    /// 迭代解析数据包
    pub fn iter<'a>(&'a mut self) -> PacketIterator<'a> {
        PacketIterator { reader: self }
    }

    fn process_block(
        block: PcapBlockOwned<'_>,
        decoder: &Decoder,
        skipped_count: &mut u64,
        legacy_linktype: &mut Linktype,
        legacy_ns_precision: &mut bool,
        interfaces: &mut Vec<InterfaceState>,
    ) -> Option<Result<DecodedPacket>> {
        match block {
            PcapBlockOwned::LegacyHeader(header) => {
                Self::handle_legacy_header(&header, legacy_linktype, legacy_ns_precision);
                None
            }
            PcapBlockOwned::Legacy(packet) => {
                if packet.caplen == 0 || packet.data.is_empty() {
                    return None;
                }

                let timestamp =
                    Self::legacy_timestamp_micros(*legacy_ns_precision, packet.ts_sec, packet.ts_usec);
                Self::decode_packet(decoder, skipped_count, packet.data, timestamp, *legacy_linktype)
            }
            PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                interfaces.clear();
                None
            }
            PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                interfaces.push(InterfaceState::from_idb(&idb));
                None
            }
            PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                let packet_data = epb.packet_data();
                if packet_data.is_empty() {
                    return None;
                }

                let interface = interfaces
                    .get(epb.if_id as usize)
                    .copied()
                    .unwrap_or(InterfaceState {
                        linktype: Linktype::ETHERNET,
                        ts_resolution: 1_000_000,
                        ts_offset: 0,
                });
                let timestamp = Self::pcapng_timestamp_micros(epb.ts_high, epb.ts_low, interface);

                Self::decode_packet(decoder, skipped_count, packet_data, timestamp, interface.linktype)
            }
            PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                let packet_data = spb.packet_data();
                if packet_data.is_empty() {
                    return None;
                }

                let linktype = interfaces
                    .first()
                    .map(|interface| interface.linktype)
                    .unwrap_or(Linktype::ETHERNET);

                Self::decode_packet(decoder, skipped_count, packet_data, 0, linktype)
            }
            PcapBlockOwned::NG(_) => None,
        }
    }

    fn handle_legacy_header(
        header: &PcapHeader,
        legacy_linktype: &mut Linktype,
        legacy_ns_precision: &mut bool,
    ) {
        *legacy_linktype = header.network;
        *legacy_ns_precision = header.is_nanosecond_precision();
    }

    fn decode_packet(
        decoder: &Decoder,
        skipped_count: &mut u64,
        packet_data: &[u8],
        timestamp: i64,
        linktype: Linktype,
    ) -> Option<Result<DecodedPacket>> {
        match decoder.decode_with_linktype(packet_data, timestamp, linktype) {
            Ok(mut packets) => packets.drain(..).next().map(Ok),
            Err(e) => {
                *skipped_count += 1;
                debug!("跳过无法解析的数据包: {}", e);
                None
            }
        }
    }

    fn legacy_timestamp_micros(legacy_ns_precision: bool, ts_sec: u32, ts_fractional: u32) -> i64 {
        let fractional = if legacy_ns_precision {
            u64::from(ts_fractional / 1_000)
        } else {
            u64::from(ts_fractional)
        };

        let micros = u64::from(ts_sec) * 1_000_000 + fractional;
        i64::try_from(micros).unwrap_or(i64::MAX)
    }

    fn pcapng_timestamp_micros(ts_high: u32, ts_low: u32, interface: InterfaceState) -> i64 {
        let raw = ((ts_high as i128) << 32) | i128::from(ts_low);
        let micros = raw * 1_000_000 / i128::from(interface.ts_resolution)
            + i128::from(interface.ts_offset) * 1_000_000;

        i64::try_from(micros).unwrap_or_else(|_| {
            if micros.is_negative() {
                i64::MIN
            } else {
                i64::MAX
            }
        })
    }
}

/// 数据包迭代器
pub struct PacketIterator<'a> {
    reader: &'a mut CaptureReader,
}

impl<'a> Iterator for PacketIterator<'a> {
    type Item = Result<DecodedPacket>;

    fn next(&mut self) -> Option<Self::Item> {
        let CaptureReader {
            reader,
            decoder,
            skipped_count,
            legacy_linktype,
            legacy_ns_precision,
            interfaces,
        } = &mut *self.reader;

        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    let result = CaptureReader::process_block(
                        block,
                        decoder,
                        skipped_count,
                        legacy_linktype,
                        legacy_ns_precision,
                        interfaces,
                    );
                    reader.consume(offset);

                    if let Some(packet) = result {
                        return Some(packet);
                    }
                }
                Err(PcapError::Eof) => return None,
                Err(PcapError::Incomplete(_)) => {
                    if let Err(e) = reader.refill() {
                        warn!("pcap 读取补充数据失败: {:?}", e);
                        return None;
                    }
                }
                Err(PcapError::BufferTooSmall) => {
                    let new_size = reader.data().len().max(DEFAULT_BUFFER_SIZE) * 2;
                    if !reader.grow(new_size) {
                        warn!("pcap 读取缓冲区过小，且扩容失败");
                        return None;
                    }
                }
                Err(e) => {
                    warn!("pcap 读取错误: {:?}", e);
                    return None;
                }
            }
        }
    }
}
