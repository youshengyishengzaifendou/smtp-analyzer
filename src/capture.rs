//! pcap/pcapng 文件读取模块

use pcap_parser::traits::PcapReaderExt;
use pcap_parser::{PcapBlockOwned, PcapError, PcapNGBlock, PcapNGReader};
use std::fs::File;
use std::io::BufReader;
use log::{debug, warn};

use crate::error::{AnalyzerError, Result};
use crate::model::DecodedPacket;
use crate::decoder::Decoder;

/// pcap 文件读取器
pub struct CaptureReader {
    reader: PcapNGReader<BufReader<File>>,
    decoder: Decoder,
    skipped_count: u64,
}

impl CaptureReader {
    /// 打开 pcap/pcapng 文件
    pub fn open(path: &str) -> Result<Self> {
        let file = File::open(path).map_err(|e| {
            AnalyzerError::FileOpen(format!("{}: {}", path, e))
        })?;

        let reader = PcapNGReader::new(BufReader::new(file))
            .map_err(|e| AnalyzerError::PcapParse(format!("Failed to create reader: {}", e)))?;

        Ok(Self {
            reader,
            decoder: Decoder::new(),
            skipped_count: 0,
        })
    }

    /// 获取跳过的包数量
    pub fn skipped_count(&self) -> u64 {
        self.skipped_count
    }

    /// 迭代解析数据包
    pub fn iter<'a>(&'a mut self) -> PacketIterator<'a> {
        PacketIterator {
            reader: self,
            needs_legacy: false,
        }
    }
}

/// 数据包迭代器
pub struct PacketIterator<'a> {
    reader: &'a mut CaptureReader,
    needs_legacy: bool,
}

impl<'a> Iterator for PacketIterator<'a> {
    type Item = Result<DecodedPacket>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let legacy = self.needs_legacy;
            match self.reader.reader.next_block() {
                Ok(pcap_parser::traits::ReadBlock::Eof) => return None,
                Ok(pcap_parser::traits::ReadBlock::Block(block)) => {
                    self.needs_legacy = false;
                    match block {
                        PcapBlockOwned::Legacy(b) => {
                            let caplen = b.caplen as usize;
                            if caplen == 0 {
                                continue;
                            }

                            let packet_data = &b.data[..caplen];
                            let timestamp = i64::from(b.ts_sec) * 1_000_000
                                + i64::from(b.ts_usec);

                            match self.reader.decoder.decode(packet_data, timestamp) {
                                Ok(packets) => {
                                    // 返回第一个解析出的包（通常每个链路层包只对应一个网络层包）
                                    if let Some(pkt) = packets.into_iter().next() {
                                        return Some(Ok(pkt));
                                    }
                                    // 如果没有解析出包，继续下一轮
                                    continue;
                                }
                                Err(e) => {
                                    self.reader.skipped_count += 1;
                                    debug!("跳过无法解析的包: {}", e);
                                    continue;
                                }
                            }
                        }
                        PcapBlockOwned::NG(PcapNGBlock::EnhancedPacket(epb)) => {
                            let caplen = epb.caplen as usize;
                            if caplen == 0 {
                                continue;
                            }

                            let packet_data = &epb.data[..caplen];
                            // 尝试从 if_fcstab 获取链路层类型
                            let link_type = self.reader.reader.if_fcstab()
                                .get(epb.if_id as usize)
                                .map(|if_| if_.link_type)
                                .unwrap_or(pcap_parser::Linktype::ETHERNET);

                            let timestamp = i64::from(epb.timestamp_high) * 1_000_000_000
                                + i64::from(epb.timestamp_low);

                            match self.reader.decoder.decode_with_linktype(packet_data, timestamp, link_type) {
                                Ok(packets) => {
                                    if let Some(pkt) = packets.into_iter().next() {
                                        return Some(Ok(pkt));
                                    }
                                    continue;
                                }
                                Err(e) => {
                                    self.reader.skipped_count += 1;
                                    debug!("跳过无法解析的包 (pcapng): {}", e);
                                    continue;
                                }
                            }
                        }
                        PcapBlockOwned::NG(PcapNGBlock::SimplePacket(spb)) => {
                            let caplen = spb.caplen as usize;
                            if caplen == 0 {
                                continue;
                            }

                            let packet_data = &spb.data[..caplen];
                            let timestamp = 0; // Simple Packet 没有时间戳

                            match self.reader.decoder.decode(packet_data, timestamp) {
                                Ok(packets) => {
                                    if let Some(pkt) = packets.into_iter().next() {
                                        return Some(Ok(pkt));
                                    }
                                    continue;
                                }
                                Err(e) => {
                                    self.reader.skipped_count += 1;
                                    debug!("跳过无法解析的包 (simple packet): {}", e);
                                    continue;
                                }
                            }
                        }
                        _ => {
                            // 其他类型的块（如 Interface Description, Name Resolution）
                            continue;
                        }
                    }
                }
                Ok(pcap_parser::traits::ReadBlock::Idle) => {
                    // 尝试刷新缓冲区
                    self.reader.reader.refill().ok();
                    continue;
                }
                Err(PcapError::Eof) => return None,
                Err(PcapError::Incomplete) => {
                    // 需要更多数据
                    self.reader.reader.refill().ok();
                    self.needs_legacy = legacy;
                    continue;
                }
                Err(e) => {
                    warn!("pcap 读取错误: {:?}", e);
                    return None;
                }
            }
        }
    }
}
