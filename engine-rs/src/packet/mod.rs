pub mod checksum;
pub mod dns;
pub mod tls;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketProtocol {
    Dns,
    Tls,
    Quic,
    Other,
}

pub struct InspectedPacketInfo {
    pub protocol: PacketProtocol,
    pub domain: Option<String>,
    pub client_ip: String,
    pub is_ipv6: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpFlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

pub struct TcpPacketDetails {
    pub flow_key: TcpFlowKey,
    pub flags: u8,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub is_ipv6: bool,
}

/// Parse TCP header and extract flow key, flags, and payload bounds
pub fn parse_tcp_details(packet: &[u8]) -> Option<TcpPacketDetails> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    let (is_ipv6, ip_hdr_len, src_ip, dst_ip) = match version {
        4 => {
            if packet.len() < 20 || packet[9] != 6 {
                return None;
            }
            let ihl = ((packet[0] & 0x0F) as usize) * 4;
            let src = IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]));
            (false, ihl, src, dst)
        }
        6 => {
            if packet.len() < 40 || packet[6] != 6 {
                return None;
            }
            let mut src_bytes = [0u8; 16];
            let mut dst_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&packet[8..24]);
            dst_bytes.copy_from_slice(&packet[24..40]);
            (true, 40, IpAddr::V6(Ipv6Addr::from(src_bytes)), IpAddr::V6(Ipv6Addr::from(dst_bytes)))
        }
        _ => return None,
    };

    if packet.len() < ip_hdr_len + 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([packet[ip_hdr_len], packet[ip_hdr_len + 1]]);
    let dst_port = u16::from_be_bytes([packet[ip_hdr_len + 2], packet[ip_hdr_len + 3]]);
    let data_offset = (((packet[ip_hdr_len + 12] >> 4) & 0x0F) as usize) * 4;
    if data_offset < 20 || packet.len() < ip_hdr_len + data_offset {
        return None;
    }

    let flags = packet[ip_hdr_len + 13];
    let payload_offset = ip_hdr_len + data_offset;
    let payload_len = packet.len() - payload_offset;

    Some(TcpPacketDetails {
        flow_key: TcpFlowKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        },
        flags,
        payload_offset,
        payload_len,
        is_ipv6,
    })
}

/// Quick classification of an intercepted packet
pub fn inspect_packet(packet: &[u8]) -> Option<InspectedPacketInfo> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    let (is_ipv6, ip_hdr_len, protocol, client_ip) = match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = ((packet[0] & 0x0F) as usize) * 4;
            let proto = packet[9];
            let src_ip = format!("{}.{}.{}.{}", packet[12], packet[13], packet[14], packet[15]);
            (false, ihl, proto, src_ip)
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let proto = packet[6];
            let mut parts = [0u16; 8];
            for i in 0..8 {
                parts[i] = u16::from_be_bytes([packet[8 + i * 2], packet[8 + i * 2 + 1]]);
            }
            let src_ip = format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]);
            (true, 40, proto, src_ip)
        }
        _ => return None,
    };

    if protocol == 17 {
        // UDP
        if packet.len() < ip_hdr_len + 8 {
            return None;
        }
        let dst_port = u16::from_be_bytes([packet[ip_hdr_len + 2], packet[ip_hdr_len + 3]]);
        if dst_port == 53 {
            // DNS
            let dns_payload = &packet[ip_hdr_len + 8..];
            let domain = dns::parse_dns_question(dns_payload).map(|q| q.qname);
            return Some(InspectedPacketInfo {
                protocol: PacketProtocol::Dns,
                domain,
                client_ip,
                is_ipv6,
            });
        } else if dst_port == 443 {
            // QUIC / HTTP3
            return Some(InspectedPacketInfo {
                protocol: PacketProtocol::Quic,
                domain: Some("[quic-port-443]".to_string()),
                client_ip,
                is_ipv6,
            });
        }
    } else if protocol == 6 {
        // TCP
        if packet.len() < ip_hdr_len + 20 {
            return None;
        }
        let dst_port = u16::from_be_bytes([packet[ip_hdr_len + 2], packet[ip_hdr_len + 3]]);
        if dst_port == 443 {
            let tcp_hdr_len = (((packet[ip_hdr_len + 12] >> 4) & 0x0F) as usize) * 4;
            if packet.len() > ip_hdr_len + tcp_hdr_len {
                let payload = &packet[ip_hdr_len + tcp_hdr_len..];
                let domain = tls::parse_tls_sni(payload);
                return Some(InspectedPacketInfo {
                    protocol: PacketProtocol::Tls,
                    domain,
                    client_ip,
                    is_ipv6,
                });
            }
        }
    }

    None
}
