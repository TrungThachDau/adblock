pub mod checksum;
pub mod dns;
pub mod tls;

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
