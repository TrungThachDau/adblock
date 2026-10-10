use super::checksum::{calc_ipv4_checksum, calc_udp_ipv4_checksum};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub question_end_offset: usize, // relative to UDP payload
}

/// Parse the first Question section from raw DNS payload (following the 12-byte header)
pub fn parse_dns_question(dns_payload: &[u8]) -> Option<DnsQuestion> {
    if dns_payload.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([dns_payload[4], dns_payload[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut cursor = 12;
    let mut labels = Vec::new();

    while cursor < dns_payload.len() {
        let len = dns_payload[cursor] as usize;
        cursor += 1;

        if len == 0 {
            // End of domain name
            break;
        }

        // Pointer / compression check (unlikely in question, but guard)
        if len & 0xC0 == 0xC0 {
            cursor += 1;
            break;
        }

        if cursor + len > dns_payload.len() {
            return None;
        }

        let label = std::str::from_utf8(&dns_payload[cursor..cursor + len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        cursor += len;
    }

    if cursor + 4 > dns_payload.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([dns_payload[cursor], dns_payload[cursor + 1]]);
    let qclass = u16::from_be_bytes([dns_payload[cursor + 2], dns_payload[cursor + 3]]);
    cursor += 4;

    Some(DnsQuestion {
        qname: labels.join("."),
        qtype,
        qclass,
        question_end_offset: cursor,
    })
}

/// Construct synthetic DNS NXDOMAIN response from original query packet
pub fn build_dns_nxdomain(packet: &[u8], is_ipv6: bool) -> Option<Vec<u8>> {
    if is_ipv6 {
        // IPv6 packet handling
        if packet.len() < 40 + 8 + 12 {
            return None;
        }
        let ip_hdr_len = 40;
        let udp_hdr_len = 8;
        let dns_offset = ip_hdr_len + udp_hdr_len;

        let question = parse_dns_question(&packet[dns_offset..])?;
        let new_dns_payload_len = question.question_end_offset;
        let new_udp_len = udp_hdr_len + new_dns_payload_len;
        let new_total_len = ip_hdr_len + new_udp_len;

        let mut res = Vec::with_capacity(new_total_len);
        res.extend_from_slice(&packet[..new_total_len]);

        // Swap IPv6 source and destination
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        src_ip.copy_from_slice(&res[8..24]);
        dst_ip.copy_from_slice(&res[24..40]);
        res[8..24].copy_from_slice(&dst_ip);
        res[24..40].copy_from_slice(&src_ip);

        // IPv6 Payload Length (excludes IPv6 40-byte header)
        res[4..6].copy_from_slice(&(new_udp_len as u16).to_be_bytes());

        // Swap UDP source and destination ports
        let src_port = [res[ip_hdr_len], res[ip_hdr_len + 1]];
        let dst_port = [res[ip_hdr_len + 2], res[ip_hdr_len + 3]];
        res[ip_hdr_len..ip_hdr_len + 2].copy_from_slice(&dst_port);
        res[ip_hdr_len + 2..ip_hdr_len + 4].copy_from_slice(&src_port);
        res[ip_hdr_len + 4..ip_hdr_len + 6].copy_from_slice(&(new_udp_len as u16).to_be_bytes());

        // Set DNS Flags: 0x8183 (QR=1, RD=1, RA=1, RCODE=3 NXDOMAIN)
        res[dns_offset + 2] = 0x81;
        res[dns_offset + 3] = 0x83;

        // Set Question count = 1, Answer = 0, NS = 0, Additional = 0
        res[dns_offset + 4..dns_offset + 6].copy_from_slice(&1u16.to_be_bytes());
        res[dns_offset + 6..dns_offset + 12].fill(0);

        return Some(res);
    }

    // IPv4 packet handling
    if packet.len() < 20 + 8 + 12 {
        return None;
    }

    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    let udp_hdr_len = 8;
    let dns_offset = ihl + udp_hdr_len;

    if packet.len() < dns_offset + 12 {
        return None;
    }

    let question = parse_dns_question(&packet[dns_offset..])?;
    let new_dns_payload_len = question.question_end_offset;
    let new_udp_len = udp_hdr_len + new_dns_payload_len;
    let new_total_len = ihl + new_udp_len;

    let mut res = Vec::with_capacity(new_total_len);
    res.extend_from_slice(&packet[..new_total_len]);

    // Swap IPv4 Source and Destination IP
    let mut src_ip = [0u8; 4];
    let mut dst_ip = [0u8; 4];
    src_ip.copy_from_slice(&res[12..16]);
    dst_ip.copy_from_slice(&res[16..20]);
    res[12..16].copy_from_slice(&dst_ip);
    res[16..20].copy_from_slice(&src_ip);

    // Update IPv4 Total Length
    res[2..4].copy_from_slice(&(new_total_len as u16).to_be_bytes());

    // Swap UDP source and destination ports
    let src_port = [res[ihl], res[ihl + 1]];
    let dst_port = [res[ihl + 2], res[ihl + 3]];
    res[ihl..ihl + 2].copy_from_slice(&dst_port);
    res[ihl + 2..ihl + 4].copy_from_slice(&src_port);
    res[ihl + 4..ihl + 6].copy_from_slice(&(new_udp_len as u16).to_be_bytes());

    // Set DNS Flags: 0x8183 (QR=1, RD=1, RA=1, RCODE=3 NXDOMAIN)
    res[dns_offset + 2] = 0x81;
    res[dns_offset + 3] = 0x83;

    // Set Question count = 1, Answer = 0, NS = 0, Additional = 0
    res[dns_offset + 4..dns_offset + 6].copy_from_slice(&1u16.to_be_bytes());
    res[dns_offset + 6..dns_offset + 12].fill(0);

    // Recalculate checksums
    calc_ipv4_checksum(&mut res[..ihl]);
    calc_udp_ipv4_checksum(&mut res, ihl);

    Some(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_nxdomain() {
        let hex_query = "45000046123400004011ea52c0a8010a08080808c001003500320000aabb010000010000000000000961647365727669636506676f6f676c6503636f6d0000010001";
        let raw = hex::decode(hex_query).unwrap();
        let ihl = ((raw[0] & 0x0F) as usize) * 4;
        let dns_payload = &raw[ihl + 8..];

        let q = parse_dns_question(dns_payload).expect("Failed to parse DNS question");
        assert_eq!(q.qname, "adservice.google.com");
        assert_eq!(q.qtype, 1);
        assert_eq!(q.qclass, 1);

        let nxdomain = build_dns_nxdomain(&raw, false).expect("Failed to build NXDOMAIN");
        // Verify swapped IP
        assert_eq!(&nxdomain[12..16], &[8, 8, 8, 8]); // New src = 8.8.8.8
        assert_eq!(&nxdomain[16..20], &[192, 168, 1, 10]); // New dst = 192.168.1.10
        // Verify swapped UDP ports
        assert_eq!(&nxdomain[ihl..ihl + 2], &[0x00, 0x35]); // New src port = 53
        assert_eq!(&nxdomain[ihl + 2..ihl + 4], &[0xc0, 0x01]); // New dst port = 49153
        // Verify DNS flags 0x8183
        assert_eq!(nxdomain[ihl + 8 + 2], 0x81);
        assert_eq!(nxdomain[ihl + 8 + 3], 0x83);
    }
}
