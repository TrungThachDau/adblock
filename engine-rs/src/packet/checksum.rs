/// RFC 1071 standard one's complement Internet Checksum calculations
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum += word as u32;
    }
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        sum += (remainder[0] as u32) << 8;
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Calculate IPv4 Header Checksum
pub fn calc_ipv4_checksum(ip_header: &mut [u8]) {
    if ip_header.len() < 20 {
        return;
    }
    // Zero out checksum field at offset 10..12
    ip_header[10] = 0;
    ip_header[11] = 0;
    let ihl = (ip_header[0] & 0x0F) as usize * 4;
    let cs = internet_checksum(&ip_header[..ihl]);
    ip_header[10..12].copy_from_slice(&cs.to_be_bytes());
}

/// Calculate UDP Checksum (IPv4 pseudo-header + UDP header + payload)
pub fn calc_udp_ipv4_checksum(packet: &mut [u8], ip_hdr_len: usize) {
    if packet.len() < ip_hdr_len + 8 {
        return;
    }
    let udp_len = u16::from_be_bytes([packet[ip_hdr_len + 4], packet[ip_hdr_len + 5]]) as usize;
    if packet.len() < ip_hdr_len + udp_len {
        return;
    }

    // Zero out UDP checksum field (offset 6..8 in UDP header)
    packet[ip_hdr_len + 6] = 0;
    packet[ip_hdr_len + 7] = 0;

    let src_ip = &packet[12..16];
    let dst_ip = &packet[16..20];
    let protocol = packet[9];

    // Build pseudo header
    let mut pseudo = Vec::with_capacity(12 + udp_len);
    pseudo.extend_from_slice(src_ip);
    pseudo.extend_from_slice(dst_ip);
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&packet[ip_hdr_len..ip_hdr_len + udp_len]);

    let cs = internet_checksum(&pseudo);
    let final_cs = if cs == 0 { 0xFFFF } else { cs };
    packet[ip_hdr_len + 6..ip_hdr_len + 8].copy_from_slice(&final_cs.to_be_bytes());
}

/// Calculate TCP Checksum (IPv4 pseudo-header + TCP header + payload)
pub fn calc_tcp_ipv4_checksum(packet: &mut [u8], ip_hdr_len: usize) {
    if packet.len() < ip_hdr_len + 20 {
        return;
    }
    let tcp_seg_len = packet.len() - ip_hdr_len;

    // Zero out TCP checksum field (offset 16..18 in TCP header)
    packet[ip_hdr_len + 16] = 0;
    packet[ip_hdr_len + 17] = 0;

    let src_ip = &packet[12..16];
    let dst_ip = &packet[16..20];
    let protocol = packet[9];

    let mut pseudo = Vec::with_capacity(12 + tcp_seg_len);
    pseudo.extend_from_slice(src_ip);
    pseudo.extend_from_slice(dst_ip);
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(&(tcp_seg_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&packet[ip_hdr_len..]);

    let cs = internet_checksum(&pseudo);
    packet[ip_hdr_len + 16..ip_hdr_len + 18].copy_from_slice(&cs.to_be_bytes());
}
