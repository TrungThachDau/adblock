use super::checksum::{calc_ipv4_checksum, calc_tcp_ipv4_checksum};

/// Parse SNI hostname from TLS Record Layer ClientHello payload
pub fn parse_tls_sni(tcp_payload: &[u8]) -> Option<String> {
    // Minimum TLS record + ClientHello header:
    // 5 bytes (Record Header) + 4 bytes (Handshake Header) + 2 (Version) + 32 (Random) + 1 (Session ID len)
    if tcp_payload.len() < 44 {
        return None;
    }

    // TLS Record Header:
    // Byte 0: ContentType (0x16 = Handshake)
    if tcp_payload[0] != 0x16 {
        return None;
    }
    // Byte 1..3: Version (e.g. 0x03, 0x01 or 0x03, 0x03)
    let _record_len = u16::from_be_bytes([tcp_payload[3], tcp_payload[4]]) as usize;

    // Handshake Header:
    // Byte 5: HandshakeType (0x01 = ClientHello)
    if tcp_payload[5] != 0x01 {
        return None;
    }

    let mut cursor = 5 + 4; // Skip Handshake Type (1) + Handshake Length (3)
    cursor += 2 + 32; // Skip Client Version (2) + Client Random (32)

    if cursor >= tcp_payload.len() {
        return None;
    }

    // Session ID
    let session_id_len = tcp_payload[cursor] as usize;
    cursor += 1 + session_id_len;

    // Cipher Suites
    if cursor + 2 > tcp_payload.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([tcp_payload[cursor], tcp_payload[cursor + 1]]) as usize;
    cursor += 2 + cipher_suites_len;

    // Compression Methods
    if cursor + 1 > tcp_payload.len() {
        return None;
    }
    let compression_len = tcp_payload[cursor] as usize;
    cursor += 1 + compression_len;

    // Extensions
    if cursor + 2 > tcp_payload.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([tcp_payload[cursor], tcp_payload[cursor + 1]]) as usize;
    cursor += 2;

    let extensions_end = (cursor + extensions_len).min(tcp_payload.len());

    while cursor + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([tcp_payload[cursor], tcp_payload[cursor + 1]]);
        let ext_len = u16::from_be_bytes([tcp_payload[cursor + 2], tcp_payload[cursor + 3]]) as usize;
        cursor += 4;

        if ext_type == 0x0000 {
            // Server Name Indication (SNI) extension
            if cursor + ext_len > extensions_end || ext_len < 2 {
                return None;
            }
            let server_name_list_len = u16::from_be_bytes([tcp_payload[cursor], tcp_payload[cursor + 1]]) as usize;
            let mut list_cursor = cursor + 2;
            let list_end = list_cursor + server_name_list_len;

            while list_cursor + 3 <= list_end {
                let name_type = tcp_payload[list_cursor];
                let name_len = u16::from_be_bytes([tcp_payload[list_cursor + 1], tcp_payload[list_cursor + 2]]) as usize;
                list_cursor += 3;

                if name_type == 0x00 {
                    // host_name
                    if list_cursor + name_len <= list_end {
                        let name_bytes = &tcp_payload[list_cursor..list_cursor + name_len];
                        return std::str::from_utf8(name_bytes)
                            .ok()
                            .map(|s| s.to_ascii_lowercase());
                    }
                }
                list_cursor += name_len;
            }
        }
        cursor += ext_len;
    }

    None
}

/// Construct synthetic TCP RST packet to client from original ClientHello packet
pub fn build_tcp_rst(packet: &[u8], is_ipv6: bool) -> Option<Vec<u8>> {
    if is_ipv6 {
        // IPv6 packet handling
        if packet.len() < 40 + 20 {
            return None;
        }
        let ip_hdr_len = 40;
        let tcp_hdr_len = (((packet[ip_hdr_len + 12] >> 4) & 0x0F) as usize) * 4;
        if packet.len() < ip_hdr_len + tcp_hdr_len {
            return None;
        }
        let payload_len = packet.len() - (ip_hdr_len + tcp_hdr_len);

        let orig_seq = u32::from_be_bytes([
            packet[ip_hdr_len + 4],
            packet[ip_hdr_len + 5],
            packet[ip_hdr_len + 6],
            packet[ip_hdr_len + 7],
        ]);
        let orig_ack = u32::from_be_bytes([
            packet[ip_hdr_len + 8],
            packet[ip_hdr_len + 9],
            packet[ip_hdr_len + 10],
            packet[ip_hdr_len + 11],
        ]);

        let total_len = 40 + 20; // IPv6 (40) + TCP without options (20)
        let mut res = vec![0u8; total_len];

        // Copy original IPv6 header and swap src/dst
        res[..40].copy_from_slice(&packet[..40]);
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        src_ip.copy_from_slice(&res[8..24]);
        dst_ip.copy_from_slice(&res[24..40]);
        res[8..24].copy_from_slice(&dst_ip);
        res[24..40].copy_from_slice(&src_ip);
        res[4..6].copy_from_slice(&20u16.to_be_bytes()); // IPv6 payload length = 20

        // Swap TCP ports
        let src_port = [packet[ip_hdr_len], packet[ip_hdr_len + 1]];
        let dst_port = [packet[ip_hdr_len + 2], packet[ip_hdr_len + 3]];
        res[ip_hdr_len..ip_hdr_len + 2].copy_from_slice(&dst_port);
        res[ip_hdr_len + 2..ip_hdr_len + 4].copy_from_slice(&src_port);

        // Sequence Number = original Ack; Acknowledgment = original Seq + payload_len
        let new_seq = orig_ack;
        let new_ack = orig_seq.wrapping_add(payload_len as u32);
        res[ip_hdr_len + 4..ip_hdr_len + 8].copy_from_slice(&new_seq.to_be_bytes());
        res[ip_hdr_len + 8..ip_hdr_len + 12].copy_from_slice(&new_ack.to_be_bytes());

        res[ip_hdr_len + 12] = 0x50; // Data offset = 5 (20 bytes)
        res[ip_hdr_len + 13] = 0x14; // Flags: RST | ACK
        res[ip_hdr_len + 14..ip_hdr_len + 16].fill(0); // Window = 0

        return Some(res);
    }

    // IPv4 packet handling
    if packet.len() < 20 + 20 {
        return None;
    }
    let ip_hdr_len = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ip_hdr_len + 20 {
        return None;
    }

    let tcp_hdr_len = (((packet[ip_hdr_len + 12] >> 4) & 0x0F) as usize) * 4;
    if packet.len() < ip_hdr_len + tcp_hdr_len {
        return None;
    }
    let payload_len = packet.len() - (ip_hdr_len + tcp_hdr_len);

    let orig_seq = u32::from_be_bytes([
        packet[ip_hdr_len + 4],
        packet[ip_hdr_len + 5],
        packet[ip_hdr_len + 6],
        packet[ip_hdr_len + 7],
    ]);
    let orig_ack = u32::from_be_bytes([
        packet[ip_hdr_len + 8],
        packet[ip_hdr_len + 9],
        packet[ip_hdr_len + 10],
        packet[ip_hdr_len + 11],
    ]);

    let total_len = ip_hdr_len + 20; // IP header + TCP header without options
    let mut res = vec![0u8; total_len];

    // Copy original IP header
    res[..ip_hdr_len].copy_from_slice(&packet[..ip_hdr_len]);

    // Swap IPv4 Source and Destination IP
    let mut src_ip = [0u8; 4];
    let mut dst_ip = [0u8; 4];
    src_ip.copy_from_slice(&res[12..16]);
    dst_ip.copy_from_slice(&res[16..20]);
    res[12..16].copy_from_slice(&dst_ip);
    res[16..20].copy_from_slice(&src_ip);

    // Total length = ip_hdr_len + 20
    res[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());

    // Swap TCP ports
    let src_port = [packet[ip_hdr_len], packet[ip_hdr_len + 1]];
    let dst_port = [packet[ip_hdr_len + 2], packet[ip_hdr_len + 3]];
    res[ip_hdr_len..ip_hdr_len + 2].copy_from_slice(&dst_port);
    res[ip_hdr_len + 2..ip_hdr_len + 4].copy_from_slice(&src_port);

    // Sequence Number = original Ack; Acknowledgment = original Seq + payload_len
    let new_seq = orig_ack;
    let new_ack = orig_seq.wrapping_add(payload_len as u32);
    res[ip_hdr_len + 4..ip_hdr_len + 8].copy_from_slice(&new_seq.to_be_bytes());
    res[ip_hdr_len + 8..ip_hdr_len + 12].copy_from_slice(&new_ack.to_be_bytes());

    res[ip_hdr_len + 12] = 0x50; // Data offset = 5 (20 bytes)
    res[ip_hdr_len + 13] = 0x14; // Flags: RST | ACK
    res[ip_hdr_len + 14..ip_hdr_len + 16].fill(0); // Window = 0
    res[ip_hdr_len + 18..ip_hdr_len + 20].fill(0); // Urgent pointer = 0

    // Recalculate checksums
    calc_ipv4_checksum(&mut res[..ip_hdr_len]);
    calc_tcp_ipv4_checksum(&mut res, ip_hdr_len);

    Some(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sni_and_rst() {
        let hex_payload = "45000085000100004006c496c0a8010a8efb2201d12301bb00000064000003e8501802000000000016030100600100005c03030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200000021301010000310000001900170000146164736572766963652e676f6f676c652e636f6d0017000000230000";
        let raw = hex::decode(hex_payload).unwrap();
        let ip_hdr_len = ((raw[0] & 0x0F) as usize) * 4;
        let tcp_hdr_len = (((raw[ip_hdr_len + 12] >> 4) & 0x0F) as usize) * 4;
        let payload = &raw[ip_hdr_len + tcp_hdr_len..];

        let sni = parse_tls_sni(payload).expect("Failed to parse SNI");
        assert_eq!(sni, "adservice.google.com");

        let rst = build_tcp_rst(&raw, false).expect("Failed to build RST");
        // Verify swapped IP
        assert_eq!(&rst[12..16], &[142, 251, 34, 1]); // New src = original dst (8efb2201)
        assert_eq!(&rst[16..20], &[192, 168, 1, 10]); // New dst = original src
        // Verify swapped TCP ports
        assert_eq!(&rst[ip_hdr_len..ip_hdr_len + 2], &[0x01, 0xbb]); // New src port = 443
        assert_eq!(&rst[ip_hdr_len + 2..ip_hdr_len + 4], &[0xd1, 0x23]); // New dst port = 53539
        // Verify RST | ACK flags (0x14)
        assert_eq!(rst[ip_hdr_len + 13], 0x14);
    }
}
