use std::net::IpAddr;

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
