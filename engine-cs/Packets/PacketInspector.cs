using System;
using System.Buffers.Binary;

namespace AdblockEngine.Packets;

public enum PacketProtocol
{
    Dns,
    Tls,
    Quic,
    Other
}

public record InspectedPacketInfo(
    PacketProtocol Protocol,
    string? Domain,
    string ClientIp,
    bool IsIPv6
);

public static class PacketInspector
{
    public static InspectedPacketInfo? Inspect(ReadOnlySpan<byte> packet)
    {
        if (packet.IsEmpty) return null;

        int version = packet[0] >> 4;
        bool isIPv6;
        int ipHdrLen;
        byte proto;
        string clientIp;

        if (version == 4)
        {
            if (packet.Length < 20) return null;
            ipHdrLen = (packet[0] & 0x0F) * 4;
            proto = packet[9];
            clientIp = $"{packet[12]}.{packet[13]}.{packet[14]}.{packet[15]}";
            isIPv6 = false;
        }
        else if (version == 6)
        {
            if (packet.Length < 40) return null;
            ipHdrLen = 40;
            proto = packet[6];
            clientIp = $"{BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(8, 2)):x}:" +
                       $"{BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(10, 2)):x}:" +
                       $"{BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(12, 2)):x}:" +
                       $"{BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(14, 2)):x}:" +
                       $"{BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(16, 2)):x}:" +
                       $"{BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(18, 2)):x}:" +
                       $"{BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(20, 2)):x}:" +
                       $"{BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(22, 2)):x}";
            isIPv6 = true;
        }
        else
        {
            return null;
        }

        if (proto == 17) // UDP
        {
            if (packet.Length < ipHdrLen + 8) return null;
            ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHdrLen + 2, 2));
            if (dstPort == 53)
            {
                var dnsPayload = packet.Slice(ipHdrLen + 8);
                var question = DnsPacket.ParseDnsQuestion(dnsPayload);
                return new InspectedPacketInfo(PacketProtocol.Dns, question?.QName, clientIp, isIPv6);
            }
            else if (dstPort == 443)
            {
                return new InspectedPacketInfo(PacketProtocol.Quic, "[quic-port-443]", clientIp, isIPv6);
            }
        }
        else if (proto == 6) // TCP
        {
            if (packet.Length < ipHdrLen + 20) return null;
            ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHdrLen + 2, 2));
            if (dstPort == 443)
            {
                int tcpHdrLen = ((packet[ipHdrLen + 12] >> 4) & 0x0F) * 4;
                if (packet.Length > ipHdrLen + tcpHdrLen)
                {
                    var payload = packet.Slice(ipHdrLen + tcpHdrLen);
                    var sni = TlsPacket.ParseTlsSni(payload);
                    return new InspectedPacketInfo(PacketProtocol.Tls, sni, clientIp, isIPv6);
                }
            }
        }

        return null;
    }
}
