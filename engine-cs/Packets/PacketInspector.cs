using System;
using System.Buffers.Binary;
using System.Net;

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

public readonly record struct FlowAddress(ulong High, ulong Low, bool IsIPv6)
{
    public static FlowAddress FromIPv4(ReadOnlySpan<byte> span)
    {
        uint ip = BinaryPrimitives.ReadUInt32BigEndian(span);
        return new FlowAddress(0, ip, false);
    }

    public static FlowAddress FromIPv6(ReadOnlySpan<byte> span)
    {
        ulong high = BinaryPrimitives.ReadUInt64BigEndian(span.Slice(0, 8));
        ulong low = BinaryPrimitives.ReadUInt64BigEndian(span.Slice(8, 8));
        return new FlowAddress(high, low, true);
    }

    public override string ToString()
    {
        if (!IsIPv6)
        {
            uint ip = (uint)Low;
            return $"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}";
        }
        else
        {
            Span<byte> b = stackalloc byte[16];
            BinaryPrimitives.WriteUInt64BigEndian(b.Slice(0, 8), High);
            BinaryPrimitives.WriteUInt64BigEndian(b.Slice(8, 8), Low);
            return new IPAddress(b).ToString();
        }
    }
}

public readonly record struct TcpFlowKey(
    FlowAddress SrcIp,
    ushort SrcPort,
    FlowAddress DstIp,
    ushort DstPort
);

public readonly record struct TcpPacketDetails(
    TcpFlowKey FlowKey,
    byte Flags,
    int PayloadOffset,
    int PayloadLen,
    bool IsIPv6
);

public static class PacketInspector
{
    public static bool TryParseTcpDetails(ReadOnlySpan<byte> packet, out TcpPacketDetails details)
    {
        details = default;
        if (packet.IsEmpty) return false;

        int version = packet[0] >> 4;
        int ipHdrLen;
        bool isIPv6;
        FlowAddress srcIp;
        FlowAddress dstIp;

        if (version == 4)
        {
            if (packet.Length < 20 || packet[9] != 6) return false;
            ipHdrLen = (packet[0] & 0x0F) * 4;
            srcIp = FlowAddress.FromIPv4(packet.Slice(12, 4));
            dstIp = FlowAddress.FromIPv4(packet.Slice(16, 4));
            isIPv6 = false;
        }
        else if (version == 6)
        {
            if (packet.Length < 40 || packet[6] != 6) return false;
            ipHdrLen = 40;
            srcIp = FlowAddress.FromIPv6(packet.Slice(8, 16));
            dstIp = FlowAddress.FromIPv6(packet.Slice(24, 16));
            isIPv6 = true;
        }
        else return false;

        if (packet.Length < ipHdrLen + 20) return false;

        ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHdrLen, 2));
        ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHdrLen + 2, 2));
        int dataOffset = ((packet[ipHdrLen + 12] >> 4) & 0x0F) * 4;
        if (dataOffset < 20 || packet.Length < ipHdrLen + dataOffset) return false;

        byte flags = packet[ipHdrLen + 13];
        int payloadOffset = ipHdrLen + dataOffset;
        int payloadLen = packet.Length - payloadOffset;

        details = new TcpPacketDetails(
            new TcpFlowKey(srcIp, srcPort, dstIp, dstPort),
            flags,
            payloadOffset,
            payloadLen,
            isIPv6
        );
        return true;
    }

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
