using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace AdblockEngine.Packets;

public record DnsQuestionInfo(string QName, ushort QType, ushort QClass, int QuestionEndOffset);

public static class DnsPacket
{
    public static DnsQuestionInfo? ParseDnsQuestion(ReadOnlySpan<byte> dnsPayload)
    {
        if (dnsPayload.Length < 12) return null;

        ushort qdCount = BinaryPrimitives.ReadUInt16BigEndian(dnsPayload.Slice(4, 2));
        if (qdCount == 0) return null;

        int cursor = 12;
        var labels = new List<string>();

        while (cursor < dnsPayload.Length)
        {
            int len = dnsPayload[cursor];
            cursor++;

            if (len == 0)
                break;

            if ((len & 0xC0) == 0xC0)
            {
                cursor++;
                break;
            }

            if (cursor + len > dnsPayload.Length)
                return null;

            string label = Encoding.UTF8.GetString(dnsPayload.Slice(cursor, len));
            labels.Add(label.ToLowerInvariant());
            cursor += len;
        }

        if (cursor + 4 > dnsPayload.Length) return null;

        ushort qtype = BinaryPrimitives.ReadUInt16BigEndian(dnsPayload.Slice(cursor, 2));
        ushort qclass = BinaryPrimitives.ReadUInt16BigEndian(dnsPayload.Slice(cursor + 2, 2));
        cursor += 4;

        return new DnsQuestionInfo(string.Join(".", labels), qtype, qclass, cursor);
    }

    public static bool TryBuildDnsNxdomain(ReadOnlySpan<byte> packet, bool isIPv6, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        if (isIPv6)
        {
            if (packet.Length < 40 + 8 + 12) return false;
            int ipHdrLen = 40;
            int udpHdrLen = 8;
            int dnsOffset = ipHdrLen + udpHdrLen;

            var question = ParseDnsQuestion(packet.Slice(dnsOffset));
            if (question == null) return false;

            int newDnsPayloadLen = question.QuestionEndOffset;
            int newUdpLen = udpHdrLen + newDnsPayloadLen;
            int newTotalLen = ipHdrLen + newUdpLen;

            if (destination.Length < newTotalLen) return false;

            packet.Slice(0, newTotalLen).CopyTo(destination);

            // Swap IPv6 Src and Dst
            Span<byte> srcIp = stackalloc byte[16];
            destination.Slice(8, 16).CopyTo(srcIp);
            destination.Slice(24, 16).CopyTo(destination.Slice(8, 16));
            srcIp.CopyTo(destination.Slice(24, 16));

            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(4, 2), (ushort)newUdpLen);

            // Swap UDP ports
            ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHdrLen, 2));
            ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHdrLen + 2, 2));
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(ipHdrLen, 2), dstPort);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(ipHdrLen + 2, 2), srcPort);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(ipHdrLen + 4, 2), (ushort)newUdpLen);

            // DNS Flags: 0x8183 (QR=1, RD=1, RA=1, RCODE=3 Name Error NXDOMAIN)
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(dnsOffset + 2, 2), 0x8183);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(dnsOffset + 6, 2), 0); // ANCOUNT = 0
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(dnsOffset + 8, 2), 0); // NSCOUNT = 0
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(dnsOffset + 10, 2), 0); // ARCOUNT = 0

            bytesWritten = newTotalLen;
            return true;
        }
        else
        {
            if (packet.Length < 20 + 8 + 12) return false;
            int ipHdrLen = (packet[0] & 0x0F) * 4;
            int udpHdrLen = 8;
            int dnsOffset = ipHdrLen + udpHdrLen;
            if (packet.Length < dnsOffset + 12) return false;

            var question = ParseDnsQuestion(packet.Slice(dnsOffset));
            if (question == null) return false;

            int newDnsPayloadLen = question.QuestionEndOffset;
            int newUdpLen = udpHdrLen + newDnsPayloadLen;
            int newTotalLen = ipHdrLen + newUdpLen;

            if (destination.Length < newTotalLen) return false;

            packet.Slice(0, newTotalLen).CopyTo(destination);

            // Swap IPv4 Src and Dst
            Span<byte> srcIp = stackalloc byte[4];
            destination.Slice(12, 4).CopyTo(srcIp);
            destination.Slice(16, 4).CopyTo(destination.Slice(12, 4));
            srcIp.CopyTo(destination.Slice(16, 4));

            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2, 2), (ushort)newTotalLen);

            // Swap UDP ports
            ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHdrLen, 2));
            ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHdrLen + 2, 2));
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(ipHdrLen, 2), dstPort);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(ipHdrLen + 2, 2), srcPort);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(ipHdrLen + 4, 2), (ushort)newUdpLen);

            // DNS Flags: 0x8183
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(dnsOffset + 2, 2), 0x8183);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(dnsOffset + 6, 2), 0);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(dnsOffset + 8, 2), 0);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(dnsOffset + 10, 2), 0);

            // Recalculate IPv4 and UDP Checksums
            Checksum.CalcIpv4Checksum(destination.Slice(0, ipHdrLen));
            Checksum.CalcUdpIpv4Checksum(destination.Slice(0, newTotalLen), ipHdrLen);

            bytesWritten = newTotalLen;
            return true;
        }
    }

    public static byte[]? BuildDnsNxdomain(byte[] packet, bool isIPv6)
    {
        byte[] temp = new byte[packet.Length + 64];
        if (TryBuildDnsNxdomain(packet, isIPv6, temp, out int bytesWritten))
        {
            byte[] res = new byte[bytesWritten];
            temp.AsSpan(0, bytesWritten).CopyTo(res);
            return res;
        }
        return null;
    }
}
