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

    public static byte[]? BuildDnsNxdomain(byte[] packet, bool isIPv6)
    {
        if (isIPv6)
        {
            if (packet.Length < 40 + 8 + 12) return null;
            int ipHdrLen = 40;
            int udpHdrLen = 8;
            int dnsOffset = ipHdrLen + udpHdrLen;

            var question = ParseDnsQuestion(packet.AsSpan(dnsOffset));
            if (question == null) return null;

            int newDnsPayloadLen = question.QuestionEndOffset;
            int newUdpLen = udpHdrLen + newDnsPayloadLen;
            int newTotalLen = ipHdrLen + newUdpLen;

            byte[] res = new byte[newTotalLen];
            Array.Copy(packet, 0, res, 0, newTotalLen);

            // Swap IPv6 Src and Dst
            byte[] srcIp = new byte[16];
            byte[] dstIp = new byte[16];
            Array.Copy(res, 8, srcIp, 0, 16);
            Array.Copy(res, 24, dstIp, 0, 16);
            Array.Copy(dstIp, 0, res, 8, 16);
            Array.Copy(srcIp, 0, res, 24, 16);

            // Update IPv6 Payload Length
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(4, 2), (ushort)newUdpLen);

            // Swap UDP ports
            ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(res.AsSpan(ipHdrLen, 2));
            ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(res.AsSpan(ipHdrLen + 2, 2));
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(ipHdrLen, 2), dstPort);
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(ipHdrLen + 2, 2), srcPort);
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(ipHdrLen + 4, 2), (ushort)newUdpLen);

            // DNS Flags = 0x8183
            res[dnsOffset + 2] = 0x81;
            res[dnsOffset + 3] = 0x83;
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(dnsOffset + 4, 2), 1);
            res.AsSpan(dnsOffset + 6, 6).Clear();

            return res;
        }
        else
        {
            if (packet.Length < 20 + 8 + 12) return null;
            int ihl = (packet[0] & 0x0F) * 4;
            int udpHdrLen = 8;
            int dnsOffset = ihl + udpHdrLen;
            if (packet.Length < dnsOffset + 12) return null;

            var question = ParseDnsQuestion(packet.AsSpan(dnsOffset));
            if (question == null) return null;

            int newDnsPayloadLen = question.QuestionEndOffset;
            int newUdpLen = udpHdrLen + newDnsPayloadLen;
            int newTotalLen = ihl + newUdpLen;

            byte[] res = new byte[newTotalLen];
            Array.Copy(packet, 0, res, 0, newTotalLen);

            // Swap IPv4 Src and Dst
            byte[] srcIp = new byte[4];
            byte[] dstIp = new byte[4];
            Array.Copy(res, 12, srcIp, 0, 4);
            Array.Copy(res, 16, dstIp, 0, 4);
            Array.Copy(dstIp, 0, res, 12, 4);
            Array.Copy(srcIp, 0, res, 16, 4);

            // Total Length
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(2, 2), (ushort)newTotalLen);

            // Swap UDP ports
            ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(res.AsSpan(ihl, 2));
            ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(res.AsSpan(ihl + 2, 2));
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(ihl, 2), dstPort);
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(ihl + 2, 2), srcPort);
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(ihl + 4, 2), (ushort)newUdpLen);

            // DNS Flags = 0x8183
            res[dnsOffset + 2] = 0x81;
            res[dnsOffset + 3] = 0x83;
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(dnsOffset + 4, 2), 1);
            res.AsSpan(dnsOffset + 6, 6).Clear();

            // Recalculate checksums
            Checksum.CalcIpv4Checksum(res.AsSpan(0, ihl));
            Checksum.CalcUdpIpv4Checksum(res, ihl);

            return res;
        }
    }
}
