using System;
using System.Buffers.Binary;
using System.Text;

namespace AdblockEngine.Packets;

public static class TlsPacket
{
    public static string? ParseTlsSni(ReadOnlySpan<byte> tcpPayload)
    {
        if (tcpPayload.Length < 44) return null;
        if (tcpPayload[0] != 0x16) return null; // ContentType Handshake

        ushort _recordLen = BinaryPrimitives.ReadUInt16BigEndian(tcpPayload.Slice(3, 2));

        if (tcpPayload[5] != 0x01) return null; // HandshakeType ClientHello

        int cursor = 5 + 4 + 2 + 32;
        if (cursor >= tcpPayload.Length) return null;

        int sessionIdLen = tcpPayload[cursor];
        cursor += 1 + sessionIdLen;

        if (cursor + 2 > tcpPayload.Length) return null;
        ushort cipherSuitesLen = BinaryPrimitives.ReadUInt16BigEndian(tcpPayload.Slice(cursor, 2));
        cursor += 2 + cipherSuitesLen;

        if (cursor + 1 > tcpPayload.Length) return null;
        int compressionLen = tcpPayload[cursor];
        cursor += 1 + compressionLen;

        if (cursor + 2 > tcpPayload.Length) return null;
        ushort extensionsLen = BinaryPrimitives.ReadUInt16BigEndian(tcpPayload.Slice(cursor, 2));
        cursor += 2;

        int extensionsEnd = Math.Min(cursor + extensionsLen, tcpPayload.Length);

        while (cursor + 4 <= extensionsEnd)
        {
            ushort extType = BinaryPrimitives.ReadUInt16BigEndian(tcpPayload.Slice(cursor, 2));
            ushort extLen = BinaryPrimitives.ReadUInt16BigEndian(tcpPayload.Slice(cursor + 2, 2));
            cursor += 4;

            if (extType == 0x0000)
            {
                // SNI Extension
                if (cursor + extLen > extensionsEnd || extLen < 2) return null;
                ushort listLen = BinaryPrimitives.ReadUInt16BigEndian(tcpPayload.Slice(cursor, 2));
                int listCursor = cursor + 2;
                int listEnd = listCursor + listLen;

                while (listCursor + 3 <= listEnd)
                {
                    byte nameType = tcpPayload[listCursor];
                    ushort nameLen = BinaryPrimitives.ReadUInt16BigEndian(tcpPayload.Slice(listCursor + 1, 2));
                    listCursor += 3;

                    if (nameType == 0x00 && listCursor + nameLen <= listEnd)
                    {
                        var nameBytes = tcpPayload.Slice(listCursor, nameLen);
                        return Encoding.UTF8.GetString(nameBytes).ToLowerInvariant();
                    }
                    listCursor += nameLen;
                }
            }
            cursor += extLen;
        }

        return null;
    }

    public static byte[]? BuildTcpRst(byte[] packet, bool isIPv6)
    {
        if (isIPv6)
        {
            if (packet.Length < 40 + 20) return null;
            int ipHdrLen = 40;
            int tcpHdrLen = ((packet[ipHdrLen + 12] >> 4) & 0x0F) * 4;
            if (packet.Length < ipHdrLen + tcpHdrLen) return null;
            int payloadLen = packet.Length - (ipHdrLen + tcpHdrLen);

            uint origSeq = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(ipHdrLen + 4, 4));
            uint origAck = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(ipHdrLen + 8, 4));

            int totalLen = 40 + 20;
            byte[] res = new byte[totalLen];
            Array.Copy(packet, 0, res, 0, 40);

            // Swap IPv6 Src and Dst
            byte[] srcIp = new byte[16];
            byte[] dstIp = new byte[16];
            Array.Copy(res, 8, srcIp, 0, 16);
            Array.Copy(res, 24, dstIp, 0, 16);
            Array.Copy(dstIp, 0, res, 8, 16);
            Array.Copy(srcIp, 0, res, 24, 16);
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(4, 2), 20);

            // Swap TCP ports
            ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(ipHdrLen, 2));
            ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(ipHdrLen + 2, 2));
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(ipHdrLen, 2), dstPort);
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(ipHdrLen + 2, 2), srcPort);

            uint newSeq = origAck;
            uint newAck = origSeq + (uint)payloadLen;
            BinaryPrimitives.WriteUInt32BigEndian(res.AsSpan(ipHdrLen + 4, 4), newSeq);
            BinaryPrimitives.WriteUInt32BigEndian(res.AsSpan(ipHdrLen + 8, 4), newAck);

            res[ipHdrLen + 12] = 0x50; // Data offset 5
            res[ipHdrLen + 13] = 0x14; // RST | ACK
            res.AsSpan(ipHdrLen + 14, 2).Clear(); // Window 0

            return res;
        }
        else
        {
            if (packet.Length < 20 + 20) return null;
            int ipHdrLen = (packet[0] & 0x0F) * 4;
            if (packet.Length < ipHdrLen + 20) return null;

            int tcpHdrLen = ((packet[ipHdrLen + 12] >> 4) & 0x0F) * 4;
            if (packet.Length < ipHdrLen + tcpHdrLen) return null;
            int payloadLen = packet.Length - (ipHdrLen + tcpHdrLen);

            uint origSeq = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(ipHdrLen + 4, 4));
            uint origAck = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(ipHdrLen + 8, 4));

            int totalLen = ipHdrLen + 20;
            byte[] res = new byte[totalLen];
            Array.Copy(packet, 0, res, 0, ipHdrLen);

            // Swap IPv4 Src and Dst
            byte[] srcIp = new byte[4];
            byte[] dstIp = new byte[4];
            Array.Copy(res, 12, srcIp, 0, 4);
            Array.Copy(res, 16, dstIp, 0, 4);
            Array.Copy(dstIp, 0, res, 12, 4);
            Array.Copy(srcIp, 0, res, 16, 4);

            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(2, 2), (ushort)totalLen);

            // Swap TCP ports
            ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(ipHdrLen, 2));
            ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(ipHdrLen + 2, 2));
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(ipHdrLen, 2), dstPort);
            BinaryPrimitives.WriteUInt16BigEndian(res.AsSpan(ipHdrLen + 2, 2), srcPort);

            uint newSeq = origAck;
            uint newAck = origSeq + (uint)payloadLen;
            BinaryPrimitives.WriteUInt32BigEndian(res.AsSpan(ipHdrLen + 4, 4), newSeq);
            BinaryPrimitives.WriteUInt32BigEndian(res.AsSpan(ipHdrLen + 8, 4), newAck);

            res[ipHdrLen + 12] = 0x50; // Data offset 5
            res[ipHdrLen + 13] = 0x14; // RST | ACK
            res.AsSpan(ipHdrLen + 14, 2).Clear(); // Window 0
            res.AsSpan(ipHdrLen + 18, 2).Clear(); // Urgent pointer 0

            // Recalculate checksums
            Checksum.CalcIpv4Checksum(res.AsSpan(0, ipHdrLen));
            Checksum.CalcTcpIpv4Checksum(res, ipHdrLen);

            return res;
        }
    }
}
