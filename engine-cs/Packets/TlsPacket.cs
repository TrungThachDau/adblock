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

    public static bool TryBuildTcpRst(ReadOnlySpan<byte> packet, bool isIPv6, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        if (isIPv6)
        {
            if (packet.Length < 40 + 20) return false;
            int ipHdrLen = 40;
            int tcpHdrLen = ((packet[ipHdrLen + 12] >> 4) & 0x0F) * 4;
            if (packet.Length < ipHdrLen + tcpHdrLen) return false;
            int payloadLen = packet.Length - (ipHdrLen + tcpHdrLen);

            uint origSeq = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(ipHdrLen + 4, 4));
            uint origAck = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(ipHdrLen + 8, 4));

            int totalLen = 40 + 20;
            if (destination.Length < totalLen) return false;

            packet.Slice(0, 40).CopyTo(destination);

            // Swap IPv6 Src and Dst
            Span<byte> srcIp = stackalloc byte[16];
            destination.Slice(8, 16).CopyTo(srcIp);
            destination.Slice(24, 16).CopyTo(destination.Slice(8, 16));
            srcIp.CopyTo(destination.Slice(24, 16));
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(4, 2), 20);

            // Swap TCP ports
            ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHdrLen, 2));
            ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHdrLen + 2, 2));
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(ipHdrLen, 2), dstPort);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(ipHdrLen + 2, 2), srcPort);

            uint newSeq = origAck;
            uint newAck = origSeq + (uint)payloadLen;
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(ipHdrLen + 4, 4), newSeq);
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(ipHdrLen + 8, 4), newAck);

            destination[ipHdrLen + 12] = 0x50; // Data offset 5
            destination[ipHdrLen + 13] = 0x14; // RST | ACK
            destination.Slice(ipHdrLen + 14, 2).Clear(); // Window 0
            destination.Slice(ipHdrLen + 16, 4).Clear(); // Checksum & Urgent pointer 0

            bytesWritten = totalLen;
            return true;
        }
        else
        {
            if (packet.Length < 20 + 20) return false;
            int ipHdrLen = (packet[0] & 0x0F) * 4;
            if (packet.Length < ipHdrLen + 20) return false;

            int tcpHdrLen = ((packet[ipHdrLen + 12] >> 4) & 0x0F) * 4;
            if (packet.Length < ipHdrLen + tcpHdrLen) return false;
            int payloadLen = packet.Length - (ipHdrLen + tcpHdrLen);

            uint origSeq = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(ipHdrLen + 4, 4));
            uint origAck = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(ipHdrLen + 8, 4));

            int totalLen = ipHdrLen + 20;
            if (destination.Length < totalLen) return false;

            packet.Slice(0, ipHdrLen).CopyTo(destination);

            // Swap IPv4 Src and Dst
            Span<byte> srcIp = stackalloc byte[4];
            destination.Slice(12, 4).CopyTo(srcIp);
            destination.Slice(16, 4).CopyTo(destination.Slice(12, 4));
            srcIp.CopyTo(destination.Slice(16, 4));

            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2, 2), (ushort)totalLen);

            // Swap TCP ports
            ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHdrLen, 2));
            ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHdrLen + 2, 2));
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(ipHdrLen, 2), dstPort);
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(ipHdrLen + 2, 2), srcPort);

            uint newSeq = origAck;
            uint newAck = origSeq + (uint)payloadLen;
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(ipHdrLen + 4, 4), newSeq);
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(ipHdrLen + 8, 4), newAck);

            destination[ipHdrLen + 12] = 0x50; // Data offset 5
            destination[ipHdrLen + 13] = 0x14; // RST | ACK
            destination.Slice(ipHdrLen + 14, 2).Clear(); // Window 0
            destination.Slice(ipHdrLen + 18, 2).Clear(); // Urgent pointer 0

            // Recalculate checksums
            Checksum.CalcIpv4Checksum(destination.Slice(0, ipHdrLen));
            Checksum.CalcTcpIpv4Checksum(destination.Slice(0, totalLen), ipHdrLen);

            bytesWritten = totalLen;
            return true;
        }
    }

    public static byte[]? BuildTcpRst(byte[] packet, bool isIPv6)
    {
        byte[] temp = new byte[64];
        if (TryBuildTcpRst(packet, isIPv6, temp, out int bytesWritten))
        {
            byte[] res = new byte[bytesWritten];
            temp.AsSpan(0, bytesWritten).CopyTo(res);
            return res;
        }
        return null;
    }
}
