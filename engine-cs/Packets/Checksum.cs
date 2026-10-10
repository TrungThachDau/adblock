using System;
using System.Buffers.Binary;

namespace AdblockEngine.Packets;

public static class Checksum
{
    public static ushort InternetChecksum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        int i = 0;
        while (i + 1 < data.Length)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2));
            i += 2;
        }

        if (i < data.Length)
        {
            sum += (uint)(data[i] << 8);
        }

        while ((sum >> 16) > 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }

    public static void CalcIpv4Checksum(Span<byte> ipHeader)
    {
        if (ipHeader.Length < 20) return;
        ipHeader[10] = 0;
        ipHeader[11] = 0;
        int ihl = (ipHeader[0] & 0x0F) * 4;
        ushort cs = InternetChecksum(ipHeader.Slice(0, ihl));
        BinaryPrimitives.WriteUInt16BigEndian(ipHeader.Slice(10, 2), cs);
    }

    public static void CalcUdpIpv4Checksum(Span<byte> packet, int ipHdrLen)
    {
        if (packet.Length < ipHdrLen + 8) return;
        ushort udpLen = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(ipHdrLen + 4, 2));
        if (packet.Length < ipHdrLen + udpLen) return;

        packet[ipHdrLen + 6] = 0;
        packet[ipHdrLen + 7] = 0;

        byte[] pseudo = new byte[12 + udpLen];
        packet.Slice(12, 4).CopyTo(pseudo.AsSpan(0, 4)); // Src IP
        packet.Slice(16, 4).CopyTo(pseudo.AsSpan(4, 4)); // Dst IP
        pseudo[8] = 0;
        pseudo[9] = packet[9]; // Protocol (17)
        BinaryPrimitives.WriteUInt16BigEndian(pseudo.AsSpan(10, 2), udpLen);
        packet.Slice(ipHdrLen, udpLen).CopyTo(pseudo.AsSpan(12, udpLen));

        ushort cs = InternetChecksum(pseudo);
        if (cs == 0) cs = 0xFFFF;
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(ipHdrLen + 6, 2), cs);
    }

    public static void CalcTcpIpv4Checksum(Span<byte> packet, int ipHdrLen)
    {
        if (packet.Length < ipHdrLen + 20) return;
        int tcpSegLen = packet.Length - ipHdrLen;

        packet[ipHdrLen + 16] = 0;
        packet[ipHdrLen + 17] = 0;

        byte[] pseudo = new byte[12 + tcpSegLen];
        packet.Slice(12, 4).CopyTo(pseudo.AsSpan(0, 4)); // Src IP
        packet.Slice(16, 4).CopyTo(pseudo.AsSpan(4, 4)); // Dst IP
        pseudo[8] = 0;
        pseudo[9] = packet[9]; // Protocol (6)
        BinaryPrimitives.WriteUInt16BigEndian(pseudo.AsSpan(10, 2), (ushort)tcpSegLen);
        packet.Slice(ipHdrLen, tcpSegLen).CopyTo(pseudo.AsSpan(12, tcpSegLen));

        ushort cs = InternetChecksum(pseudo);
        BinaryPrimitives.WriteUInt16BigEndian(packet.Slice(ipHdrLen + 16, 2), cs);
    }
}
