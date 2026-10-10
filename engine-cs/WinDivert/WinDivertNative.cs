using System;
using System.Runtime.InteropServices;

namespace AdblockEngine.WinDivert;

[StructLayout(LayoutKind.Explicit, Size = 80)]
public struct WinDivertAddress
{
    [FieldOffset(0)]
    public long Timestamp;

    [FieldOffset(8)]
    public ulong Bitfields;

    [FieldOffset(16)]
    public uint IfIdx;

    [FieldOffset(20)]
    public uint SubIfIdx;

    public bool IsOutbound => (Bitfields & (1UL << 17)) != 0;

    public void SetOutbound(bool outbound)
    {
        if (outbound)
            Bitfields |= (1UL << 17);
        else
            Bitfields &= ~(1UL << 17);
    }

    public bool IsIPv6 => (Bitfields & (1UL << 20)) != 0;
}

public static class WinDivertNative
{
    public const uint WINDIVERT_LAYER_NETWORK = 0;
    public const short WINDIVERT_PRIORITY_NORMAL = 0;
    public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern IntPtr WinDivertOpen(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        uint layer,
        short priority,
        ulong flags);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecv(
        IntPtr handle,
        byte[] packet,
        uint packetLen,
        out uint recvLen,
        ref WinDivertAddress addr);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSend(
        IntPtr handle,
        byte[] packet,
        uint packetLen,
        out uint sendLen,
        ref WinDivertAddress addr);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertHelperCalcChecksums(
        byte[] packet,
        uint packetLen,
        ref WinDivertAddress addr,
        ulong flags);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(IntPtr handle);
}
