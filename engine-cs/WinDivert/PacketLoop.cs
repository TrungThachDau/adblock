using System;
using System.Threading;
using AdblockEngine.Ipc;
using AdblockEngine.Packets;
using AdblockEngine.Rules;

namespace AdblockEngine.WinDivert;

public class PacketLoop
{
    public const string FilterString =
        "outbound and !loopback and (udp.DstPort == 53 or (tcp.DstPort == 443 and tcp.PayloadLength > 0) or udp.DstPort == 443)";

    private readonly RuleStore _rules;
    private readonly NamedPipeServer _ipc;

    public PacketLoop(RuleStore rules, NamedPipeServer ipc)
    {
        _rules = rules;
        _ipc = ipc;
    }

    public void Run(CancellationToken cancellationToken)
    {
        IntPtr handle;
        try
        {
            handle = WinDivertNative.WinDivertOpen(
                FilterString,
                WinDivertNative.WINDIVERT_LAYER_NETWORK,
                WinDivertNative.WINDIVERT_PRIORITY_NORMAL,
                0);

            if (handle == WinDivertNative.INVALID_HANDLE_VALUE || handle == IntPtr.Zero)
            {
                Console.WriteLine("[WinDivert] Failed to open WinDivert handle. Run as Administrator with WinDivert.dll available.");
                return;
            }
        }
        catch (DllNotFoundException)
        {
            Console.WriteLine("[WinDivert] WinDivert.dll not found. Running engine in stub/mock mode without packet capture driver.");
            return;
        }

        Console.WriteLine($"[WinDivert] Packet filtering active with filter: {FilterString}");

        byte[] packetBuffer = new byte[65535];
        var addr = new WinDivertAddress();

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                if (!WinDivertNative.WinDivertRecv(handle, packetBuffer, (uint)packetBuffer.Length, out uint recvLen, ref addr))
                {
                    continue;
                }

                if (_ipc.IsPaused)
                {
                    WinDivertNative.WinDivertSend(handle, packetBuffer, recvLen, out _, ref addr);
                    continue;
                }

                var packetSpan = packetBuffer.AsSpan(0, (int)recvLen);
                var info = PacketInspector.Inspect(packetSpan);
                if (info == null)
                {
                    WinDivertNative.WinDivertSend(handle, packetBuffer, recvLen, out _, ref addr);
                    continue;
                }

                long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                switch (info.Protocol)
                {
                    case PacketProtocol.Dns:
                        string domain = info.Domain ?? "";
                        string? matchedRule = _rules.Check(domain);
                        if (matchedRule != null)
                        {
                            // Blocked -> Synthesize NXDOMAIN
                            _ipc.IncrementDns(blocked: true);
                            byte[] rawCopy = packetSpan.ToArray();
                            byte[]? nxdomain = DnsPacket.BuildDnsNxdomain(rawCopy, info.IsIPv6);
                            if (nxdomain != null)
                            {
                                var respAddr = addr;
                                respAddr.SetOutbound(false); // Inbound direction
                                WinDivertNative.WinDivertHelperCalcChecksums(nxdomain, (uint)nxdomain.Length, ref respAddr, 0);
                                WinDivertNative.WinDivertSend(handle, nxdomain, (uint)nxdomain.Length, out _, ref respAddr);
                            }
                            // Original query dropped

                            _ipc.BroadcastLog(new QueryLogData(
                                _ipc.NextLogId(),
                                timestamp,
                                "DNS",
                                info.ClientIp,
                                domain,
                                "blocked",
                                $"Rule match: {matchedRule}"
                            ));
                        }
                        else
                        {
                            // Allowed
                            _ipc.IncrementDns(blocked: false);
                            WinDivertNative.WinDivertSend(handle, packetBuffer, recvLen, out _, ref addr);
                            _ipc.BroadcastLog(new QueryLogData(
                                _ipc.NextLogId(),
                                timestamp,
                                "DNS",
                                info.ClientIp,
                                domain,
                                "allowed",
                                "Allowed"
                            ));
                        }
                        break;

                    case PacketProtocol.Tls:
                        if (info.Domain is { } sni)
                        {
                            string? tlsRule = _rules.Check(sni);
                            if (tlsRule != null)
                            {
                                // Blocked -> Synthesize TCP RST to client
                                _ipc.IncrementTls(blocked: true);
                                byte[] rawCopy = packetSpan.ToArray();
                                byte[]? rst = TlsPacket.BuildTcpRst(rawCopy, info.IsIPv6);
                                if (rst != null)
                                {
                                    var respAddr = addr;
                                    respAddr.SetOutbound(false); // Inbound direction
                                    WinDivertNative.WinDivertHelperCalcChecksums(rst, (uint)rst.Length, ref respAddr, 0);
                                    WinDivertNative.WinDivertSend(handle, rst, (uint)rst.Length, out _, ref respAddr);
                                }
                                // Original ClientHello dropped

                                _ipc.BroadcastLog(new QueryLogData(
                                    _ipc.NextLogId(),
                                    timestamp,
                                    "TLS",
                                    info.ClientIp,
                                    sni,
                                    "blocked",
                                    $"Rule match: {tlsRule}"
                                ));
                            }
                            else
                            {
                                // Allowed
                                _ipc.IncrementTls(blocked: false);
                                WinDivertNative.WinDivertSend(handle, packetBuffer, recvLen, out _, ref addr);
                                _ipc.BroadcastLog(new QueryLogData(
                                    _ipc.NextLogId(),
                                    timestamp,
                                    "TLS",
                                    info.ClientIp,
                                    sni,
                                    "allowed",
                                    "Allowed"
                                ));
                            }
                        }
                        else
                        {
                            // Not a ClientHello
                            WinDivertNative.WinDivertSend(handle, packetBuffer, recvLen, out _, ref addr);
                        }
                        break;

                    case PacketProtocol.Quic:
                        // Drop UDP 443 to force fallback to TCP 443
                        _ipc.IncrementQuic();
                        _ipc.BroadcastLog(new QueryLogData(
                            _ipc.NextLogId(),
                            timestamp,
                            "QUIC",
                            info.ClientIp,
                            "[quic-port-443]",
                            "dropped",
                            "QUIC dropped to force TCP fallback"
                        ));
                        // Original packet dropped
                        break;

                    default:
                        WinDivertNative.WinDivertSend(handle, packetBuffer, recvLen, out _, ref addr);
                        break;
                }
            }
        }
        finally
        {
            WinDivertNative.WinDivertClose(handle);
            Console.WriteLine("[WinDivert] Packet filtering loop terminated.");
        }
    }
}
