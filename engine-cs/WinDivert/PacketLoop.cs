using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;
using AdblockEngine.Ipc;
using AdblockEngine.Packets;
using AdblockEngine.Rules;

namespace AdblockEngine.WinDivert;

internal sealed class FlowTracker
{
    private readonly Dictionary<TcpFlowKey, long> _allowedFlows = new(1024);
    private long _lastCleanupTicks = Environment.TickCount64;

    public bool IsAllowed(in TcpFlowKey key)
    {
        return _allowedFlows.ContainsKey(key);
    }

    public void MarkAllowed(in TcpFlowKey key)
    {
        _allowedFlows[key] = Environment.TickCount64;
        MaybePrune();
    }

    public void Remove(in TcpFlowKey key)
    {
        _allowedFlows.Remove(key);
    }

    private void MaybePrune()
    {
        long now = Environment.TickCount64;
        if (now - _lastCleanupTicks > 30_000 || _allowedFlows.Count > 10_000)
        {
            var toRemove = new List<TcpFlowKey>();
            foreach (var kvp in _allowedFlows)
            {
                if (now - kvp.Value > 120_000)
                {
                    toRemove.Add(kvp.Key);
                }
            }
            foreach (var k in toRemove)
            {
                _allowedFlows.Remove(k);
            }
            _lastCleanupTicks = now;
        }
    }
}

public class PacketLoop
{
    public const string FilterString = "outbound and (udp.DstPort == 53 or tcp.DstPort == 443)";

    private readonly RuleStore _rules;
    private readonly NamedPipeServer _ipc;

    public PacketLoop(RuleStore rules, NamedPipeServer ipc)
    {
        _rules = rules;
        _ipc = ipc;
    }

    public void Run(CancellationToken cancellationToken)
    {
        Console.WriteLine($"[WinDivert] Opening WinDivert capture on narrow filter: {FilterString}");

        IntPtr handle = IntPtr.Zero;
        try
        {
            handle = WinDivertNative.WinDivertOpen(
                FilterString,
                WinDivertNative.WINDIVERT_LAYER_NETWORK,
                WinDivertNative.WINDIVERT_PRIORITY_NORMAL,
                0);

            if (handle == WinDivertNative.INVALID_HANDLE_VALUE || handle == IntPtr.Zero)
            {
                Console.WriteLine("[WinDivert] Driver failed to open (admin privileges required). Running in fail-open mode without packet interception.");
                handle = IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("[WinDivert] WinDivert capture started successfully. Monitoring DNS and TLS 443 traffic.");
            }
        }
        catch (DllNotFoundException)
        {
            Console.WriteLine("[WinDivert] WinDivert.dll not found. Running engine in fail-open mode.");
            handle = IntPtr.Zero;
        }

        if (handle == IntPtr.Zero)
        {
            // Fail-open loop: stay alive, respond to IPC, wait for stop signal
            while (!cancellationToken.IsCancellationRequested)
            {
                Thread.Sleep(500);
            }
            Console.WriteLine("[WinDivert] WinDivert fail-open worker exiting.");
            return;
        }

        byte[] packetBuffer = ArrayPool<byte>.Shared.Rent(65535);
        byte[] responseBuffer = ArrayPool<byte>.Shared.Rent(65535);
        var addr = new WinDivertAddress();
        var flowTracker = new FlowTracker();

        try
        {
            unsafe
            {
                fixed (byte* pPacket = packetBuffer)
                fixed (byte* pResp = responseBuffer)
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        if (!WinDivertNative.WinDivertRecv(handle, pPacket, (uint)packetBuffer.Length, out uint recvLen, ref addr))
                        {
                            continue;
                        }

                        // Fail-open: If the engine is paused, forward packet immediately
                        if (_ipc.IsPaused)
                        {
                            WinDivertNative.WinDivertSend(handle, pPacket, recvLen, out _, ref addr);
                            continue;
                        }

                        if (recvLen < 20)
                        {
                            // Malformed packet: fail-open forward
                            WinDivertNative.WinDivertSend(handle, pPacket, recvLen, out _, ref addr);
                            continue;
                        }

                        var rawSpan = new ReadOnlySpan<byte>(pPacket, (int)recvLen);
                        byte version = (byte)(rawSpan[0] >> 4);
                        bool isIPv6 = version == 6;
                        int ipHdrLen = isIPv6 ? 40 : ((rawSpan[0] & 0x0F) * 4);
                        byte protocol = isIPv6 ? rawSpan[6] : rawSpan[9];

                        long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                        if (protocol == 17) // UDP
                        {
                            // ==========================================
                            // 1. DNS (UDP Port 53) Outbound Interception
                            // ==========================================
                            if (rawSpan.Length >= ipHdrLen + 8)
                            {
                                ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(rawSpan.Slice(ipHdrLen + 2, 2));
                                if (dstPort == 53)
                                {
                                    var dnsPayload = rawSpan.Slice(ipHdrLen + 8);
                                    string clientIp = isIPv6
                                        ? "ipv6-client"
                                        : $"{rawSpan[12]}.{rawSpan[13]}.{rawSpan[14]}.{rawSpan[15]}";

                                    var question = DnsPacket.ParseDnsQuestion(dnsPayload);
                                    string? qname = question?.QName;
                                    bool isBlocked = false;

                                    if (qname != null)
                                    {
                                        string? matchedRule = _rules.Check(qname);
                                        if (matchedRule != null)
                                        {
                                            isBlocked = true;
                                            _ipc.IncrementDns(blocked: true);

                                            // Synthesize inbound NXDOMAIN response
                                            if (DnsPacket.TryBuildDnsNxdomain(rawSpan, isIPv6, responseBuffer.AsSpan(0, responseBuffer.Length), out int respLen))
                                            {
                                                var respAddr = addr;
                                                respAddr.SetOutbound(false); // Inbound to client
                                                WinDivertNative.WinDivertHelperCalcChecksums(pResp, (uint)respLen, ref respAddr, 0);
                                                WinDivertNative.WinDivertSend(handle, pResp, (uint)respLen, out _, ref respAddr);
                                            }

                                            // Original query dropped
                                            _ipc.BroadcastLog(new QueryLogData(
                                                _ipc.NextLogId(),
                                                timestamp,
                                                "DNS",
                                                clientIp,
                                                qname,
                                                "blocked",
                                                $"Rule match: {matchedRule}"
                                            ));
                                        }
                                    }

                                    if (!isBlocked)
                                    {
                                        _ipc.IncrementDns(blocked: false);
                                        WinDivertNative.WinDivertSend(handle, pPacket, recvLen, out _, ref addr);

                                        if (qname != null)
                                        {
                                            _ipc.BroadcastLog(new QueryLogData(
                                                _ipc.NextLogId(),
                                                timestamp,
                                                "DNS",
                                                clientIp,
                                                qname,
                                                "allowed",
                                                "Allowed"
                                            ));
                                        }
                                    }
                                    continue;
                                }
                            }

                            // Fallback for unexpected UDP: fail-open forward
                            WinDivertNative.WinDivertSend(handle, pPacket, recvLen, out _, ref addr);
                        }
                        else if (protocol == 6) // TCP
                        {
                            // ==========================================
                            // 2. HTTPS (TCP Port 443) Outbound Interception
                            // Only inspect the first data packet of a 443 flow!
                            // ==========================================
                            if (!PacketInspector.TryParseTcpDetails(rawSpan, out var details) || details.FlowKey.DstPort != 443)
                            {
                                // Non-443 or unparseable TCP: fail-open forward
                                WinDivertNative.WinDivertSend(handle, pPacket, recvLen, out _, ref addr);
                                continue;
                            }

                            var flowKey = details.FlowKey;
                            bool fin = (details.Flags & 0x01) != 0;
                            bool rst = (details.Flags & 0x04) != 0;

                            // If connection is tearing down (FIN or RST), clean up flow tracker
                            if (fin || rst)
                            {
                                flowTracker.Remove(flowKey);
                                WinDivertNative.WinDivertSend(handle, pPacket, recvLen, out _, ref addr);
                                continue;
                            }

                            // If packet has no payload (SYN, pure ACK, window probe): bypass immediately
                            if (details.PayloadLen == 0)
                            {
                                WinDivertNative.WinDivertSend(handle, pPacket, recvLen, out _, ref addr);
                                continue;
                            }

                            // If flow has already been inspected on its first data packet and permitted: bypass
                            if (flowTracker.IsAllowed(flowKey))
                            {
                                WinDivertNative.WinDivertSend(handle, pPacket, recvLen, out _, ref addr);
                                continue;
                            }

                            // --- THIS IS THE FIRST DATA PACKET OF A 443 FLOW ---
                            var payload = rawSpan.Slice(details.PayloadOffset, details.PayloadLen);
                            string? sni = TlsPacket.ParseTlsSni(payload);
                            string clientIp = flowKey.SrcIp.ToString();

                            bool isBlocked = false;
                            if (sni != null)
                            {
                                string? matchedRule = _rules.Check(sni);
                                if (matchedRule != null)
                                {
                                    isBlocked = true;
                                    _ipc.IncrementTls(blocked: true);

                                    // Synthesize inbound TCP RST | ACK to client socket
                                    if (TlsPacket.TryBuildTcpRst(rawSpan, details.IsIPv6, responseBuffer.AsSpan(0, responseBuffer.Length), out int respLen))
                                    {
                                        var respAddr = addr;
                                        respAddr.SetOutbound(false); // Inbound
                                        WinDivertNative.WinDivertHelperCalcChecksums(pResp, (uint)respLen, ref respAddr, 0);
                                        WinDivertNative.WinDivertSend(handle, pResp, (uint)respLen, out _, ref respAddr);
                                    }

                                    // Original ClientHello dropped
                                    _ipc.BroadcastLog(new QueryLogData(
                                        _ipc.NextLogId(),
                                        timestamp,
                                        "TLS",
                                        clientIp,
                                        sni,
                                        "blocked",
                                        $"Rule match: {matchedRule}"
                                    ));
                                }
                            }

                            if (!isBlocked)
                            {
                                // First data packet is allowed (clean domain or non-SNI TLS payload)
                                // Mark flow as allowed so subsequent packets in this stream bypass inspection!
                                _ipc.IncrementTls(blocked: false);
                                flowTracker.MarkAllowed(flowKey);
                                WinDivertNative.WinDivertSend(handle, pPacket, recvLen, out _, ref addr);

                                if (sni != null)
                                {
                                    _ipc.BroadcastLog(new QueryLogData(
                                        _ipc.NextLogId(),
                                        timestamp,
                                        "TLS",
                                        clientIp,
                                        sni,
                                        "allowed",
                                        "Allowed"
                                    ));
                                }
                            }
                        }
                        else
                        {
                            // Any other packet: fail-open forward
                            WinDivertNative.WinDivertSend(handle, pPacket, recvLen, out _, ref addr);
                        }
                    }
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(packetBuffer);
            ArrayPool<byte>.Shared.Return(responseBuffer);
            if (handle != IntPtr.Zero)
            {
                WinDivertNative.WinDivertClose(handle);
            }
            Console.WriteLine("[WinDivert] Packet filtering loop terminated.");
        }
    }
}
