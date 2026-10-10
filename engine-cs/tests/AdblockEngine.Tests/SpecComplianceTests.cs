using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using AdblockEngine.Packets;
using AdblockEngine.Rules;
using Xunit;

namespace AdblockEngine.Tests;

public class SpecComplianceTests
{
    private static string FindSpecPath(string relativePath)
    {
        string? dir = AppContext.BaseDirectory;
        while (!string.IsNullOrEmpty(dir))
        {
            string candidate = Path.Combine(dir, "spec", relativePath);
            if (File.Exists(candidate)) return candidate;
            dir = Directory.GetParent(dir)?.FullName;
        }

        throw new FileNotFoundException($"Cannot find spec file at {relativePath}");
    }

    [Fact]
    public void TestSpecDomainMatchingVectors()
    {
        string testCasesPath = FindSpecPath("test-data/test_cases.json");
        string json = File.ReadAllText(testCasesPath);
        using var doc = JsonDocument.Parse(json);

        var rules = new List<string>();
        foreach (var r in doc.RootElement.GetProperty("rules").EnumerateArray())
        {
            rules.Add(r.GetString()!);
        }

        var store = new RuleStore();
        store.Add(rules);

        foreach (var c in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            string query = c.GetProperty("query").GetString()!;
            bool expectedBlocked = c.GetProperty("expected_blocked").GetBoolean();
            string desc = c.GetProperty("description").GetString()!;

            bool actualBlocked = store.Check(query) != null;
            Assert.True(actualBlocked == expectedBlocked,
                $"Failed case '{query}' ({desc}) - expected {expectedBlocked}, actual {actualBlocked}");
        }
    }

    [Fact]
    public void TestSpecPacketHexVectors()
    {
        string packetsPath = FindSpecPath("test-data/packets.json");
        string json = File.ReadAllText(packetsPath);
        using var doc = JsonDocument.Parse(json);

        // 1. DNS query ad
        var dnsAd = doc.RootElement.GetProperty("dns_query_ad");
        byte[] rawDns = Convert.FromHexString(dnsAd.GetProperty("hex").GetString()!);
        var dnsInfo = PacketInspector.Inspect(rawDns);
        Assert.NotNull(dnsInfo);
        Assert.Equal(PacketProtocol.Dns, dnsInfo.Protocol);
        Assert.Equal(dnsAd.GetProperty("expected_domain").GetString(), dnsInfo.Domain);

        byte[]? nxdomain = DnsPacket.BuildDnsNxdomain(rawDns, dnsInfo.IsIPv6);
        Assert.NotNull(nxdomain);
        Assert.True(nxdomain.Length > 0);

        // 2. TLS ClientHello ad
        var tlsAd = doc.RootElement.GetProperty("tls_clienthello_ad");
        byte[] rawTls = Convert.FromHexString(tlsAd.GetProperty("hex").GetString()!);
        var tlsInfo = PacketInspector.Inspect(rawTls);
        Assert.NotNull(tlsInfo);
        Assert.Equal(PacketProtocol.Tls, tlsInfo.Protocol);
        Assert.Equal(tlsAd.GetProperty("expected_domain").GetString(), tlsInfo.Domain);

        byte[]? rst = TlsPacket.BuildTcpRst(rawTls, tlsInfo.IsIPv6);
        Assert.NotNull(rst);
        Assert.Equal(40, rst.Length);

        // 3. QUIC packet
        var quic = doc.RootElement.GetProperty("quic_packet");
        byte[] rawQuic = Convert.FromHexString(quic.GetProperty("hex").GetString()!);
        var quicInfo = PacketInspector.Inspect(rawQuic);
        Assert.NotNull(quicInfo);
        Assert.Equal(PacketProtocol.Quic, quicInfo.Protocol);
        Assert.Equal(quic.GetProperty("expected_domain").GetString(), quicInfo.Domain);
    }
}
