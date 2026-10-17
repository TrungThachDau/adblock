using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AdblockApp.Services;

public record EngineStatsModel(
    long AllowedCount,
    long BlockedCount,
    long DnsQueries,
    long DnsBlocked,
    long TlsQueries,
    long TlsBlocked,
    long QuicDropped,
    long UptimeSeconds,
    long RamBytes,
    double RamMb
);

public record QueryLogModel(
    string Id,
    long Timestamp,
    string Protocol,
    string ClientIp,
    string Domain,
    string Action,
    string Reason
);

public record BlockedQueryModel(
    string Id,
    long Timestamp,
    string Protocol,
    string ClientIp,
    string Domain,
    string MatchedRule,
    string SourceList
);

public record EngineStatusModel(
    string Name,
    string Version,
    string State,
    long UptimeSeconds,
    int ActiveRulesCount,
    int AllowlistCount,
    int ListsCount,
    EngineStatsModel? Stats
);

public record SetListsResult(
    string Status,
    int LoadedLists,
    int ActiveRulesCount,
    List<string> FailedPaths
);

public record SetAllowlistResult(
    string Status,
    int AllowlistCount
);

public record RulesListResult(
    int Total,
    int Offset,
    int Limit,
    List<string> Rules
);

public record PrivateDnsConfigModel(
    bool Enabled,
    string Url
);

public record TestPrivateDnsResult(
    string Status,
    long LatencyMs,
    string Host
);

public class EngineClient : IDisposable
{
    public static readonly string[] CandidatePipes = ["adblock.engine", "adblock-engine"];

    private NamedPipeClientStream? _pipe;
    private StreamWriter? _writer;
    private CancellationTokenSource? _cts;
    private Task? _readTask;

    private readonly ConcurrentDictionary<string, TaskCompletionSource<JsonElement>> _pendingRequests = new();
    private long _requestIdSeq = 1;
    private volatile bool _isConnected;
    private string _activePipeName = "";
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public bool IsConnected => _isConnected;
    public string ActivePipeName => _activePipeName;

    public event Action<bool>? ConnectionStateChanged;
    public event Action<QueryLogModel>? QueryLogReceived;
    public event Action<BlockedQueryModel>? BlockedQueryReceived;
    public event Action<EngineStatsModel>? StatsUpdateReceived;

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _ = ConnectLoopAsync(_cts.Token);
    }

    private async Task ConnectLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            foreach (var pipeName in CandidatePipes)
            {
                if (cancellationToken.IsCancellationRequested) break;

                NamedPipeClientStream? pipe = null;
                bool wasConnected = false;
                try
                {
                    pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                    await pipe.ConnectAsync(1500, cancellationToken);

                    _pipe = pipe;
                    _activePipeName = pipeName;
                    _writer = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true };
                    _isConnected = true;
                    wasConnected = true;
                    RaiseSafe(() => ConnectionStateChanged?.Invoke(true));

                    _readTask = ReadLoopAsync(pipe, cancellationToken);
                    await _readTask;
                }
                catch (OperationCanceledException) { }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[PipeClient] {pipeName}: {ex.Message}");
                }
                finally
                {
                    _isConnected = false;
                    Cleanup();
                    pipe?.Dispose();
                    foreach (var key in _pendingRequests.Keys)
                    {
                        if (_pendingRequests.TryRemove(key, out var tcs))
                            tcs.TrySetException(new IOException("Engine connection lost."));
                    }
                    if (wasConnected) RaiseSafe(() => ConnectionStateChanged?.Invoke(false));
                }

                if (wasConnected) break;
            }

            try
            {
                await Task.Delay(2000, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task ReadLoopAsync(NamedPipeClientStream pipe, CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
        while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
        {
            string? line = await reader.ReadLineAsync(cancellationToken);
            if (line == null) break;

            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;

                // 1. Asynchronous push events from engine
                if (root.TryGetProperty("event", out var eventProp))
                {
                    string eventType = eventProp.GetString() ?? "";
                    if (eventType == "blocked_query" && root.TryGetProperty("data", out var bData))
                    {
                        var blocked = new BlockedQueryModel(
                            bData.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "",
                            bData.TryGetProperty("timestamp", out var ts) ? ts.GetInt64() : 0,
                            bData.TryGetProperty("protocol", out var proto) ? proto.GetString() ?? "" : "",
                            bData.TryGetProperty("client_ip", out var ip) ? ip.GetString() ?? "" : "",
                            bData.TryGetProperty("domain", out var dom) ? dom.GetString() ?? "" : "",
                            bData.TryGetProperty("matched_rule", out var mr) ? mr.GetString() ?? "" : "",
                            bData.TryGetProperty("source_list", out var sl) ? sl.GetString() ?? "" : ""
                        );
                        BlockedQueryReceived?.Invoke(blocked);

                        // Also emit query log for unified logs
                        var log = new QueryLogModel(
                            blocked.Id,
                            blocked.Timestamp,
                            blocked.Protocol,
                            blocked.ClientIp,
                            blocked.Domain,
                            "BLOCKED",
                            blocked.MatchedRule
                        );
                        QueryLogReceived?.Invoke(log);
                    }
                    else if (eventType == "query_log" && root.TryGetProperty("data", out var logData))
                    {
                        var log = new QueryLogModel(
                            logData.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "",
                            logData.TryGetProperty("timestamp", out var ts) ? ts.GetInt64() : 0,
                            logData.TryGetProperty("protocol", out var proto) ? proto.GetString() ?? "" : "",
                            logData.TryGetProperty("client_ip", out var ip) ? ip.GetString() ?? "" : "",
                            logData.TryGetProperty("domain", out var dom) ? dom.GetString() ?? "" : "",
                            logData.TryGetProperty("action", out var act) ? act.GetString() ?? "" : "",
                            logData.TryGetProperty("reason", out var reas) ? reas.GetString() ?? "" : ""
                        );
                        QueryLogReceived?.Invoke(log);

                        // Both engines push blocks as query_log with action "blocked".
                        if (log.Action.Equals("blocked", StringComparison.OrdinalIgnoreCase) ||
                            log.Action.Equals("dropped", StringComparison.OrdinalIgnoreCase))
                        {
                            BlockedQueryReceived?.Invoke(new BlockedQueryModel(
                                log.Id, log.Timestamp, log.Protocol, log.ClientIp, log.Domain, log.Reason, ""));
                        }
                    }
                    else if (eventType == "stats_update" && root.TryGetProperty("data", out var statsData))
                    {
                        var stats = ParseStats(statsData);
                        StatsUpdateReceived?.Invoke(stats);
                    }
                    continue;
                }

                // 2. RPC command response
                if (root.TryGetProperty("id", out var idProp))
                {
                    string idStr = idProp.ToString();
                    if (_pendingRequests.TryRemove(idStr, out var tcs))
                    {
                        if (root.TryGetProperty("result", out var resultProp))
                        {
                            tcs.TrySetResult(resultProp.Clone());
                        }
                        else if (root.TryGetProperty("error", out var errorProp))
                        {
                            string msg = errorProp.TryGetProperty("message", out var m) ? m.GetString() ?? "RPC error" : "RPC error";
                            tcs.TrySetException(new Exception(msg));
                        }
                    }
                }
            }
            catch { }
        }
    }

    private static EngineStatsModel ParseStats(JsonElement el)
    {
        long dnsQueries = el.TryGetProperty("dns_queries", out var dq) ? dq.GetInt64() : 0;
        long dnsBlocked = el.TryGetProperty("dns_blocked", out var db) ? db.GetInt64() : 0;
        long tlsQueries = el.TryGetProperty("tls_queries", out var tq) ? tq.GetInt64() : 0;
        long tlsBlocked = el.TryGetProperty("tls_blocked", out var tb) ? tb.GetInt64() : 0;
        long quicDropped = el.TryGetProperty("quic_dropped", out var qd) ? qd.GetInt64() : 0;

        long allowed = el.TryGetProperty("allowed_count", out var ac) ? ac.GetInt64()
            : Math.Max(0, (dnsQueries + tlsQueries) - (dnsBlocked + tlsBlocked));
        long blocked = el.TryGetProperty("blocked_count", out var bc) ? bc.GetInt64()
            : (dnsBlocked + tlsBlocked + quicDropped);

        long uptime = el.TryGetProperty("uptime_seconds", out var ut) ? ut.GetInt64() : 0;
        long ramBytes = el.TryGetProperty("ram_bytes", out var rb) ? rb.GetInt64() : 0;
        double ramMb = el.TryGetProperty("ram_mb", out var rm) ? rm.GetDouble() : Math.Round((double)ramBytes / (1024 * 1024), 2);

        return new EngineStatsModel(
            allowed,
            blocked,
            dnsQueries,
            dnsBlocked,
            tlsQueries,
            tlsBlocked,
            quicDropped,
            uptime,
            ramBytes,
            ramMb
        );
    }

    public async Task<JsonElement> SendCommandAsync(string command, object? parameters = null, int timeoutMs = 6000)
    {
        if (!_isConnected || _writer == null)
            throw new InvalidOperationException("Not connected to engine named pipe.");

        string reqId = Interlocked.Increment(ref _requestIdSeq).ToString();
        var tcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingRequests[reqId] = tcs;

        // Supply both 'cmd' (spec IPC.md) and 'method' (JSON-RPC) for universal interchangeability
        var payload = new
        {
            id = reqId,
            cmd = command,
            method = command,
            @params = parameters ?? new { }
        };

        string json = JsonSerializer.Serialize(payload);
        await _writeLock.WaitAsync();
        try
        {
            var writer = _writer ?? throw new IOException("Engine connection lost.");
            await writer.WriteLineAsync(json);
        }
        catch
        {
            _pendingRequests.TryRemove(reqId, out _);
            throw;
        }
        finally
        {
            _writeLock.Release();
        }

        using var cts = new CancellationTokenSource(timeoutMs);
        using (cts.Token.Register(() =>
        {
            if (_pendingRequests.TryRemove(reqId, out var removed))
            {
                removed.TrySetException(new TimeoutException($"Request '{command}' timed out."));
            }
        }))
        {
            return await tcs.Task;
        }
    }

    public async Task<bool> PingAsync()
    {
        try
        {
            var res = await SendCommandAsync("engine.ping");
            return res.TryGetProperty("status", out var s) && s.GetString() == "ok";
        }
        catch
        {
            return false;
        }
    }

    public async Task<EngineStatusModel> GetStatusAsync()
    {
        var res = await SendCommandAsync("get_status");
        string name = res.TryGetProperty("name", out var n) ? n.GetString() ?? "Unknown" : "Unknown";
        string version = res.TryGetProperty("version", out var v) ? v.GetString() ?? "1.0.0" : "1.0.0";
        string state = res.TryGetProperty("state", out var st) ? st.GetString() ?? "unknown" : "unknown";
        long uptime = res.TryGetProperty("uptime_seconds", out var ut) ? ut.GetInt64() : 0;
        int activeRules = res.TryGetProperty("active_rules_count", out var ar) ? ar.GetInt32() : 0;
        int allowlistCount = res.TryGetProperty("allowlist_count", out var ac) ? ac.GetInt32() : 0;
        int listsCount = res.TryGetProperty("lists_count", out var lc) ? lc.GetInt32() : 0;

        EngineStatsModel? stats = null;
        if (res.TryGetProperty("stats", out var stEl))
        {
            stats = ParseStats(stEl);
        }

        return new EngineStatusModel(name, version, state, uptime, activeRules, allowlistCount, listsCount, stats);
    }

    public async Task<string> StartEngineAsync()
    {
        var res = await SendCommandAsync("start");
        return res.TryGetProperty("state", out var s) ? s.GetString() ?? "running" : "running";
    }

    public async Task<string> StopEngineAsync()
    {
        var res = await SendCommandAsync("stop");
        return res.TryGetProperty("state", out var s) ? s.GetString() ?? "stopped" : "stopped";
    }

    public async Task<SetListsResult> SetListsAsync(IEnumerable<string> paths)
    {
        var res = await SendCommandAsync("set_lists", new { paths });
        string status = res.TryGetProperty("status", out var s) ? s.GetString() ?? "ok" : "ok";
        int loadedLists = res.TryGetProperty("loaded_lists", out var ll) ? ll.GetInt32() : 0;
        int activeRules = res.TryGetProperty("active_rules_count", out var ar) ? ar.GetInt32() : 0;

        var failed = new List<string>();
        if (res.TryGetProperty("failed_paths", out var fp) && fp.ValueKind == JsonValueKind.Array)
        {
            foreach (var el in fp.EnumerateArray())
            {
                if (el.GetString() is { } str) failed.Add(str);
            }
        }

        return new SetListsResult(status, loadedLists, activeRules, failed);
    }

    public async Task<SetAllowlistResult> SetAllowlistAsync(IEnumerable<string> rules, IEnumerable<string>? paths = null)
    {
        var res = await SendCommandAsync("set_allowlist", new
        {
            rules,
            paths = paths ?? Array.Empty<string>()
        });
        string status = res.TryGetProperty("status", out var s) ? s.GetString() ?? "ok" : "ok";
        int count = res.TryGetProperty("allowlist_count", out var ac) ? ac.GetInt32() : 0;
        return new SetAllowlistResult(status, count);
    }

    public async Task<EngineStatsModel> GetStatsAsync()
    {
        var res = await SendCommandAsync("get_stats");
        return ParseStats(res);
    }

    public async Task<List<BlockedQueryModel>> GetRecentBlockedAsync(int limit = 50)
    {
        var res = await SendCommandAsync("get_recent_blocked", new { limit = 500 });
        var list = new List<BlockedQueryModel>();
        if (res.TryGetProperty("items", out var items) && items.ValueKind == JsonValueKind.Array)
        {
            foreach (var el in items.EnumerateArray())
            {
                list.Add(new BlockedQueryModel(
                    el.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "",
                    el.TryGetProperty("timestamp", out var ts) ? ts.GetInt64() : 0,
                    el.TryGetProperty("protocol", out var proto) ? proto.GetString() ?? "" : "",
                    el.TryGetProperty("client_ip", out var ip) ? ip.GetString() ?? "" : "",
                    el.TryGetProperty("domain", out var dom) ? dom.GetString() ?? "" : "",
                    el.TryGetProperty("matched_rule", out var mr) ? mr.GetString() ?? "" : (el.TryGetProperty("reason", out var re) ? re.GetString() ?? "" : ""),
                    el.TryGetProperty("source_list", out var sl) ? sl.GetString() ?? "" : ""
                ));
            }
        }
        // Normalize ordering for the engine's recent-blocked response.
        return list
            .OrderByDescending(b => b.Timestamp)
            .ThenByDescending(b => long.TryParse(b.Id, out var n) ? n : 0)
            .Take(limit)
            .ToList();
    }

    public async Task ReloadAsync()
    {
        await SendCommandAsync("reload");
    }

    public async Task ResetStatsAsync()
    {
        await SendCommandAsync("stats.reset");
    }

    public async Task<PrivateDnsConfigModel> SetPrivateDnsAsync(bool enabled, string url)
    {
        var res = await SendCommandAsync("set_private_dns", new
        {
            enabled,
            url = url ?? ""
        });
        bool isEnabled = res.TryGetProperty("enabled", out var en) && en.GetBoolean();
        string resolvedUrl = res.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
        return new PrivateDnsConfigModel(isEnabled, resolvedUrl);
    }

    public async Task<PrivateDnsConfigModel> GetPrivateDnsAsync()
    {
        var res = await SendCommandAsync("get_private_dns");
        bool isEnabled = res.TryGetProperty("enabled", out var en) && en.GetBoolean();
        string resolvedUrl = res.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
        return new PrivateDnsConfigModel(isEnabled, resolvedUrl);
    }

    public async Task<TestPrivateDnsResult> TestPrivateDnsAsync(string url)
    {
        string targetUrl = url ?? "";
        var res = await SendCommandAsync("test_private_dns", new
        {
            url = targetUrl
        }, timeoutMs: 10000);
        string status = res.TryGetProperty("status", out var s) ? s.GetString() ?? "ok" : "ok";
        long latency = res.TryGetProperty("latency_ms", out var l) ? l.GetInt64() : 0;
        string host = res.TryGetProperty("host", out var h) ? h.GetString() ?? targetUrl : targetUrl;
        return new TestPrivateDnsResult(status, latency, host);
    }

    private static void RaiseSafe(Action a)
    {
        try { a(); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[PipeClient] handler: {ex.Message}"); }
    }

    private void Cleanup()
    {
        try { _writer?.Dispose(); } catch { }
        try { _pipe?.Dispose(); } catch { }
        _writer = null;
        _pipe = null;
    }

    public void Dispose()
    {
        _cts?.Cancel();
        Cleanup();
    }
}
