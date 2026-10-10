using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AdblockEngine.Rules;

namespace AdblockEngine.Ipc;

public class NamedPipeServer
{
    public const string PipeNameApp = "adblock.engine";
    public const string PipeNameLegacy = "adblock-engine";

    private readonly RuleStore _rules;
    private readonly Stopwatch _uptime = Stopwatch.StartNew();
    private readonly ConcurrentDictionary<Guid, Channel<string>> _clients = new();
    private readonly ConcurrentQueue<QueryLogData> _recentBlocked = new();
    private readonly List<string> _configuredLists = new();
    private readonly List<string> _configuredAllowlist = new();
    private readonly object _configLock = new();

    private long _dnsQueries;
    private long _dnsBlocked;
    private long _tlsQueries;
    private long _tlsBlocked;
    private long _quicDropped;
    private long _logSeq = 1;
    private volatile bool _isPaused;

    public bool IsPaused
    {
        get => _isPaused;
        set => _isPaused = value;
    }

    public NamedPipeServer(RuleStore rules)
    {
        _rules = rules;
    }

    public EngineStats GetStats()
    {
        return new EngineStats(
            Interlocked.Read(ref _dnsQueries),
            Interlocked.Read(ref _dnsBlocked),
            Interlocked.Read(ref _tlsQueries),
            Interlocked.Read(ref _tlsBlocked),
            Interlocked.Read(ref _quicDropped)
        );
    }

    public void ResetStats()
    {
        Interlocked.Exchange(ref _dnsQueries, 0);
        Interlocked.Exchange(ref _dnsBlocked, 0);
        Interlocked.Exchange(ref _tlsQueries, 0);
        Interlocked.Exchange(ref _tlsBlocked, 0);
        Interlocked.Exchange(ref _quicDropped, 0);
        BroadcastStatsUpdate();
    }

    public void IncrementDns(bool blocked)
    {
        Interlocked.Increment(ref _dnsQueries);
        if (blocked) Interlocked.Increment(ref _dnsBlocked);
    }

    public void IncrementTls(bool blocked)
    {
        Interlocked.Increment(ref _tlsQueries);
        if (blocked) Interlocked.Increment(ref _tlsBlocked);
    }

    public void IncrementQuic()
    {
        Interlocked.Increment(ref _quicDropped);
    }

    public string NextLogId() => Interlocked.Increment(ref _logSeq).ToString();

    public void BroadcastLog(QueryLogData data)
    {
        if (string.Equals(data.Action, "blocked", StringComparison.OrdinalIgnoreCase))
        {
            _recentBlocked.Enqueue(data);
            while (_recentBlocked.Count > 500 && _recentBlocked.TryDequeue(out _)) { }
        }

        var evt = new QueryLogEvent("query_log", data);
        string json = JsonSerializer.Serialize(evt);
        Broadcast(json);
    }

    public void BroadcastStatsUpdate()
    {
        var evt = new StatsUpdateEvent("stats_update", GetStats());
        string json = JsonSerializer.Serialize(evt);
        Broadcast(json);
    }

    private void Broadcast(string message)
    {
        foreach (var client in _clients.Values)
        {
            client.Writer.TryWrite(message);
        }
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        Console.WriteLine($"[IPC] Starting Named Pipe servers on \\\\.\\pipe\\{PipeNameApp} and \\\\.\\pipe\\{PipeNameLegacy}");

        var taskApp = ListenPipeAsync(PipeNameApp, cancellationToken);
        var taskLegacy = ListenPipeAsync(PipeNameLegacy, cancellationToken);

        await Task.WhenAll(taskApp, taskLegacy);
    }

    private async Task ListenPipeAsync(string pipeName, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var pipeServer = new NamedPipeServerStream(
                    pipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await pipeServer.WaitForConnectionAsync(cancellationToken);
                _ = Task.Run(() => HandleClientAsync(pipeServer, cancellationToken), cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[IPC] Error accepting named pipe client on {pipeName}: {ex.Message}");
                await Task.Delay(500, cancellationToken);
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        var clientId = Guid.NewGuid();
        var clientChannel = Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = true });
        _clients[clientId] = clientChannel;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = cts.Token;

        try
        {
            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };

            var readTask = Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    string? line = await reader.ReadLineAsync(token);
                    if (line == null) break;

                    string response = HandleRequest(line);
                    await writer.WriteLineAsync(response.AsMemory(), token);
                }
            }, token);

            var writeTask = Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    string message = await clientChannel.Reader.ReadAsync(token);
                    await writer.WriteLineAsync(message.AsMemory(), token);
                }
            }, token);

            await Task.WhenAny(readTask, writeTask);
            cts.Cancel();
        }
        catch
        {
            // Client disconnected or pipe closed
        }
        finally
        {
            _clients.TryRemove(clientId, out _);
            try { pipe.Dispose(); } catch { }
        }
    }

    public string HandleRequest(string line)
    {
        RpcRequest? req;
        try
        {
            req = JsonSerializer.Deserialize<RpcRequest>(line);
            if (req == null) throw new Exception();
        }
        catch
        {
            return JsonSerializer.Serialize(new RpcErrorResponse(null, new RpcErrorDetail(-32700, "Parse error")));
        }

        object? id = req.Id;
        string method = req.EffectiveMethod;
        var p = req.Params;

        try
        {
            switch (method)
            {
                case "start":
                case "engine.start":
                    _isPaused = false;
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        status = "ok",
                        state = "running"
                    }));

                case "stop":
                case "engine.stop":
                    _isPaused = true;
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        status = "ok",
                        state = "stopped"
                    }));

                case "get_status":
                case "engine.get_status":
                    int listsCount;
                    lock (_configLock) listsCount = _configuredLists.Count;
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        name = "engine-cs",
                        version = "1.0.0",
                        state = _isPaused ? "stopped" : "running",
                        active_rules_count = _rules.Count,
                        allowlist_count = _rules.AllowlistCount,
                        lists_count = listsCount,
                        uptime_seconds = (long)_uptime.Elapsed.TotalSeconds,
                        stats = GetStats()
                    }));

                case "set_lists":
                    var newPaths = new List<string>();
                    if (p.HasValue && p.Value.TryGetProperty("paths", out var pathsProp) && pathsProp.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var el in pathsProp.EnumerateArray())
                        {
                            if (el.GetString() is { } s) newPaths.Add(s);
                        }
                    }

                    int loadedLists = 0;
                    var failedPaths = new List<string>();

                    lock (_configLock)
                    {
                        _configuredLists.Clear();
                        _configuredLists.AddRange(newPaths);

                        _rules.Clear();
                        foreach (var path in newPaths)
                        {
                            if (File.Exists(path))
                            {
                                int loaded = _rules.LoadFile(path);
                                if (loaded >= 0) loadedLists++;
                                else failedPaths.Add(path);
                            }
                            else
                            {
                                failedPaths.Add(path);
                            }
                        }

                        // Re-apply configured allowlists
                        _rules.AddAllowlist(_configuredAllowlist);
                    }

                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        status = "ok",
                        loaded_lists = loadedLists,
                        active_rules_count = _rules.Count,
                        failed_paths = failedPaths
                    }));

                case "set_allowlist":
                    var allowRules = new List<string>();
                    if (p.HasValue && p.Value.TryGetProperty("rules", out var arProp) && arProp.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var el in arProp.EnumerateArray())
                        {
                            if (el.GetString() is { } s) allowRules.Add(s);
                        }
                    }

                    if (p.HasValue && p.Value.TryGetProperty("paths", out var apProp) && apProp.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var el in apProp.EnumerateArray())
                        {
                            if (el.GetString() is { } pth && File.Exists(pth))
                            {
                                allowRules.AddRange(File.ReadAllLines(pth));
                            }
                        }
                    }

                    lock (_configLock)
                    {
                        _configuredAllowlist.Clear();
                        _configuredAllowlist.AddRange(allowRules);
                        _rules.AddAllowlist(allowRules);
                    }

                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        status = "ok",
                        allowlist_count = _rules.AllowlistCount
                    }));

                case "reload":
                    lock (_configLock)
                    {
                        _rules.Clear();
                        foreach (var path in _configuredLists)
                        {
                            if (File.Exists(path)) _rules.LoadFile(path);
                        }
                        _rules.AddAllowlist(_configuredAllowlist);
                    }

                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        status = "ok",
                        active_rules_count = _rules.Count,
                        allowlist_count = _rules.AllowlistCount
                    }));

                case "get_stats":
                case "stats.get":
                    var currentStats = GetStats();
                    long ramBytes = 0;
                    try
                    {
                        using var proc = Process.GetCurrentProcess();
                        ramBytes = proc.WorkingSet64;
                    }
                    catch { }

                    double ramMb = Math.Round((double)ramBytes / (1024 * 1024), 2);
                    long allowedCount = Math.Max(0, (currentStats.DnsQueries + currentStats.TlsQueries)
                        - (currentStats.DnsBlocked + currentStats.TlsBlocked));
                    long blockedCount = currentStats.DnsBlocked + currentStats.TlsBlocked + currentStats.QuicDropped;

                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        allowed_count = allowedCount,
                        blocked_count = blockedCount,
                        dns_queries = currentStats.DnsQueries,
                        dns_blocked = currentStats.DnsBlocked,
                        tls_queries = currentStats.TlsQueries,
                        tls_blocked = currentStats.TlsBlocked,
                        quic_dropped = currentStats.QuicDropped,
                        uptime_seconds = (long)_uptime.Elapsed.TotalSeconds,
                        ram_bytes = ramBytes,
                        ram_mb = ramMb
                    }));

                case "get_recent_blocked":
                    int limit = p.HasValue && p.Value.TryGetProperty("limit", out var lim) ? lim.GetInt32() : 50;
                    var items = _recentBlocked.Take(limit).ToList();
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        items
                    }));

                case "engine.ping":
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        status = "ok",
                        timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                    }));

                case "engine.set_state":
                    string targetState = p.HasValue && p.Value.TryGetProperty("state", out var stateProp)
                        ? stateProp.GetString() ?? "" : "";
                    if (targetState == "paused")
                    {
                        _isPaused = true;
                        return JsonSerializer.Serialize(new RpcSuccessResponse(id, new { state = "paused" }));
                    }
                    else if (targetState == "running")
                    {
                        _isPaused = false;
                        return JsonSerializer.Serialize(new RpcSuccessResponse(id, new { state = "running" }));
                    }
                    return JsonSerializer.Serialize(new RpcErrorResponse(id,
                        new RpcErrorDetail(-32602, "Invalid state parameter. Use 'running' or 'paused'.")));

                case "rules.list":
                    int offset = p.HasValue && p.Value.TryGetProperty("offset", out var offProp) ? offProp.GetInt32() : 0;
                    int rlimit = p.HasValue && p.Value.TryGetProperty("limit", out var limProp) ? limProp.GetInt32() : 100;
                    var (total, rulesList) = _rules.List(offset, rlimit);
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        total,
                        offset,
                        limit = rlimit,
                        rules = rulesList
                    }));

                case "rules.add":
                    var toAdd = new List<string>();
                    if (p.HasValue && p.Value.TryGetProperty("rules", out var addRulesProp) && addRulesProp.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var el in addRulesProp.EnumerateArray())
                        {
                            if (el.GetString() is { } s) toAdd.Add(s);
                        }
                    }
                    int added = _rules.Add(toAdd);
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        added,
                        active_rules_count = _rules.Count
                    }));

                case "rules.remove":
                    var toRemove = new List<string>();
                    if (p.HasValue && p.Value.TryGetProperty("rules", out var remRulesProp) && remRulesProp.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var el in remRulesProp.EnumerateArray())
                        {
                            if (el.GetString() is { } s) toRemove.Add(s);
                        }
                    }
                    int removed = _rules.Remove(toRemove);
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        removed,
                        active_rules_count = _rules.Count
                    }));

                case "rules.clear":
                    _rules.Clear();
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        status = "ok",
                        active_rules_count = 0
                    }));

                case "stats.reset":
                    ResetStats();
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        status = "ok",
                        reset = true
                    }));

                default:
                    return JsonSerializer.Serialize(new RpcErrorResponse(id,
                        new RpcErrorDetail(-32601, $"Method '{method}' not found")));
            }
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new RpcErrorResponse(id,
                new RpcErrorDetail(-32603, $"Internal error: {ex.Message}")));
        }
    }
}
