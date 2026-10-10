using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AdblockEngine.Rules;

namespace AdblockEngine.Ipc;

public class NamedPipeServer
{
    public const string PipeName = "adblock-engine";
    private readonly RuleStore _rules;
    private readonly Stopwatch _uptime = Stopwatch.StartNew();
    private readonly ConcurrentDictionary<Guid, Channel<string>> _clients = new();

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
        Console.WriteLine($"[IPC] Starting Named Pipe server on \\\\.\\pipe\\{PipeName}");

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var pipe = new NamedPipeServerStream(
                    PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await pipe.WaitForConnectionAsync(cancellationToken);
                _ = HandleClientAsync(pipe, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[IPC] Error accepting pipe client: {ex.Message}");
                await Task.Delay(500, cancellationToken);
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        var clientId = Guid.NewGuid();
        var channel = Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = true });
        _clients[clientId] = channel;

        using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };

        // Background task to send broadcast messages
        var sendTask = Task.Run(async () =>
        {
            try
            {
                while (await channel.Reader.WaitToReadAsync(cancellationToken))
                {
                    while (channel.Reader.TryRead(out var msg))
                    {
                        await writer.WriteLineAsync(msg);
                    }
                }
            }
            catch { }
        }, cancellationToken);

        try
        {
            while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
            {
                string? line = await reader.ReadLineAsync(cancellationToken);
                if (line == null) break;

                string response = HandleRequest(line);
                await writer.WriteLineAsync(response);
            }
        }
        catch { }
        finally
        {
            _clients.TryRemove(clientId, out _);
            channel.Writer.TryComplete();
            try { await sendTask; } catch { }
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
        string method = req.Method;
        var p = req.Params;

        try
        {
            switch (method)
            {
                case "engine.ping":
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        status = "ok",
                        timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                    }));

                case "engine.get_status":
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        state = _isPaused ? "paused" : "running",
                        uptime_seconds = (long)_uptime.Elapsed.TotalSeconds,
                        active_rules_count = _rules.Count,
                        stats = GetStats()
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
                    int limit = p.HasValue && p.Value.TryGetProperty("limit", out var limProp) ? limProp.GetInt32() : 100;
                    var (total, rulesList) = _rules.List(offset, limit);
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new
                    {
                        total,
                        offset,
                        limit,
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
                        cleared = true,
                        active_rules_count = 0
                    }));

                case "stats.get":
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, GetStats()));

                case "stats.reset":
                    ResetStats();
                    return JsonSerializer.Serialize(new RpcSuccessResponse(id, new { reset = true }));

                default:
                    return JsonSerializer.Serialize(new RpcErrorResponse(id,
                        new RpcErrorDetail(-32601, $"Method not found: {method}")));
            }
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new RpcErrorResponse(id,
                new RpcErrorDetail(-32603, $"Internal error: {ex.Message}")));
        }
    }
}
