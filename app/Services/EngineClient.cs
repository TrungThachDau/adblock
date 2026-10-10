using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AdblockApp.Services;

public record EngineStatsModel(
    long DnsQueries,
    long DnsBlocked,
    long TlsQueries,
    long TlsBlocked,
    long QuicDropped
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

public record EngineStatusModel(
    string State,
    long UptimeSeconds,
    int ActiveRulesCount,
    EngineStatsModel Stats
);

public record RulesListResult(
    int Total,
    int Offset,
    int Limit,
    List<string> Rules
);

public class EngineClient : IDisposable
{
    public const string PipeName = "adblock-engine";
    private NamedPipeClientStream? _pipe;
    private StreamWriter? _writer;
    private CancellationTokenSource? _cts;
    private Task? _readTask;

    private readonly ConcurrentDictionary<string, TaskCompletionSource<JsonElement>> _pendingRequests = new();
    private long _requestIdSeq = 1;
    private bool _isConnected;

    public bool IsConnected => _isConnected;

    public event Action<bool>? ConnectionStateChanged;
    public event Action<QueryLogModel>? QueryLogReceived;
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
            try
            {
                var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(3000, cancellationToken);

                _pipe = pipe;
                _writer = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true };
                _isConnected = true;
                ConnectionStateChanged?.Invoke(true);

                _readTask = ReadLoopAsync(pipe, cancellationToken);
                await _readTask;
            }
            catch (TimeoutException) { }
            catch (IOException) { }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PipeClient] Error: {ex.Message}");
            }
            finally
            {
                _isConnected = false;
                ConnectionStateChanged?.Invoke(false);
                Cleanup();
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

                // Check if this is an Event push
                if (root.TryGetProperty("event", out var eventProp))
                {
                    string eventType = eventProp.GetString() ?? "";
                    if (eventType == "query_log" && root.TryGetProperty("data", out var logData))
                    {
                        var log = new QueryLogModel(
                            logData.GetProperty("id").GetString() ?? "",
                            logData.GetProperty("timestamp").GetInt64(),
                            logData.GetProperty("protocol").GetString() ?? "",
                            logData.GetProperty("client_ip").GetString() ?? "",
                            logData.GetProperty("domain").GetString() ?? "",
                            logData.GetProperty("action").GetString() ?? "",
                            logData.GetProperty("reason").GetString() ?? ""
                        );
                        QueryLogReceived?.Invoke(log);
                    }
                    else if (eventType == "stats_update" && root.TryGetProperty("data", out var statsData))
                    {
                        var stats = ParseStats(statsData);
                        StatsUpdateReceived?.Invoke(stats);
                    }
                    continue;
                }

                // Check if this is an RPC Response
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
                            string msg = errorProp.GetProperty("message").GetString() ?? "RPC error";
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
        return new EngineStatsModel(
            el.GetProperty("dns_queries").GetInt64(),
            el.GetProperty("dns_blocked").GetInt64(),
            el.GetProperty("tls_queries").GetInt64(),
            el.GetProperty("tls_blocked").GetInt64(),
            el.GetProperty("quic_dropped").GetInt64()
        );
    }

    private async Task<JsonElement> SendRequestAsync(string method, object? parameters = null, int timeoutMs = 5000)
    {
        if (!_isConnected || _writer == null)
            throw new InvalidOperationException("Not connected to engine named pipe.");

        string reqId = Interlocked.Increment(ref _requestIdSeq).ToString();
        var tcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingRequests[reqId] = tcs;

        var payload = new
        {
            id = reqId,
            method = method,
            @params = parameters ?? new { }
        };

        string json = JsonSerializer.Serialize(payload);
        await _writer.WriteLineAsync(json);

        using var cts = new CancellationTokenSource(timeoutMs);
        using (cts.Token.Register(() => {
            if (_pendingRequests.TryRemove(reqId, out var removed))
            {
                removed.TrySetException(new TimeoutException("Request timed out."));
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
            var res = await SendRequestAsync("engine.ping");
            return res.TryGetProperty("status", out var s) && s.GetString() == "ok";
        }
        catch
        {
            return false;
        }
    }

    public async Task<EngineStatusModel> GetStatusAsync()
    {
        var res = await SendRequestAsync("engine.get_status");
        string state = res.GetProperty("state").GetString() ?? "unknown";
        long uptime = res.GetProperty("uptime_seconds").GetInt64();
        int rulesCount = res.GetProperty("active_rules_count").GetInt32();
        var stats = ParseStats(res.GetProperty("stats"));

        return new EngineStatusModel(state, uptime, rulesCount, stats);
    }

    public async Task<string> SetStateAsync(string state)
    {
        var res = await SendRequestAsync("engine.set_state", new { state });
        return res.GetProperty("state").GetString() ?? state;
    }

    public async Task<RulesListResult> ListRulesAsync(int offset = 0, int limit = 100)
    {
        var res = await SendRequestAsync("rules.list", new { offset, limit });
        int total = res.GetProperty("total").GetInt32();
        int off = res.GetProperty("offset").GetInt32();
        int lim = res.GetProperty("limit").GetInt32();

        var list = new List<string>();
        foreach (var r in res.GetProperty("rules").EnumerateArray())
        {
            if (r.GetString() is { } s) list.Add(s);
        }

        return new RulesListResult(total, off, lim, list);
    }

    public async Task<int> AddRulesAsync(IEnumerable<string> rules)
    {
        var res = await SendRequestAsync("rules.add", new { rules });
        return res.GetProperty("added").GetInt32();
    }

    public async Task<int> RemoveRulesAsync(IEnumerable<string> rules)
    {
        var res = await SendRequestAsync("rules.remove", new { rules });
        return res.GetProperty("removed").GetInt32();
    }

    public async Task ClearRulesAsync()
    {
        await SendRequestAsync("rules.clear");
    }

    public async Task<EngineStatsModel> GetStatsAsync()
    {
        var res = await SendRequestAsync("stats.get");
        return ParseStats(res);
    }

    public async Task ResetStatsAsync()
    {
        await SendRequestAsync("stats.reset");
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
