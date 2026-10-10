using System.Text.Json;
using System.Text.Json.Serialization;

namespace AdblockEngine.Ipc;

public class RpcRequest
{
    [JsonPropertyName("id")]
    public object? Id { get; set; }

    [JsonPropertyName("method")]
    public string? Method { get; set; }

    [JsonPropertyName("cmd")]
    public string? Cmd { get; set; }

    [JsonIgnore]
    public string EffectiveMethod => Method ?? Cmd ?? string.Empty;

    [JsonPropertyName("params")]
    public JsonElement? Params { get; set; }
}

public record RpcSuccessResponse(
    [property: JsonPropertyName("id")] object? Id,
    [property: JsonPropertyName("result")] object Result
);

public record RpcErrorDetail(
    [property: JsonPropertyName("code")] int Code,
    [property: JsonPropertyName("message")] string Message
);

public record RpcErrorResponse(
    [property: JsonPropertyName("id")] object? Id,
    [property: JsonPropertyName("error")] RpcErrorDetail Error
);

public record EngineStats(
    [property: JsonPropertyName("dns_queries")] long DnsQueries,
    [property: JsonPropertyName("dns_blocked")] long DnsBlocked,
    [property: JsonPropertyName("tls_queries")] long TlsQueries,
    [property: JsonPropertyName("tls_blocked")] long TlsBlocked,
    [property: JsonPropertyName("quic_dropped")] long QuicDropped
);

public record QueryLogData(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("timestamp")] long Timestamp,
    [property: JsonPropertyName("protocol")] string Protocol,
    [property: JsonPropertyName("client_ip")] string ClientIp,
    [property: JsonPropertyName("domain")] string Domain,
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("reason")] string Reason
);

public record QueryLogEvent(
    [property: JsonPropertyName("event")] string Event,
    [property: JsonPropertyName("data")] QueryLogData Data
);

public record StatsUpdateEvent(
    [property: JsonPropertyName("event")] string Event,
    [property: JsonPropertyName("data")] EngineStats Data
);
