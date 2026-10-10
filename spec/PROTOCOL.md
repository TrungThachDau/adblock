# Adblock Engine IPC Protocol Specification

## 1. Overview

The Adblock Engine IPC protocol defines the communication contract between the core packet filtering engine and client applications (such as the WinUI 3 management GUI).

### Core Principles
1. **Engine Agnostic**: The protocol abstracts all internal implementation details. The client application MUST NOT know or care whether the engine is implemented in Rust (`engine-rs`), C# (`engine-cs`), or any other language.
2. **Identical Semantics**: Both `engine-rs` and `engine-cs` implement this exact specification. Any feature or response present in one engine MUST be present in the other with identical wire format and behavior.
3. **Transport**: Stream-oriented Windows Named Pipe.
4. **Framing**: Newline-Delimited JSON (NDJSON) UTF-8 text. Every message is a single valid JSON object ending with a newline character (`\n` or `\r\n`).

---

## 2. Transport Layer

- **Pipe Name**: `\\.\pipe\adblock-engine`
- **Direction**: Bidirectional (`PIPE_ACCESS_DUPLEX`)
- **Mode**: Byte stream (`PIPE_TYPE_BYTE | PIPE_READMODE_BYTE`)
- **Concurrency**: The engine MUST support multiple concurrent client connections. Events are broadcast to all connected clients.
- **Encoding**: UTF-8 without Byte Order Mark (BOM).
- **Framing**: Line-delimited (`\n`). Messages MUST NOT contain unescaped newline characters within the JSON payload.

---

## 3. Message Framing & Types

There are two categories of messages transmitted across the pipe:
1. **RPC Request / Response**: Initiated by the client, replied to by the engine.
2. **Events (Push Notifications)**: Emitted spontaneously by the engine to connected clients (e.g., live query log entries, statistics updates).

### 3.1 RPC Request Format (Client -> Engine)

```json
{
  "id": "string | number",
  "method": "string",
  "params": {}
}
```

- `id` (required): Unique request identifier chosen by the client. The engine echoes this exact identifier in its response.
- `method` (required): The RPC method name in `<namespace>.<action>` format (e.g., `engine.get_status`).
- `params` (optional / required depending on method): JSON object containing method-specific parameters. Defaults to `{}` if omitted.

### 3.2 RPC Success Response Format (Engine -> Client)

```json
{
  "id": "string | number",
  "result": {}
}
```

- `id`: Matches the request `id`.
- `result`: Method-specific result payload.

### 3.3 RPC Error Response Format (Engine -> Client)

```json
{
  "id": "string | number",
  "error": {
    "code": -32000,
    "message": "Human readable error description",
    "data": null
  }
}
```

Standard Error Codes:
- `-32700`: Parse error (invalid JSON).
- `-32600`: Invalid request (missing required fields).
- `-32601`: Method not found.
- `-32602`: Invalid parameters.
- `-32603`: Internal engine error.
- `-32000`: Application-level error.

### 3.4 Event Format (Engine -> Client)

```json
{
  "event": "string",
  "data": {}
}
```

- `event`: Name of the event (e.g. `query_log`, `stats_update`).
- `data`: Event-specific payload.

---

## 4. RPC Methods

### 4.1 `engine.ping`
Checks pipe connectivity and engine liveness.

**Request:**
```json
{"id": 1, "method": "engine.ping", "params": {}}
```

**Response:**
```json
{
  "id": 1,
  "result": {
    "status": "ok",
    "timestamp": 1728553893
  }
}
```

### 4.2 `engine.get_status`
Retrieves current engine operational state, uptime, active rule count, and packet metrics.

**Request:**
```json
{"id": 2, "method": "engine.get_status", "params": {}}
```

**Response:**
```json
{
  "id": 2,
  "result": {
    "state": "running",
    "uptime_seconds": 3600,
    "active_rules_count": 1250,
    "stats": {
      "dns_queries": 450,
      "dns_blocked": 32,
      "tls_queries": 820,
      "tls_blocked": 15,
      "quic_dropped": 54
    }
  }
}
```
*Note: `state` can be `"running"` or `"paused"`.*

### 4.3 `engine.set_state`
Pauses or resumes packet filtering. When paused, packets pass through untouched (no DNS NXDOMAIN injection, no TLS RST, no QUIC drop).

**Request:**
```json
{"id": 3, "method": "engine.set_state", "params": {"state": "paused"}}
```

**Response:**
```json
{
  "id": 3,
  "result": {
    "state": "paused"
  }
}
```

### 4.4 `rules.list`
Lists currently loaded domain block rules with pagination.

**Request:**
```json
{"id": 4, "method": "rules.list", "params": {"offset": 0, "limit": 100}}
```

**Response:**
```json
{
  "id": 4,
  "result": {
    "total": 1250,
    "offset": 0,
    "limit": 100,
    "rules": [
      "adservice.google.com",
      "telemetry.microsoft.com",
      "*.doubleclick.net"
    ]
  }
}
```

### 4.5 `rules.add`
Adds one or more domain rules into the active blocklist.

**Request:**
```json
{
  "id": 5,
  "method": "rules.add",
  "params": {
    "rules": [
      "tracker.example.com",
      "*.adnetwork.org"
    ]
  }
}
```

**Response:**
```json
{
  "id": 5,
  "result": {
    "added": 2,
    "active_rules_count": 1252
  }
}
```

### 4.6 `rules.remove`
Removes one or more domain rules from the active blocklist.

**Request:**
```json
{
  "id": 6,
  "method": "rules.remove",
  "params": {
    "rules": [
      "tracker.example.com"
    ]
  }
}
```

**Response:**
```json
{
  "id": 6,
  "result": {
    "removed": 1,
    "active_rules_count": 1251
  }
}
```

### 4.7 `rules.clear`
Clears all active domain rules.

**Request:**
```json
{"id": 7, "method": "rules.clear", "params": {}}
```

**Response:**
```json
{
  "id": 7,
  "result": {
    "cleared": true,
    "active_rules_count": 0
  }
}
```

### 4.8 `stats.get`
Retrieves cumulative statistics counters.

**Request:**
```json
{"id": 8, "method": "stats.get", "params": {}}
```

**Response:**
```json
{
  "id": 8,
  "result": {
    "dns_queries": 450,
    "dns_blocked": 32,
    "tls_queries": 820,
    "tls_blocked": 15,
    "quic_dropped": 54
  }
}
```

### 4.9 `stats.reset`
Resets all cumulative statistics counters to zero.

**Request:**
```json
{"id": 9, "method": "stats.reset", "params": {}}
```

**Response:**
```json
{
  "id": 9,
  "result": {
    "reset": true
  }
}
```

---

## 5. Asynchronous Events

### 5.1 `query_log`
Emitted whenever a DNS query, TLS SNI handshake, or QUIC packet is inspected.

**Payload:**
```json
{
  "event": "query_log",
  "data": {
    "id": "100293",
    "timestamp": 1728553893,
    "protocol": "DNS",
    "client_ip": "192.168.1.15",
    "domain": "adservice.google.com",
    "action": "blocked",
    "reason": "Rule match: adservice.google.com"
  }
}
```

Fields:
- `id` (string): Monotonically increasing unique ID for UI tracking.
- `timestamp` (integer): Unix timestamp in seconds.
- `protocol` (string): `"DNS"`, `"TLS"`, or `"QUIC"`.
- `client_ip` (string): Source IP address string (IPv4 or IPv6).
- `domain` (string): Extracted QNAME (for DNS), SNI hostname (for TLS), or `"[quic-port-443]"` (for QUIC).
- `action` (string): `"blocked"` or `"allowed"`.
- `reason` (string): Reason description (e.g. `"Rule match: *.doubleclick.net"`, `"QUIC dropped to force TCP fallback"`, `"Allowed"`).

### 5.2 `stats_update`
Emitted periodically or upon significant metric changes to keep UI counters in sync without aggressive polling.

**Payload:**
```json
{
  "event": "stats_update",
  "data": {
    "dns_queries": 451,
    "dns_blocked": 33,
    "tls_queries": 820,
    "tls_blocked": 15,
    "quic_dropped": 54
  }
}
```

---

## 6. Packet Handling Specification

### 6.1 WinDivert Filter
Both engines MUST open WinDivert at `WINDIVERT_LAYER_NETWORK` with priority `0`, flags `0`, using the filter:
```
outbound and !loopback and (udp.DstPort == 53 or (tcp.DstPort == 443 and tcp.PayloadLength > 0) or udp.DstPort == 443)
```

### 6.2 DNS Inspection (UDP 53)
1. Parse DNS Question section from UDP payload. Extract QNAME.
2. If QNAME matches an active rule:
   - Construct synthetic DNS response:
     - Swap source and destination IP addresses.
     - Swap source and destination UDP ports (source becomes 53).
     - Preserve DNS Transaction ID.
     - Set DNS Flags to `0x8183` (QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=3 [NXDOMAIN]).
     - Copy Question section.
     - Truncate packet after Question section (ANCOUNT=0, NSCOUNT=0, ARCOUNT=0).
     - Update UDP Length (`8 + 12 + question_length`).
     - Update IP Total Length.
     - Clear `addr.Outbound` bit (set to `0` for inbound injection).
     - Recalculate IP and UDP checksums via `WinDivertHelperCalcChecksums`.
     - Inject response inbound via `WinDivertSend`.
     - Drop the original outbound packet.
     - Increment `dns_queries` and `dns_blocked`.
     - Emit `query_log` event (`action: "blocked"`).
3. If QNAME does NOT match:
   - Reinject original packet outbound untouched via `WinDivertSend`.
   - Increment `dns_queries`.
   - Emit `query_log` event (`action: "allowed"`).

### 6.3 TLS SNI Inspection (TCP 443)
1. Verify TCP payload starts with TLS Record Layer Handshake:
   - Byte 0 == `0x16` (Handshake)
   - Byte 5 == `0x01` (ClientHello)
   *(If not ClientHello, immediately reinject packet outbound untouched).*
2. Parse ClientHello extensions to locate Extension Type `0x0000` (Server Name Indication). Extract hostname.
3. If SNI matches an active rule:
   - Construct synthetic TCP RST packet to client:
     - Swap source and destination IP addresses.
     - Swap source and destination TCP ports (source becomes 443).
     - Set TCP Sequence Number = original TCP Acknowledgment Number.
     - Set TCP Acknowledgment Number = original TCP Sequence Number + TCP Payload Length.
     - Set TCP Flags = `0x14` (RST | ACK).
     - Set TCP Window = 0.
     - Set IP Total Length to IP header length + 20 (no TCP options).
     - Clear `addr.Outbound` bit (set to `0` for inbound injection).
     - Recalculate IP and TCP checksums via `WinDivertHelperCalcChecksums`.
     - Inject RST inbound via `WinDivertSend`.
     - Drop the original outbound ClientHello packet.
     - Increment `tls_queries` and `tls_blocked`.
     - Emit `query_log` event (`action: "blocked"`).
4. If SNI does NOT match:
   - Reinject original packet outbound untouched via `WinDivertSend`.
   - Increment `tls_queries`.
   - Emit `query_log` event (`action: "allowed"`).

### 6.4 QUIC Dropping (UDP 443)
1. Any outbound UDP packet with destination port 443 is dropped immediately (never reinjected).
2. Browsers (Chrome, Edge, Firefox) fall back to TCP 443 (HTTP/2 / HTTP/1.1) when QUIC is blocked, allowing TLS SNI inspection.
3. Increment `quic_dropped`.
4. Emit `query_log` event (`protocol: "QUIC"`, `action: "dropped"`, `reason: "QUIC dropped to force TCP fallback"`).

### 6.5 Coexistence with WARP / WireGuard
1. WireGuard / Cloudflare WARP uses an outer UDP transport tunnel (e.g. UDP 2408 for WARP, UDP 51820 for standard WireGuard). Because the filter strictly selects `udp.DstPort == 53`, `tcp.DstPort == 443`, and `udp.DstPort == 443`, WireGuard tunnel encapsulation packets are NEVER captured, delayed, or dropped.
2. For packets traversing the Wintun adapter, the adapter interface index `addr.Network.IfIdx` is preserved on all reinjections and inbound responses.
