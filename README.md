# Windows Domain-Level Ad & Tracker Blocker Monorepo

High-performance Windows domain-level ad and tracker blocker using **WinDivert 2.x**. Intercepts outbound DNS (UDP 53) and TLS SNI (TCP 443), synthesizes instant block responses (DNS NXDOMAIN and TCP RST), drops UDP 443 (QUIC / HTTP/3), and coexists seamlessly with **Cloudflare WARP** and **WireGuard**.

---

## 1. Monorepo Architecture

```
/
├── spec/               # Shared contract & test vectors
│   ├── PROTOCOL.md     # IPC wire specification (Named Pipe + NDJSON)
│   ├── schema.json     # JSON schema for requests, responses & events
│   └── test-data/      # Test fixtures (domain vectors, raw packet hex)
│       ├── rules.txt
│       ├── test_cases.json
│       └── packets.json
│
├── engine-rs/          # Rust filtering engine (independent daemon/service)
│   ├── Cargo.toml
│   ├── src/
│   └── tests/
│
├── engine-cs/          # C# .NET 10 filtering engine (independent daemon/service)
│   ├── AdblockEngine.csproj
│   ├── Program.cs
│   └── tests/
│
└── app/                # WinUI 3 unpackaged GUI application
    ├── AdblockApp.csproj
    ├── MainWindow.xaml
    └── Services/EngineClient.cs
```

### Core Invariant & Interchangeability Rule
- Both `engine-rs` and `engine-cs` implement the **exact same IPC specification** over the Windows Named Pipe `\\.\pipe\adblock-engine`.
- The UI (`/app`) communicates exclusively over this pipe.
- The UI does not know, check, or care which engine implementation is currently running. Both engines are 100% interchangeable drop-ins.

---

## 2. Packet Filtering Specification (WinDivert 2.x)

### Filter String
Both engines open WinDivert at `WINDIVERT_LAYER_NETWORK` (layer 0) with priority `0`:
```sql
outbound and !loopback and (udp.DstPort == 53 or (tcp.DstPort == 443 and tcp.PayloadLength > 0) or udp.DstPort == 443)
```

### 1. DNS (UDP Port 53)
- **Parse**: Extracts the QNAME from the DNS Question section.
- **Match**: Fast suffix/subdomain lookup against the active rule set.
- **Block Action**:
  - Synthesizes an **NXDOMAIN** response:
    - Preserves transaction ID.
    - Sets flags to `0x8183` (QR=1, RD=1, RA=1, RCODE=3 Name Error).
    - Swaps Source and Destination IP addresses.
    - Swaps Source and Destination UDP ports (Source port becomes 53).
    - Clears `addr.Outbound` (inbound direction).
    - Recalculates checksums via `WinDivertHelperCalcChecksums`.
    - Injects inbound to the OS resolver via `WinDivertSend`.
  - **Drops** the original outbound query packet.

### 2. HTTPS / TLS SNI (TCP Port 443)
- **Parse**: Intercepts outbound TCP packets with payload. Verifies TLS Record Layer (`0x16`) and Handshake (`0x01` ClientHello). Walks extension records to locate Extension `0x0000` (Server Name Indication) and extracts the SNI hostname.
- **Match**: Evaluates hostname against the active rule set.
- **Block Action**:
  - Synthesizes a **TCP RST** packet to the client:
    - Swaps Source and Destination IP addresses.
    - Swaps Source and Destination TCP ports (Source port becomes 443).
    - Sets TCP Sequence Number = original Acknowledgment Number.
    - Sets TCP Acknowledgment Number = original Sequence Number + TCP payload length.
    - Sets TCP Flags = `0x14` (`RST | ACK`).
    - Clears `addr.Outbound` (inbound direction).
    - Recalculates checksums via `WinDivertHelperCalcChecksums`.
    - Injects inbound to the client socket via `WinDivertSend`.
  - **Drops** the original outbound ClientHello packet.
  - The client application / browser socket receives an instant RST (`ERR_CONNECTION_RESET`), failing fast without connection timeouts.

### 3. QUIC / HTTP/3 (UDP Port 443)
- **Action**: Drops all outbound UDP 443 packets immediately.
- **Rationale**: Web browsers (Chrome, Edge, Firefox) automatically fall back to standard TCP 443 (HTTP/2 / HTTP/1.1) when UDP 443 traffic is dropped, allowing reliable domain extraction via TLS SNI inspection.

---

## 3. Coexistence with WARP and WireGuard

Conflicts between packet interceptors and VPNs typically occur when an interceptor filters outer encrypted transport packets or resets adapter routing indexes. This solution guarantees coexistence:

1. **Outer Transport Isolation**:
   - Cloudflare WARP communicates with Cloudflare edge nodes using outer UDP on port **2408** (or fallback ports).
   - Standard WireGuard endpoints communicate via outer UDP on port **51820** (or custom ports).
   - The WinDivert filter specifically captures destination ports `53` and `443`. Outer VPN tunnel encapsulation packets are never touched.

2. **Interface Preservation (`WINDIVERT_DATA_NETWORK`)**:
   - WireGuard and WARP route unencrypted internal traffic through the **Wintun** virtual adapter.
   - When WinDivert captures packets, it records the interface index `addr.Network.IfIdx` and `addr.Network.SubIfIdx`.
   - Both engines preserve these exact interface indexes when reinjecting inbound synthetic responses (DNS NXDOMAIN and TCP RST). The Windows TCP/IP stack routes the response directly back to the process bound to the Wintun adapter.

---

## 4. IPC Protocol Specification (`/spec`)

- **Endpoint**: `\\.\pipe\adblock-engine`
- **Framing**: Newline-delimited JSON (NDJSON) over standard Windows Named Pipe.

### RPC Methods
| Method | Description |
|---|---|
| `engine.ping` | Healthcheck and latency probe. Returns `{"status": "ok", "timestamp": ...}` |
| `engine.get_status` | Returns `{ state, uptime_seconds, active_rules_count, stats }` |
| `engine.set_state` | Sets filtering state (`{"state": "running" \| "paused"}`) |
| `rules.list` | Returns paginated list of active block rules |
| `rules.add` | Adds domain rules (`{"rules": ["ad.com", "*.tracker.org"]}`) |
| `rules.remove` | Removes domain rules |
| `rules.clear` | Clears all domain rules |
| `stats.get` | Returns counters (`dns_queries`, `dns_blocked`, `tls_queries`, `tls_blocked`, `quic_dropped`) |
| `stats.reset` | Resets all counters to zero |

### Asynchronous Events
- `query_log`: Emitted in real-time when a packet is inspected:
  ```json
  {"event":"query_log","data":{"id":"101","timestamp":1728553893,"protocol":"DNS","client_ip":"192.168.1.15","domain":"adservice.google.com","action":"blocked","reason":"Rule match: adservice.google.com"}}
  ```
- `stats_update`: Broadcast periodically to synchronize metrics with the UI.

---

## 5. Building and Running

### Prerequisites
- Windows 10 (version 1809+) or Windows 11.
- Administrator privileges (required to load the WinDivert kernel driver).
- [WinDivert 2.2+](https://reqrypt.org/windivert.html): Ensure `WinDivert.dll` and `WinDivert64.sys` are located in your executable directory or system path.

### 1. Rust Engine (`/engine-rs`)
```powershell
cd d:\adblock\engine-rs

# Run spec compliance unit tests (runs offline without driver)
cargo test

# Build and run engine (requires Administrator for packet divert)
cargo run --release
```

### 2. C# Engine (`/engine-cs`)
```powershell
cd d:\adblock\engine-cs

# Run spec compliance unit tests
dotnet test tests/AdblockEngine.Tests/AdblockEngine.Tests.csproj

# Build and run engine (requires Administrator for packet divert)
dotnet run -c Release
```

### 3. WinUI 3 Application (`/app`)
```powershell
cd d:\adblock\app

# Build and run unpackaged WinUI 3 UI
dotnet run -c Release
```
