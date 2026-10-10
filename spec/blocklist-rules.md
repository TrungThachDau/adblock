# Domain Blocklist Parsing & Matching Specification

## 1. Overview & Architectural Scope

This specification defines the exact parsing, normalization, and evaluation rules for the domain-level ad/tracker blocking engines (`engine-rs` and `engine-cs`).

Because the blocking mechanism operates strictly at **Layer 7 Network Interception** (reading DNS QNAME from UDP 53 and TLS Server Name Indication from TCP 443 `ClientHello`), it cannot inspect HTTP request URLs, paths, query strings, headers, or DOM elements. Any rule requiring HTTP-level features MUST be discarded during parsing.

---

## 2. Supported Rule Syntaxes

Each input line from a list file is parsed independently. The engine MUST support four distinct domain formats:

### 2.1 Adblock Plus (ABP) Domain Block Rules
- **Syntax**: `||<host>^`
- **Semantics**: Blocks `<host>` and all its subdomains.
- **Example**: `||doubleclick.net^`
  - Matches: `doubleclick.net`, `ad.doubleclick.net`, `sub.ad.doubleclick.net`.
  - Does NOT match: `notdoubleclick.net` or `doubleclick.net.evil.com`.
- **Parsing**:
  - Starts with prefix `||`.
  - Ends with separator `^`.
  - Extracted domain: text between `||` and `^`.

### 2.2 Adblock Plus (ABP) Allowlist / Exception Rules
- **Syntax**: `@@||<host>^`
- **Semantics**: Whitelists `<host>` and all its subdomains. Overrides any blocklist rule matching the domain.
- **Example**: `@@||safe.doubleclick.net^`
  - Unblocks: `safe.doubleclick.net`, `api.safe.doubleclick.net`.
  - Does NOT unblock: `doubleclick.net` or `other.doubleclick.net`.
- **Parsing**:
  - Starts with prefix `@@||`.
  - Ends with separator `^`.
  - Extracted domain: text between `@@||` and `^`.

### 2.3 Hosts File Format
- **Syntax**: `<IP> <host> [<host2> ... [<hostN>]] [# comment]`
- **Semantics**: Standard operating system hosts file format mapping sinkhole IPs to blocked domains.
- **Valid IP prefixes**:
  - `0.0.0.0`
  - `127.0.0.1`
  - `::1`
  - `::`
  - `0`
- **Examples**:
  - `0.0.0.0 analytics.google.com` &rarr; blocks `analytics.google.com`.
  - `127.0.0.1 bad-tracker.com banner.bad-tracker.com # tracker list` &rarr; blocks both `bad-tracker.com` and `banner.bad-tracker.com`.
  - `::1 telemetry.microsoft.com` &rarr; blocks `telemetry.microsoft.com`.
- **Parsing**:
  - Strip inline comments starting with `#` to end of line.
  - Split tokens by whitespace (space or tab).
  - First token MUST match a recognized sinkhole/loopback IP address.
  - Subsequent tokens are treated as individual hostnames to block (excluding `localhost`, `broadcasthost`, `local`).

### 2.4 Plain Domain Format
- **Syntax**: `<host>`
- **Semantics**: Bare hostname per line (common in Pi-hole or simple domain lists). Implicitly blocks the domain and all its subdomains.
- **Example**: `popup-network.biz`
  - Matches: `popup-network.biz` and `sub.popup-network.biz`.

---

## 3. Rules to Skip (Disqualification Criteria)

Any rule containing non-domain features MUST be skipped and discarded. Engines MUST NOT throw errors on these lines; they are simply ignored.

| Condition | Indicator | Example Rule | Rationale |
|---|---|---|---|
| **Path / URL rule** | Contains `/` | `\|\|example.com/ads/*`<br>`example.com/banner.js`<br>`/ad-banner/` | Domain filter cannot inspect HTTP paths or files. |
| **Wildcard rule** | Contains `*` | `\|\|*click*.com^`<br>`ad*.tracking.org`<br>`*analytics*` | Regex/glob evaluation introduces latency. Only strict hierarchical domain matching is supported. |
| **Element Hiding / Cosmetic** | Contains `##`, `#?#`, `#@#`, `#$#` | `example.com##.ad-box`<br>`###ad-frame`<br>`site.org#@#.whitelist` | Cosmetic DOM hiding rules only apply inside browser page renderers. |
| **Options / Modifiers** | Contains `$` | `\|\|track.com^$domain=news.com`<br>`\|\|ad.net^$script,third-party`<br>`\|\|cdn.com^$image` | Context-sensitive modifiers (first/third-party, content-type) are not visible at packet layer. |
| **Comments** | Starts with `!` or `#` | `! Title: EasyList`<br>`# Hosts list update` | Human-readable metadata and headers. |
| **Blank Lines** | Empty or whitespace | ` ` or `\t\r\n` | Formatting whitespace. |
| **IP Addresses** | Numeric IPv4 / IPv6 | `192.168.1.1` | Domain engine operates on DNS/SNI hostnames. |
| **Loopback names** | Reserved localhost | `localhost`, `local` | System hostnames. |

---

## 4. Domain Normalization Algorithm

Before storing in rule tables or performing lookups, all extracted hostnames MUST be normalized using the following deterministic steps:

1. **Whitespace Trimming**: Strip all leading and trailing whitespace characters (`\t`, `\r`, `\n`, space).
2. **ASCII Lowercase**: Convert all characters to lowercase (`A-Z` &rarr; `a-z`). Domain matching is strictly case-insensitive.
3. **Dot Trimming**: Strip all leading and trailing dot characters (`.`):
   - Example: `.adservice.google.com.` &rarr; `adservice.google.com`.
4. **Validation**:
   - A valid hostname MUST consist only of ASCII letters (`a-z`), digits (`0-9`), hyphens (`-`), underscores (`_`), and dots (`.`).
   - Labels (segments between dots) MUST NOT be empty.
   - If a hostname fails validation or is empty, it MUST be skipped.

---

## 5. Evaluation & Matching Pipeline

When an outbound DNS query or TLS `ClientHello` packet arrives, the target hostname is evaluated through a strict multi-tier pipeline:

```
                  +---------------------------+
                  | Outbound Packet Received  |
                  |  (DNS QNAME or TLS SNI)   |
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  |  Normalize Query Domain   |
                  | (lowercase, strip dots)   |
                  +-------------+-------------+
                                |
                                v
                  +---------------------------+
                  | Check Allowlist / @@      |
                  |  (Exact or Subdomain)     |
                  +-------------+-------------+
                               / \
                        Match /   \ No Match
                             v     v
                 +------------+   +---------------------------+
                 |   ALLOW    |   | Check Blocklist           |
                 | (Forward)  |   |  (Exact or Subdomain)     |
                 +------------+   +-------------+-------------+
                                               / \
                                        Match /   \ No Match
                                             v     v
                                 +------------+   +------------+
                                 |   BLOCK    |   |   ALLOW    |
                                 |  (Drop +   |   | (Forward)  |
                                 |  NX/RST)   |   +------------+
                                 +------------+
```

### 5.1 Step 1: Query Normalization
The query hostname `Q` extracted from the packet is trimmed, converted to ASCII lowercase, and stripped of trailing dots.

### 5.2 Step 2: Allowlist Check (First Priority)
- The engine checks whether `Q` matches any entry in the **Allowlist**.
- If a match is found:
  - Evaluation terminates immediately.
  - Return **ALLOWED** (`blocked = false`).
  - The packet is forwarded untouched.

### 5.3 Step 3: Blocklist Check
- If not allowlisted, the engine checks whether `Q` matches any entry in the **Blocklist**.
- If a match is found:
  - Evaluation terminates immediately.
  - Return **BLOCKED** (`blocked = true`).
  - Perform protocol block action:
    - DNS UDP 53: Inject synthetic `NXDOMAIN` response inbound + drop outbound query.
    - TLS TCP 443: Inject synthetic `TCP RST | ACK` inbound + drop outbound `ClientHello`.
- If no match is found:
  - Return **ALLOWED** (`blocked = false`).
  - The packet is forwarded untouched.

---

## 6. Suffix / Subdomain Matching Semantics

A domain rule `R` matches a query domain `Q` if and only if:
$$\mathbf{Match}(Q, R) \iff (Q = R) \lor Q.\text{EndsWith}("." + R)$$

### Boundary Verification Examples

| Rule $R$ | Query $Q$ | Matches? | Rationale |
|---|---|---|---|
| `adservice.google.com` | `adservice.google.com` | **YES** | Exact match ($Q = R$). |
| `adservice.google.com` | `sub.adservice.google.com` | **YES** | Subdomain boundary match ($Q$ ends with `.adservice.google.com`). |
| `adservice.google.com` | `a.b.adservice.google.com` | **YES** | Multi-level subdomain match. |
| `adservice.google.com` | `notadservice.google.com` | **NO** | Missing dot separator (prefix collision prevented). |
| `adservice.google.com` | `google.com` | **NO** | Parent domain is never blocked by child rule. |
| `adservice.google.com` | `adservice.google.com.evil.com` | **NO** | Query is a subdomain of `evil.com`, not $R$. |
| `tracker.net` | `sub.tracker.net` | **YES** | Suffix match with dot separator. |
| `tracker.net` | `mytracker.net` | **NO** | String suffix without dot boundary. |

---

## 7. Data Structure Guidelines for Engines

To achieve sub-microsecond lookup latency under high network traffic:
- **Hash-Set of Suffix Domains**: Extract each dot-separated suffix of the incoming query domain ($Q$, parent of $Q$, grandparent of $Q$, ...) and check against a hash set. For example, for `a.b.adservice.google.com`:
  1. Check `a.b.adservice.google.com`
  2. Check `b.adservice.google.com`
  3. Check `adservice.google.com` &rarr; MATCH.
- **Domain Trie**: Alternatively, reverse labels (e.g. `["com", "google", "adservice"]`) in a prefix trie.
- Both engines MUST produce identical matching results for all cases in `/spec/testdata/cases.json`.
