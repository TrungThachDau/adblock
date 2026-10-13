use parking_lot::RwLock;
use std::collections::HashSet;
use std::fs::File;
use std::hash::{BuildHasherDefault, Hasher};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedRule {
    Block(String),
    Allow(String),
}

/// Normalizes a hostname according to spec/blocklist-rules.md:
/// - Strips leading/trailing dots and whitespace
/// - ASCII lowercase
/// - Validates character set ([a-z0-9-_.]), checks for empty labels
pub fn normalize_domain(raw: &str) -> Option<String> {
    let clean = raw.trim().trim_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return None;
    }
    // Must be valid hostname characters
    if !clean.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return None;
    }
    // Labels cannot be empty
    if clean.split('.').any(|label| label.is_empty()) {
        return None;
    }
    Some(clean)
}

fn is_reserved_host(host: &str) -> bool {
    let lower = host.trim().trim_matches('.').to_ascii_lowercase();
    matches!(lower.as_str(), "localhost" | "local" | "broadcasthost")
}

/// Parses a single line from an adblock/hosts list according to spec/blocklist-rules.md
pub fn parse_line(line: &str) -> Vec<ParsedRule> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('#') {
        return Vec::new();
    }

    // Skip rules containing path (/), options ($), cosmetic selectors (##, #?#, #@#, #$#)
    if trimmed.contains('/') || trimmed.contains('$') {
        return Vec::new();
    }
    if trimmed.contains("##") || trimmed.contains("#?#") || trimmed.contains("#@#") || trimmed.contains("#$#") {
        return Vec::new();
    }

    // Handle wildcard skip: if contains '*', skip unless it is a leading wildcard prefix '*.domain'
    if trimmed.contains('*') {
        if let Some(suffix) = trimmed.strip_prefix("*.") {
            if !suffix.contains('*') {
                if let Some(valid) = normalize_domain(suffix) {
                    return vec![ParsedRule::Block(valid)];
                }
            }
        }
        return Vec::new();
    }

    // 1. ABP Allowlist @@||host^
    if let Some(rest) = trimmed.strip_prefix("@@||") {
        let domain = rest.trim_end_matches('^');
        if let Some(valid) = normalize_domain(domain) {
            return vec![ParsedRule::Allow(valid)];
        }
        return Vec::new();
    }

    // 2. ABP Block ||host^
    if let Some(rest) = trimmed.strip_prefix("||") {
        let domain = rest.trim_end_matches('^');
        if let Some(valid) = normalize_domain(domain) {
            return vec![ParsedRule::Block(valid)];
        }
        return Vec::new();
    }

    // 3. Hosts format (strip inline comments first)
    let no_comment = if let Some(idx) = trimmed.find('#') {
        trimmed[..idx].trim()
    } else {
        trimmed
    };

    let parts: Vec<&str> = no_comment.split_whitespace().collect();
    if parts.len() >= 2 {
        let ip = parts[0];
        if matches!(ip, "0.0.0.0" | "127.0.0.1" | "::1" | "::" | "0") {
            let mut result = Vec::new();
            for host in &parts[1..] {
                if is_reserved_host(host) {
                    continue;
                }
                if let Some(valid) = normalize_domain(host) {
                    result.push(ParsedRule::Block(valid));
                }
            }
            return result;
        }
    }

    // 4. Plain domain
    if !trimmed.contains(char::is_whitespace) {
        if is_reserved_host(trimmed) {
            return Vec::new();
        }
        if let Some(valid) = normalize_domain(trimmed) {
            return vec![ParsedRule::Block(valid)];
        }
    }

    Vec::new()
}

/// Keys are already FNV-1a hashes, so the set must not hash them again.
#[derive(Debug, Default, Clone, Copy)]
pub struct IdentityHasher(u64);

impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 << 8) | u64::from(b);
        }
    }

    fn write_u64(&mut self, i: u64) {
        self.0 = i;
    }
}

type HashSet64 = HashSet<u64, BuildHasherDefault<IdentityHasher>>;

/// FNV-1a 64-bit; must match engine-cs so both engines agree on rule identity.
fn hash_domain(domain: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in domain.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Normalized domains are ASCII, so one byte per char in a single buffer avoids a heap allocation per rule.
#[derive(Debug, Clone, Default)]
struct DomainList {
    buf: Vec<u8>,
    ends: Vec<u32>,
}

impl DomainList {
    fn len(&self) -> usize {
        self.ends.len()
    }

    fn push(&mut self, domain: &str) {
        self.buf.extend_from_slice(domain.as_bytes());
        self.ends.push(self.buf.len() as u32);
    }

    fn remove(&mut self, domain: &str) -> bool {
        let mut start = 0usize;
        for i in 0..self.ends.len() {
            let end = self.ends[i] as usize;
            if end - start == domain.len() && &self.buf[start..end] == domain.as_bytes() {
                self.buf.drain(start..end);
                let removed = domain.len() as u32;
                for e in &mut self.ends[i + 1..] {
                    *e -= removed;
                }
                self.ends.remove(i);
                return true;
            }
            start = end;
        }
        false
    }

    fn range(&self, offset: usize, end: usize) -> Vec<String> {
        (offset..end)
            .map(|i| {
                let start = if i == 0 { 0 } else { self.ends[i - 1] as usize };
                String::from_utf8_lossy(&self.buf[start..self.ends[i] as usize]).into_owned()
            })
            .collect()
    }

    fn shrink_to_fit(&mut self) {
        self.buf.shrink_to_fit();
        self.ends.shrink_to_fit();
    }

    fn clear(&mut self) {
        self.buf = Vec::new();
        self.ends = Vec::new();
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuleStore {
    // Suffix rules for blocking (e.g. "doubleclick.net" matches "doubleclick.net" and "*.doubleclick.net")
    block_rules: HashSet64,
    // Suffix rules for allowlisting (priority over block_rules)
    allowlist_rules: HashSet64,
    // Ordered normalized block domains for deterministic pagination in UI
    ordered_rules: DomainList,
}

impl RuleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a collection of raw lines (auto-parses ABP, hosts, plain domains, and allowlists)
    pub fn add(&mut self, rules: &[String]) -> usize {
        let mut added_count = 0;
        for raw in rules {
            let parsed = parse_line(raw);
            for rule in parsed {
                match rule {
                    ParsedRule::Block(domain) => {
                        if self.block_rules.insert(hash_domain(&domain)) {
                            self.ordered_rules.push(&domain);
                            added_count += 1;
                        }
                    }
                    ParsedRule::Allow(domain) => {
                        if self.allowlist_rules.insert(hash_domain(&domain)) {
                            added_count += 1;
                        }
                    }
                }
            }
        }
        added_count
    }

    /// Explicitly add allowlist rules
    pub fn add_allowlist(&mut self, rules: &[String]) -> usize {
        let mut count = 0;
        for raw in rules {
            let parsed = parse_line(raw);
            if parsed.is_empty() {
                if let Some(valid) = normalize_domain(raw) {
                    if self.allowlist_rules.insert(hash_domain(&valid)) {
                        count += 1;
                    }
                }
            } else {
                for p in parsed {
                    match p {
                        ParsedRule::Allow(d) | ParsedRule::Block(d) => {
                            if self.allowlist_rules.insert(hash_domain(&d)) {
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
        count
    }

    /// Remove a collection of rules
    pub fn remove(&mut self, rules: &[String]) -> usize {
        let mut removed_count = 0;
        for raw in rules {
            let parsed = parse_line(raw);
            for p in parsed {
                let domain = match p {
                    ParsedRule::Block(d) => d,
                    ParsedRule::Allow(d) => d,
                };
                let hash = hash_domain(&domain);
                let removed_block = self.block_rules.remove(&hash);
                let removed_allow = self.allowlist_rules.remove(&hash);
                if removed_block {
                    self.ordered_rules.remove(&domain);
                }
                if removed_block || removed_allow {
                    removed_count += 1;
                }
            }
        }
        removed_count
    }

    /// Clear all rules
    pub fn clear(&mut self) {
        self.block_rules = HashSet64::default();
        self.allowlist_rules = HashSet64::default();
        self.ordered_rules.clear();
    }

    /// Total active block rules count
    pub fn count(&self) -> usize {
        self.block_rules.len()
    }

    /// Total active allowlist rules count
    pub fn allowlist_count(&self) -> usize {
        self.allowlist_rules.len()
    }

    /// Check if a queried domain matches any rule.
    /// Follows spec/blocklist-rules.md:
    /// 1. Check Allowlist FIRST (exact or suffix match) -> returns None (allowed)
    /// 2. Check Blocklist (exact or suffix match) -> returns Some(matching_rule) (blocked)
    pub fn check(&self, domain: &str) -> Option<String> {
        let clean = match normalize_domain(domain) {
            Some(d) => d,
            None => return None,
        };

        // 1. Allowlist Check FIRST (exact or dot-boundary suffix)
        if self.allowlist_rules.contains(&hash_domain(&clean)) {
            return None;
        }
        let mut cursor = clean.as_str();
        while let Some(dot_idx) = cursor.find('.') {
            cursor = &cursor[dot_idx + 1..];
            if self.allowlist_rules.contains(&hash_domain(cursor)) {
                return None;
            }
        }

        // 2. Blocklist Check (exact or dot-boundary suffix)
        if self.block_rules.contains(&hash_domain(&clean)) {
            return Some(clean);
        }
        let mut cursor = clean.as_str();
        while let Some(dot_idx) = cursor.find('.') {
            cursor = &cursor[dot_idx + 1..];
            if self.block_rules.contains(&hash_domain(cursor)) {
                return Some(cursor.to_string());
            }
        }

        None
    }

    /// Get paginated list of rules
    pub fn list(&self, offset: usize, limit: usize) -> (usize, Vec<String>) {
        let total = self.ordered_rules.len();
        if offset >= total {
            return (total, Vec::new());
        }
        let end = (offset + limit).min(total);
        (total, self.ordered_rules.range(offset, end))
    }

    /// Load rules from a line-delimited text file
    pub fn load_file(&mut self, path: &Path) -> std::io::Result<usize> {
        const CHUNK: usize = 8192;
        let reader = BufReader::new(File::open(path)?);
        let mut chunk: Vec<String> = Vec::with_capacity(CHUNK);
        let mut added = 0;
        for line in reader.lines() {
            chunk.push(line?);
            if chunk.len() == CHUNK {
                added += self.add(&chunk);
                chunk.clear();
            }
        }
        added += self.add(&chunk);

        self.block_rules.shrink_to_fit();
        self.allowlist_rules.shrink_to_fit();
        self.ordered_rules.shrink_to_fit();
        Ok(added)
    }
}

pub type SharedRuleStore = Arc<RwLock<RuleStore>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matching() {
        let mut store = RuleStore::new();
        store.add(&[
            "doubleclick.net".into(),
            "adservice.google.com".into(),
            "*.adnxs.com".into(),
            "trackers.adtech.io".into(),
            "*.tracker-network.net".into(),
        ]);

        assert!(store.check("doubleclick.net").is_some());
        assert!(store.check("ad.doubleclick.net").is_some());
        assert!(store.check("deep.sub.ad.doubleclick.net").is_some());
        assert!(store.check("notdoubleclick.net").is_none());

        assert!(store.check("adservice.google.com").is_some());
        assert!(store.check("google.com").is_none());
        assert!(store.check("mail.google.com").is_none());

        assert!(store.check("ib.adnxs.com").is_some());
        assert!(store.check("eu.secure.ib.adnxs.com").is_some());
        assert!(store.check("adnxs.com").is_some());
        assert!(store.check("fakeadnxs.com").is_none());

        assert!(store.check("trackers.adtech.io").is_some());
        assert!(store.check("api.tracker-network.net").is_some());
        assert!(store.check("github.com").is_none());
        assert!(store.check("cloudflare.com").is_none());
        assert!(store.check("ADSERVICE.GOOGLE.COM").is_some());
    }

    #[test]
    fn test_abp_and_allowlist() {
        let mut store = RuleStore::new();
        store.add(&[
            "||adservice.google.com^".into(),
            "@@||safe.adservice.google.com^".into(),
            "0.0.0.0 bad-host.com banner.bad-host.com".into(),
            "127.0.0.1 malicious-tracker.net # inline comment".into(),
            "plain-ad.com".into(),
        ]);

        // Blocked ABP
        assert!(store.check("adservice.google.com").is_some());
        assert!(store.check("sub.adservice.google.com").is_some());

        // Allowlisted ABP
        assert!(store.check("safe.adservice.google.com").is_none());
        assert!(store.check("sub.safe.adservice.google.com").is_none());

        // Hosts
        assert!(store.check("bad-host.com").is_some());
        assert!(store.check("banner.bad-host.com").is_some());
        assert!(store.check("malicious-tracker.net").is_some());

        // Plain domain
        assert!(store.check("plain-ad.com").is_some());
        assert!(store.check("sub.plain-ad.com").is_some());
    }

    #[test]
    fn test_list_and_remove_keep_order_and_offsets() {
        let mut store = RuleStore::new();
        store.add(&[
            "a.com".into(),
            "0.0.0.0 bb.net".into(),
            "||ccc.org^".into(),
            "dddd.io".into(),
        ]);

        assert_eq!(
            store.list(0, 10),
            (4, vec!["a.com".to_string(), "bb.net".into(), "ccc.org".into(), "dddd.io".into()])
        );
        assert_eq!(store.list(1, 2).1, vec!["bb.net".to_string(), "ccc.org".into()]);
        assert!(store.list(9, 2).1.is_empty());

        assert_eq!(store.remove(&["bb.net".into()]), 1);
        assert_eq!(store.count(), 3);
        assert_eq!(store.list(0, 10).1, vec!["a.com".to_string(), "ccc.org".into(), "dddd.io".into()]);
        assert!(store.check("bb.net").is_none());
        assert!(store.check("x.dddd.io").is_some());

        // Removing a domain must not remove rules that merely contain it as a substring.
        store.add(&["xa.com".into()]);
        assert_eq!(store.remove(&["a.com".into()]), 1);
        assert!(store.check("xa.com").is_some());
        assert_eq!(store.list(0, 10).1, vec!["ccc.org".to_string(), "dddd.io".into(), "xa.com".into()]);
    }
}
