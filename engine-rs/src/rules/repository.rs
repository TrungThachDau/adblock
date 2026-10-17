use super::models::{hash_domain, DomainList, HashSet64, ParsedRule};
use super::parser::{normalize_domain, parse_line};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

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
