use parking_lot::RwLock;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct RuleStore {
    // Exact domain rules (or normalized base domains)
    exact_rules: HashSet<String>,
    // Wildcard / suffix rules (e.g. "doubleclick.net" matches any "*.doubleclick.net")
    suffix_rules: HashSet<String>,
    // Ordered raw rules list for deterministic pagination in UI
    ordered_rules: Vec<String>,
}

impl RuleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Normalize a domain: lowercase, strip whitespace, strip leading/trailing dots and "*."
    pub fn normalize_rule(rule: &str) -> (String, bool) {
        let trimmed = rule.trim().to_ascii_lowercase();
        if let Some(wildcard) = trimmed.strip_prefix("*.") {
            (wildcard.trim_matches('.').to_string(), true)
        } else {
            let clean = trimmed.trim_matches('.').to_string();
            // In standard adblockers, a domain rule like "doubleclick.net" also blocks subdomains
            (clean, true)
        }
    }

    /// Add a collection of rules
    pub fn add(&mut self, rules: &[String]) -> usize {
        let mut added_count = 0;
        for raw in rules {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let (normalized, is_suffix) = Self::normalize_rule(trimmed);
            if normalized.is_empty() {
                continue;
            }

            if !self.exact_rules.contains(&normalized) && !self.suffix_rules.contains(&normalized) {
                if is_suffix {
                    self.suffix_rules.insert(normalized.clone());
                } else {
                    self.exact_rules.insert(normalized.clone());
                }
                self.ordered_rules.push(trimmed.to_string());
                added_count += 1;
            }
        }
        added_count
    }

    /// Remove a collection of rules
    pub fn remove(&mut self, rules: &[String]) -> usize {
        let mut removed_count = 0;
        for raw in rules {
            let (normalized, _) = Self::normalize_rule(raw);
            let removed_exact = self.exact_rules.remove(&normalized);
            let removed_suffix = self.suffix_rules.remove(&normalized);
            if removed_exact || removed_suffix {
                self.ordered_rules.retain(|r| {
                    let (n, _) = Self::normalize_rule(r);
                    n != normalized
                });
                removed_count += 1;
            }
        }
        removed_count
    }

    /// Clear all rules
    pub fn clear(&mut self) {
        self.exact_rules.clear();
        self.suffix_rules.clear();
        self.ordered_rules.clear();
    }

    /// Total active rules count
    pub fn count(&self) -> usize {
        self.ordered_rules.len()
    }

    /// Check if a queried domain matches any rule.
    /// Returns Some(matching_rule) or None.
    pub fn check(&self, domain: &str) -> Option<String> {
        let clean = domain.trim().trim_matches('.').to_ascii_lowercase();
        if clean.is_empty() {
            return None;
        }

        // 1. Direct exact or suffix match
        if self.exact_rules.contains(&clean) {
            return Some(clean);
        }
        if self.suffix_rules.contains(&clean) {
            return Some(clean);
        }

        // 2. Iteratively peel off leftmost subdomain label:
        // e.g. "ad.doubleclick.net" -> checks "doubleclick.net"
        let mut cursor = clean.as_str();
        while let Some(dot_idx) = cursor.find('.') {
            cursor = &cursor[dot_idx + 1..];
            if self.suffix_rules.contains(cursor) {
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
        (total, self.ordered_rules[offset..end].to_vec())
    }

    /// Load rules from a line-delimited text file
    pub fn load_file(&mut self, path: &Path) -> std::io::Result<usize> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut lines = Vec::new();
        for line in reader.lines() {
            lines.push(line?);
        }
        Ok(self.add(&lines))
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
}
