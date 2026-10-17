use super::models::ParsedRule;

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
