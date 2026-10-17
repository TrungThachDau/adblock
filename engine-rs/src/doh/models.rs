use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateDnsConfig {
    pub enabled: bool,
    pub url: String,
}

impl Default for PrivateDnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDohUrl {
    pub raw_url: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub is_https: bool,
}

impl ParsedDohUrl {
    pub fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err("Private DNS URL cannot be empty.".to_string());
        }

        let (is_https, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = trimmed.strip_prefix("http://") {
            (false, r)
        } else {
            return Err("URL must start with https:// (e.g. https://cloudflare-dns.com/dns-query)".to_string());
        };

        let (authority, path_part) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };

        if authority.is_empty() {
            return Err("URL host cannot be empty.".to_string());
        }

        let default_port = if is_https { 443 } else { 80 };
        let (host, port) = if authority.starts_with('[') {
            // IPv6 literal e.g. [2606:4700:4700::1111]:443
            let end_bracket = authority
                .find(']')
                .ok_or_else(|| "Invalid IPv6 host in URL.".to_string())?;
            let host_part = &authority[1..end_bracket];
            let port_part = &authority[end_bracket + 1..];
            let port = if let Some(p_str) = port_part.strip_prefix(':') {
                p_str
                    .parse::<u16>()
                    .map_err(|_| "Invalid port in URL.".to_string())?
            } else if port_part.is_empty() {
                default_port
            } else {
                return Err("Invalid authority after IPv6 address.".to_string());
            };
            (host_part.to_string(), port)
        } else if let Some((h, p_str)) = authority.rsplit_once(':') {
            let port = p_str
                .parse::<u16>()
                .map_err(|_| "Invalid port in URL.".to_string())?;
            (h.to_string(), port)
        } else {
            (authority.to_string(), default_port)
        };

        if host.is_empty() {
            return Err("URL host cannot be empty.".to_string());
        }

        let path = if path_part.is_empty() || path_part == "/" {
            "/dns-query".to_string()
        } else {
            path_part.to_string()
        };

        Ok(Self {
            raw_url: trimmed.to_string(),
            host,
            port,
            path,
            is_https,
        })
    }
}

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub(crate) struct CacheKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

pub(crate) struct CacheEntry {
    pub response_wire: Vec<u8>,
    pub expires_at: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_doh_url_variants() {
        let u1 = ParsedDohUrl::parse("https://cloudflare-dns.com/dns-query").unwrap();
        assert_eq!(u1.host, "cloudflare-dns.com");
        assert_eq!(u1.port, 443);
        assert_eq!(u1.path, "/dns-query");
        assert!(u1.is_https);

        let u2 = ParsedDohUrl::parse("https://dns.nextdns.io/abc123").unwrap();
        assert_eq!(u2.host, "dns.nextdns.io");
        assert_eq!(u2.port, 443);
        assert_eq!(u2.path, "/abc123");

        let u3 = ParsedDohUrl::parse("https://1.1.1.1").unwrap();
        assert_eq!(u3.host, "1.1.1.1");
        assert_eq!(u3.port, 443);
        assert_eq!(u3.path, "/dns-query");

        let u4 = ParsedDohUrl::parse("https://[2606:4700:4700::1111]:8443/dns-query").unwrap();
        assert_eq!(u4.host, "2606:4700:4700::1111");
        assert_eq!(u4.port, 8443);
        assert_eq!(u4.path, "/dns-query");

        assert!(ParsedDohUrl::parse("ftp://example.com").is_err());
        assert!(ParsedDohUrl::parse("").is_err());
    }
}
