use super::client::send_doh_post;
use super::models::{CacheEntry, CacheKey, ParsedDohUrl};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct DohResolver {
    cache: RwLock<HashMap<CacheKey, CacheEntry>>,
}

impl Default for DohResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DohResolver {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(256)),
        }
    }

    pub fn clear_cache(&self) {
        self.cache.write().clear();
    }

    pub fn resolve(
        &self,
        target: &ParsedDohUrl,
        qname: &str,
        qtype: u16,
        qclass: u16,
        dns_query_payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let key = CacheKey {
            qname: qname.to_ascii_lowercase(),
            qtype,
            qclass,
        };

        // Check in-memory cache first
        {
            let cache_read = self.cache.read();
            if let Some(entry) = cache_read.get(&key) {
                if Instant::now() < entry.expires_at {
                    return Ok(entry.response_wire.clone());
                }
            }
        }

        let response = send_doh_post(target, dns_query_payload)?;

        // Cache valid NOERROR responses (RCODE == 0) for 60 seconds
        if response.len() >= 12 && (response[3] & 0x0F) == 0 {
            let mut cache_write = self.cache.write();
            if cache_write.len() >= 1024 {
                let now = Instant::now();
                cache_write.retain(|_, v| now < v.expires_at);
                if cache_write.len() >= 1024 {
                    cache_write.clear();
                }
            }
            cache_write.insert(
                key,
                CacheEntry {
                    response_wire: response.clone(),
                    expires_at: Instant::now() + Duration::from_secs(60),
                },
            );
        }

        Ok(response)
    }

    /// Probes the custom DoH endpoint with a standard RFC 8484 query for `example.com` (A)
    /// and returns round-trip latency in milliseconds.
    pub fn test_endpoint(&self, target: &ParsedDohUrl) -> Result<u64, String> {
        // Standard DNS query wire format for `example.com` A IN (TXID 0x0000)
        let probe_query: [u8; 29] = [
            0x00, 0x00, // ID = 0
            0x01, 0x00, // Flags: RD=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // root label
            0x00, 0x01, // QTYPE = A (1)
            0x00, 0x01, // QCLASS = IN (1)
        ];

        let started = Instant::now();
        let resp = send_doh_post(target, &probe_query)?;
        if resp.len() < 12 {
            return Err("Invalid DNS response from server (too short).".to_string());
        }
        // Check QR bit == 1 (response)
        if (resp[2] & 0x80) == 0 {
            return Err("Response from server is not a valid DNS reply.".to_string());
        }
        Ok(started.elapsed().as_millis() as u64)
    }
}
