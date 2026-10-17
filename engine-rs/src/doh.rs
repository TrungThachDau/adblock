use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr;
use std::time::{Duration, Instant};

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
struct CacheKey {
    qname: String,
    qtype: u16,
    qclass: u16,
}

struct CacheEntry {
    response_wire: Vec<u8>,
    expires_at: Instant,
}

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

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
struct WinHttpHandle(*mut c_void);

#[cfg(windows)]
impl Drop for WinHttpHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Networking::WinHttp::WinHttpCloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
pub fn send_doh_post(target: &ParsedDohUrl, dns_query_payload: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Networking::WinHttp::*;

    if dns_query_payload.len() < 12 {
        return Err("DNS query payload too short".to_string());
    }

    // Per RFC 8484 Section 4.1, set DNS ID to 0 for HTTP cache friendliness;
    // build_dns_response restores the original transaction ID before injecting to the client.
    let mut body = dns_query_payload.to_vec();
    body[0] = 0;
    body[1] = 0;

    let agent = to_wide("AdblockEngine-DoH/1.0");
    let host_wide = to_wide(&target.host);
    let method_wide = to_wide("POST");
    let path_wide = to_wide(&target.path);
    let headers_wide = to_wide(
        "Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n",
    );

    unsafe {
        let session = WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            ptr::null(),
            ptr::null(),
            0,
        );
        if session.is_null() {
            return Err("WinHttpOpen failed".to_string());
        }
        let _session_guard = WinHttpHandle(session);

        // Set timeouts: resolve=3000ms, connect=3000ms, send=3000ms, receive=4000ms
        let _ = WinHttpSetTimeouts(session, 3000, 3000, 3000, 4000);

        let connect = WinHttpConnect(session, host_wide.as_ptr(), target.port, 0);
        if connect.is_null() {
            return Err(format!("Failed to connect to DoH host {}", target.host));
        }
        let _connect_guard = WinHttpHandle(connect);

        let flags = if target.is_https { WINHTTP_FLAG_SECURE } else { 0 };
        let request = WinHttpOpenRequest(
            connect,
            method_wide.as_ptr(),
            path_wide.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            flags,
        );
        if request.is_null() {
            return Err("WinHttpOpenRequest failed".to_string());
        }
        let _request_guard = WinHttpHandle(request);

        let sent = WinHttpSendRequest(
            request,
            headers_wide.as_ptr(),
            u32::MAX,
            body.as_ptr() as *const c_void,
            body.len() as u32,
            body.len() as u32,
            0,
        );
        if sent == 0 {
            return Err(format!(
                "DoH request to {} failed (TLS/connection error)",
                target.raw_url
            ));
        }

        let received = WinHttpReceiveResponse(request, ptr::null_mut());
        if received == 0 {
            return Err("WinHttpReceiveResponse failed".to_string());
        }

        let mut status_code: u32 = 0;
        let mut status_size = std::mem::size_of::<u32>() as u32;
        let queried = WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            ptr::null(),
            &mut status_code as *mut u32 as *mut c_void,
            &mut status_size,
            ptr::null_mut(),
        );
        if queried == 0 || status_code != 200 {
            return Err(format!("DoH server returned HTTP status {}", status_code));
        }

        let mut response_bytes = Vec::with_capacity(512);
        let mut chunk = [0u8; 2048];
        loop {
            let mut bytes_read: u32 = 0;
            let ok = WinHttpReadData(
                request,
                chunk.as_mut_ptr() as *mut c_void,
                chunk.len() as u32,
                &mut bytes_read,
            );
            if ok == 0 {
                return Err("WinHttpReadData failed".to_string());
            }
            if bytes_read == 0 {
                break;
            }
            response_bytes.extend_from_slice(&chunk[..bytes_read as usize]);
            if response_bytes.len() > 65500 {
                return Err("DoH response exceeded maximum DNS message size".to_string());
            }
        }

        if response_bytes.len() < 12 {
            return Err("DoH response payload is smaller than 12-byte DNS header".to_string());
        }

        Ok(response_bytes)
    }
}

#[cfg(not(windows))]
pub fn send_doh_post(_target: &ParsedDohUrl, _dns_query_payload: &[u8]) -> Result<Vec<u8>, String> {
    Err("WinHTTP DoH is only supported on Windows".to_string())
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
