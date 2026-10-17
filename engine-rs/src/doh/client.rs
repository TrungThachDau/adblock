use super::models::ParsedDohUrl;
use std::ffi::c_void;
use std::ptr;

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
