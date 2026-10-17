use crate::doh::{DohResolver, ParsedDohUrl, PrivateDnsConfig};
use crate::rules::SharedRuleStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::BufRead;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

pub const PIPE_NAME_APP: &str = r"\\.\pipe\adblock.engine";
pub const PIPE_NAME_LEGACY: &str = r"\\.\pipe\adblock-engine";

#[derive(Debug, Default)]
pub struct EngineMetrics {
    pub dns_queries: AtomicU64,
    pub dns_blocked: AtomicU64,
    pub tls_queries: AtomicU64,
    pub tls_blocked: AtomicU64,
    pub quic_dropped: AtomicU64,
}

impl EngineMetrics {
    pub fn snapshot(&self) -> StatsData {
        StatsData {
            dns_queries: self.dns_queries.load(Ordering::Relaxed),
            dns_blocked: self.dns_blocked.load(Ordering::Relaxed),
            tls_queries: self.tls_queries.load(Ordering::Relaxed),
            tls_blocked: self.tls_blocked.load(Ordering::Relaxed),
            quic_dropped: self.quic_dropped.load(Ordering::Relaxed),
        }
    }

    pub fn reset(&self) {
        self.dns_queries.store(0, Ordering::Relaxed);
        self.dns_blocked.store(0, Ordering::Relaxed);
        self.tls_queries.store(0, Ordering::Relaxed);
        self.tls_blocked.store(0, Ordering::Relaxed);
        self.quic_dropped.store(0, Ordering::Relaxed);
    }
}

pub struct EngineState {
    pub start_time: Instant,
    pub is_paused: AtomicBool,
    pub stop_requested: AtomicBool,
    pub stats: EngineMetrics,
    pub log_seq: AtomicU64,
    pub recent_blocked: parking_lot::RwLock<VecDeque<QueryLogEntry>>,
    pub configured_lists: parking_lot::RwLock<Vec<String>>,
    pub configured_allowlist: parking_lot::RwLock<Vec<String>>,
    pub private_dns: parking_lot::RwLock<(PrivateDnsConfig, Option<ParsedDohUrl>)>,
    pub doh_resolver: Arc<DohResolver>,
}

impl EngineState {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            is_paused: AtomicBool::new(false),
            stop_requested: AtomicBool::new(false),
            stats: EngineMetrics::default(),
            log_seq: AtomicU64::new(1),
            recent_blocked: parking_lot::RwLock::new(VecDeque::with_capacity(500)),
            configured_lists: parking_lot::RwLock::new(Vec::new()),
            configured_allowlist: parking_lot::RwLock::new(Vec::new()),
            private_dns: parking_lot::RwLock::new((PrivateDnsConfig::default(), None)),
            doh_resolver: Arc::new(DohResolver::new()),
        }
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn next_log_id(&self) -> u64 {
        self.log_seq.fetch_add(1, Ordering::Relaxed)
    }

    pub fn record_blocked(&self, entry: QueryLogEntry) {
        let mut recent = self.recent_blocked.write();
        if recent.len() >= 500 {
            recent.pop_back();
        }
        recent.push_front(entry);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsData {
    pub dns_queries: u64,
    pub dns_blocked: u64,
    pub tls_queries: u64,
    pub tls_blocked: u64,
    pub quic_dropped: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogEntry {
    pub id: String,
    pub timestamp: i64,
    pub protocol: String,
    pub client_ip: String,
    pub domain: String,
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EngineEvent {
    QueryLog { event: String, data: QueryLogEntry },
    StatsUpdate { event: String, data: StatsData },
}

#[derive(Clone)]
pub struct EventBroadcaster {
    sender: broadcast::Sender<String>,
}

impl EventBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.sender.subscribe()
    }

    pub fn send_log(&self, entry: QueryLogEntry) {
        let event = EngineEvent::QueryLog {
            event: "query_log".to_string(),
            data: entry,
        };
        if let Ok(json) = serde_json::to_string(&event) {
            let _ = self.sender.send(json);
        }
    }

    pub fn send_stats(&self, stats: StatsData) {
        let event = EngineEvent::StatsUpdate {
            event: "stats_update".to_string(),
            data: stats,
        };
        if let Ok(json) = serde_json::to_string(&event) {
            let _ = self.sender.send(json);
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RawRpcRequest {
    id: Value,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    cmd: Option<String>,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Clone)]
pub struct RpcRequest {
    pub id: Value,
    pub method: String,
    pub params: Value,
}

impl RpcRequest {
    // The GUI sends both `cmd` and `method`; a serde alias would reject that as a duplicate field.
    pub fn parse(line: &str) -> Option<Self> {
        let raw: RawRpcRequest = serde_json::from_str(line).ok()?;
        Some(Self {
            id: raw.id,
            method: raw.method.or(raw.cmd)?,
            params: raw.params,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{handle_request_line, EngineState, EventBroadcaster, RpcRequest};
    use crate::rules::RuleStore;
    use std::sync::Arc;

    #[test]
    fn parses_request_with_both_cmd_and_method() {
        let req = RpcRequest::parse(r#"{"id":"1","cmd":"get_status","method":"get_status","params":{}}"#)
            .expect("request with both keys must parse");
        assert_eq!(req.method, "get_status");
    }

    #[test]
    fn parses_request_with_only_cmd() {
        let req = RpcRequest::parse(r#"{"id":1,"cmd":"engine.ping"}"#).unwrap();
        assert_eq!(req.method, "engine.ping");
    }

    #[tokio::test]
    async fn set_and_get_private_dns_rpc() {
        let state = Arc::new(EngineState::new());
        let rules = Arc::new(parking_lot::RwLock::new(RuleStore::new()));
        let broadcaster = EventBroadcaster::new(16);

        let resp = handle_request_line(
            r#"{"id":1,"cmd":"set_private_dns","params":{"enabled":true,"url":"https://cloudflare-dns.com/dns-query"}}"#,
            &state,
            &rules,
            &broadcaster,
        )
        .await;
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["enabled"], true);
        assert_eq!(v["result"]["url"], "https://cloudflare-dns.com/dns-query");

        let get_resp = handle_request_line(
            r#"{"id":2,"cmd":"get_private_dns","params":{}}"#,
            &state,
            &rules,
            &broadcaster,
        )
        .await;
        let gv: serde_json::Value = serde_json::from_str(&get_resp).unwrap();
        assert_eq!(gv["result"]["enabled"], true);
        assert_eq!(gv["result"]["url"], "https://cloudflare-dns.com/dns-query");

        // Reject invalid URL
        let bad_resp = handle_request_line(
            r#"{"id":3,"cmd":"set_private_dns","params":{"enabled":true,"url":"not-a-url"}}"#,
            &state,
            &rules,
            &broadcaster,
        )
        .await;
        let bv: serde_json::Value = serde_json::from_str(&bad_resp).unwrap();
        assert!(bv.get("error").is_some());
    }
}

pub fn get_process_ram() -> (u64, f64) {
    #[cfg(windows)]
    unsafe {
        use std::mem::size_of;
        use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        let handle = GetCurrentProcess();
        if K32GetProcessMemoryInfo(handle, &mut counters, size_of::<PROCESS_MEMORY_COUNTERS>() as u32) != 0 {
            let bytes = counters.WorkingSetSize as u64;
            let mb = (bytes as f64) / (1024.0 * 1024.0);
            return (bytes, (mb * 100.0).round() / 100.0);
        }
    }
    (0, 0.0)
}

pub async fn run_ipc_server(
    state: Arc<EngineState>,
    rules: SharedRuleStore,
    broadcaster: EventBroadcaster,
) {
    info!("Starting IPC server on Named Pipes: {} and {}", PIPE_NAME_APP, PIPE_NAME_LEGACY);

    let state1 = Arc::clone(&state);
    let rules1 = Arc::clone(&rules);
    let broadcaster1 = broadcaster.clone();
    tokio::spawn(async move {
        listen_pipe(PIPE_NAME_APP, state1, rules1, broadcaster1).await;
    });

    listen_pipe(PIPE_NAME_LEGACY, state, rules, broadcaster).await;
}

async fn listen_pipe(
    pipe_name: &str,
    state: Arc<EngineState>,
    rules: SharedRuleStore,
    broadcaster: EventBroadcaster,
) {
    let mut server_options = ServerOptions::new();
    server_options.first_pipe_instance(false);

    loop {
        match create_pipe_server(&server_options, pipe_name) {
            Ok(server) => {
                let state_clone = Arc::clone(&state);
                let rules_clone = Arc::clone(&rules);
                let broadcaster_clone = broadcaster.clone();

                match server.connect().await {
                    Ok(()) => {
                        tokio::spawn(async move {
                            handle_client(server, state_clone, rules_clone, broadcaster_clone).await;
                        });
                    }
                    Err(e) => {
                        warn!("Pipe client connect error on {}: {}", pipe_name, e);
                    }
                }
            }
            Err(e) => {
                error!("Failed to create named pipe {}: {}", pipe_name, e);
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
    }
}

fn create_pipe_server(
    options: &ServerOptions,
    pipe_name: &str,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::ffi::c_void;
    use std::ptr;
    use windows_sys::Win32::Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SECURITY_ATTRIBUTES,
    };

    let sddl: Vec<u16> = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut security_descriptor: *mut c_void = ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut security_descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor,
        bInheritHandle: 0,
    };
    let attributes_ptr = (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>();
    let result = unsafe { options.create_with_security_attributes_raw(pipe_name, attributes_ptr) };
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(security_descriptor);
    }
    result
}

async fn handle_client(
    stream: tokio::net::windows::named_pipe::NamedPipeServer,
    state: Arc<EngineState>,
    rules: SharedRuleStore,
    broadcaster: EventBroadcaster,
) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = TokioBufReader::new(reader).lines();
    let mut rx = broadcaster.subscribe();

    loop {
        tokio::select! {
            line_result = lines.next_line() => {
                match line_result {
                    Ok(Some(line)) => {
                        let response_str = handle_request_line(&line, &state, &rules, &broadcaster).await;
                        if writer.write_all(format!("{}\n", response_str).as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    _ => break, // Client disconnected or error
                }
            }
            // Push events to connected client
            event_result = rx.recv() => {
                if let Ok(event_json) = event_result {
                    if writer.write_all(format!("{}\n", event_json).as_bytes()).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
}

async fn handle_request_line(
    line: &str,
    state: &Arc<EngineState>,
    rules: &SharedRuleStore,
    broadcaster: &EventBroadcaster,
) -> String {
    let req: RpcRequest = match RpcRequest::parse(line) {
        Some(r) => r,
        None => {
            return json!({
                "id": null,
                "error": { "code": -32700, "message": "Parse error" }
            }).to_string();
        }
    };

    let req_id = req.id;
    let method = req.method.as_str();
    let params = req.params;

    match method {
        "start" | "engine.start" => {
            state.is_paused.store(false, Ordering::Relaxed);
            json!({
                "id": req_id,
                "result": { "status": "ok", "state": "running" }
            }).to_string()
        }
        "stop" | "engine.stop" => {
            state.is_paused.store(true, Ordering::Relaxed);
            json!({
                "id": req_id,
                "result": { "status": "ok", "state": "stopped" }
            }).to_string()
        }
        "get_status" | "engine.get_status" => {
            let is_paused = state.is_paused.load(Ordering::Relaxed);
            let state_str = if is_paused { "stopped" } else { "running" };
            let (rules_count, allow_count) = {
                let r = rules.read();
                (r.count(), r.allowlist_count())
            };
            let lists_count = state.configured_lists.read().len();
            let stats = state.stats.snapshot();
            let dns_cfg = state.private_dns.read().0.clone();

            json!({
                "id": req_id,
                "result": {
                    "name": "engine-rs",
                    "version": "1.0.0",
                    "state": state_str,
                    "active_rules_count": rules_count,
                    "allowlist_count": allow_count,
                    "lists_count": lists_count,
                    "private_dns_enabled": dns_cfg.enabled,
                    "private_dns_url": dns_cfg.url,
                    "uptime_seconds": state.uptime_seconds(),
                    "stats": stats
                }
            }).to_string()
        }
        "set_lists" => {
            let paths: Vec<String> = params
                .get("paths")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let mut loaded_lists = 0;
            let mut failed_paths = Vec::new();

            {
                let mut r = rules.write();
                r.clear();

                for path_str in &paths {
                    let path = Path::new(path_str);
                    if path.exists() {
                        if r.load_file(path).is_ok() {
                            loaded_lists += 1;
                        } else {
                            failed_paths.push(path_str.clone());
                        }
                    } else {
                        failed_paths.push(path_str.clone());
                    }
                }

                // Re-apply custom allowlist
                let allow = state.configured_allowlist.read();
                r.add_allowlist(&allow);
            }

            *state.configured_lists.write() = paths;
            let active_rules_count = rules.read().count();

            json!({
                "id": req_id,
                "result": {
                    "status": "ok",
                    "loaded_lists": loaded_lists,
                    "active_rules_count": active_rules_count,
                    "failed_paths": failed_paths
                }
            }).to_string()
        }
        "set_allowlist" => {
            let allow_rules: Vec<String> = params
                .get("rules")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let paths: Vec<String> = params
                .get("paths")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let mut all_allow = allow_rules;
            for p_str in paths {
                let p = Path::new(&p_str);
                if p.exists() {
                    if let Ok(file) = std::fs::File::open(p) {
                        let reader = std::io::BufReader::new(file);
                        for line in reader.lines().map_while(Result::ok) {
                            all_allow.push(line);
                        }
                    }
                }
            }

            let allowlist_count = {
                let mut r = rules.write();
                r.add_allowlist(&all_allow);
                r.allowlist_count()
            };

            *state.configured_allowlist.write() = all_allow;

            json!({
                "id": req_id,
                "result": {
                    "status": "ok",
                    "allowlist_count": allowlist_count
                }
            }).to_string()
        }
        "reload" => {
            let lists = state.configured_lists.read().clone();
            let allow = state.configured_allowlist.read().clone();

            let (rules_count, allow_count) = {
                let mut r = rules.write();
                r.clear();
                for path_str in &lists {
                    let p = Path::new(path_str);
                    if p.exists() {
                        let _ = r.load_file(p);
                    }
                }
                r.add_allowlist(&allow);
                (r.count(), r.allowlist_count())
            };

            json!({
                "id": req_id,
                "result": {
                    "status": "ok",
                    "active_rules_count": rules_count,
                    "allowlist_count": allow_count
                }
            }).to_string()
        }
        "get_stats" | "stats.get" => {
            let stats = state.stats.snapshot();
            let (ram_bytes, ram_mb) = get_process_ram();
            let allowed_count = (stats.dns_queries + stats.tls_queries)
                .saturating_sub(stats.dns_blocked + stats.tls_blocked);
            let blocked_count = stats.dns_blocked + stats.tls_blocked + stats.quic_dropped;

            json!({
                "id": req_id,
                "result": {
                    "allowed_count": allowed_count,
                    "blocked_count": blocked_count,
                    "dns_queries": stats.dns_queries,
                    "dns_blocked": stats.dns_blocked,
                    "tls_queries": stats.tls_queries,
                    "tls_blocked": stats.tls_blocked,
                    "quic_dropped": stats.quic_dropped,
                    "uptime_seconds": state.uptime_seconds(),
                    "ram_bytes": ram_bytes,
                    "ram_mb": ram_mb
                }
            }).to_string()
        }
        "get_recent_blocked" => {
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            let items: Vec<QueryLogEntry> = {
                let r = state.recent_blocked.read();
                r.iter().take(limit).cloned().collect()
            };

            json!({
                "id": req_id,
                "result": {
                    "items": items
                }
            }).to_string()
        }
        "engine.ping" => {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            json!({
                "id": req_id,
                "result": {
                    "status": "ok",
                    "timestamp": timestamp
                }
            }).to_string()
        }
        "engine.set_state" => {
            let target_state = params.get("state").and_then(|v| v.as_str()).unwrap_or("");
            if target_state == "paused" {
                state.is_paused.store(true, Ordering::Relaxed);
                json!({ "id": req_id, "result": { "state": "paused" } }).to_string()
            } else if target_state == "running" {
                state.is_paused.store(false, Ordering::Relaxed);
                json!({ "id": req_id, "result": { "state": "running" } }).to_string()
            } else {
                json!({
                    "id": req_id,
                    "error": { "code": -32602, "message": "Invalid state parameter. Use 'running' or 'paused'." }
                }).to_string()
            }
        }
        "rules.list" => {
            let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
            let (total, list) = { rules.read().list(offset, limit) };

            json!({
                "id": req_id,
                "result": {
                    "total": total,
                    "offset": offset,
                    "limit": limit,
                    "rules": list
                }
            }).to_string()
        }
        "rules.add" => {
            let to_add: Vec<String> = params
                .get("rules")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let (added, count) = {
                let mut r = rules.write();
                let added = r.add(&to_add);
                (added, r.count())
            };

            json!({
                "id": req_id,
                "result": {
                    "added": added,
                    "active_rules_count": count
                }
            }).to_string()
        }
        "rules.remove" => {
            let to_remove: Vec<String> = params
                .get("rules")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let (removed, count) = {
                let mut r = rules.write();
                let removed = r.remove(&to_remove);
                (removed, r.count())
            };

            json!({
                "id": req_id,
                "result": {
                    "removed": removed,
                    "active_rules_count": count
                }
            }).to_string()
        }
        "rules.clear" => {
            {
                let mut r = rules.write();
                r.clear();
            }
            json!({
                "id": req_id,
                "result": { "status": "ok", "active_rules_count": 0 }
            }).to_string()
        }
        "stats.reset" => {
            state.stats.reset();
            let stats = state.stats.snapshot();
            broadcaster.send_stats(stats.clone());
            json!({
                "id": req_id,
                "result": { "status": "ok", "reset": true }
            }).to_string()
        }
        "set_private_dns" | "dns.set_config" => {
            let enabled = params
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let url = params
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();

            let parsed_url = if !url.is_empty() {
                match ParsedDohUrl::parse(&url) {
                    Ok(p) => Some(p),
                    Err(err) => {
                        return json!({
                            "id": req_id,
                            "error": { "code": -32602, "message": err }
                        })
                        .to_string();
                    }
                }
            } else if enabled {
                return json!({
                    "id": req_id,
                    "error": { "code": -32602, "message": "Private DNS URL cannot be empty when enabled." }
                })
                .to_string();
            } else {
                None
            };

            let normalized_url = parsed_url
                .as_ref()
                .map(|p| p.raw_url.clone())
                .unwrap_or(url);

            state.doh_resolver.clear_cache();
            *state.private_dns.write() = (
                PrivateDnsConfig {
                    enabled,
                    url: normalized_url.clone(),
                },
                parsed_url,
            );

            json!({
                "id": req_id,
                "result": {
                    "status": "ok",
                    "enabled": enabled,
                    "url": normalized_url
                }
            })
            .to_string()
        }
        "get_private_dns" | "dns.get_config" => {
            let cfg = state.private_dns.read().0.clone();
            json!({
                "id": req_id,
                "result": {
                    "enabled": cfg.enabled,
                    "url": cfg.url
                }
            })
            .to_string()
        }
        "test_private_dns" | "dns.test" => {
            let url = params
                .get("url")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| state.private_dns.read().0.url.clone());

            let parsed = match ParsedDohUrl::parse(&url) {
                Ok(p) => p,
                Err(err) => {
                    return json!({
                        "id": req_id,
                        "error": { "code": -32602, "message": err }
                    })
                    .to_string();
                }
            };

            let resolver = Arc::clone(&state.doh_resolver);
            let test_res = tokio::task::spawn_blocking(move || resolver.test_endpoint(&parsed)).await;
            match test_res {
                Ok(Ok(latency_ms)) => json!({
                    "id": req_id,
                    "result": {
                        "status": "ok",
                        "latency_ms": latency_ms,
                        "host": url
                    }
                })
                .to_string(),
                Ok(Err(err)) => json!({
                    "id": req_id,
                    "error": { "code": -32000, "message": err }
                })
                .to_string(),
                Err(err) => json!({
                    "id": req_id,
                    "error": { "code": -32603, "message": format!("Internal task error: {}", err) }
                })
                .to_string(),
            }
        }
        _ => {
            json!({
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": format!("Method '{}' not found", method)
                }
            }).to_string()
        }
    }
}
