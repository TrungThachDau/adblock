use crate::rules::SharedRuleStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

pub const PIPE_NAME: &str = r"\\.\pipe\adblock-engine";

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
}

impl EngineState {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            is_paused: AtomicBool::new(false),
            stop_requested: AtomicBool::new(false),
            stats: EngineMetrics::default(),
            log_seq: AtomicU64::new(1),
        }
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn next_log_id(&self) -> u64 {
        self.log_seq.fetch_add(1, Ordering::Relaxed)
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
        let event = json!({
            "event": "query_log",
            "data": entry
        });
        let _ = self.sender.send(event.to_string());
    }

    pub fn send_stats(&self, stats: StatsData) {
        let event = json!({
            "event": "stats_update",
            "data": stats
        });
        let _ = self.sender.send(event.to_string());
    }
}

#[derive(Debug, Deserialize)]
struct RpcRequest {
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

pub async fn run_ipc_server(
    state: Arc<EngineState>,
    rules: SharedRuleStore,
    broadcaster: EventBroadcaster,
) {
    info!("Starting IPC server on Named Pipe: {}", PIPE_NAME);

    loop {
        if state.stop_requested.load(Ordering::Relaxed) {
            break;
        }

        let server = match ServerOptions::new()
            .first_pipe_instance(false)
            .create(PIPE_NAME)
        {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to create Named Pipe instance: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                continue;
            }
        };

        if let Err(e) = server.connect().await {
            warn!("Pipe client connect error: {}", e);
            continue;
        }

        let client_state = Arc::clone(&state);
        let client_rules = Arc::clone(&rules);
        let client_broadcaster = broadcaster.clone();

        tokio::spawn(async move {
            handle_client(server, client_state, client_rules, client_broadcaster).await;
        });
    }
}

async fn handle_client(
    stream: tokio::net::windows::named_pipe::NamedPipeServer,
    state: Arc<EngineState>,
    rules: SharedRuleStore,
    broadcaster: EventBroadcaster,
) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    let mut rx = broadcaster.subscribe();

    loop {
        tokio::select! {
            // Read incoming RPC commands
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
    let req: RpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(_) => {
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
        "engine.get_status" => {
            let is_paused = state.is_paused.load(Ordering::Relaxed);
            let state_str = if is_paused { "paused" } else { "running" };
            let rules_count = { rules.read().count() };
            let stats = state.stats.snapshot();

            json!({
                "id": req_id,
                "result": {
                    "state": state_str,
                    "uptime_seconds": state.uptime_seconds(),
                    "active_rules_count": rules_count,
                    "stats": stats
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
                "result": {
                    "cleared": true,
                    "active_rules_count": 0
                }
            }).to_string()
        }
        "stats.get" => {
            let stats = state.stats.snapshot();
            json!({
                "id": req_id,
                "result": stats
            }).to_string()
        }
        "stats.reset" => {
            state.stats.reset();
            let stats = state.stats.snapshot();
            broadcaster.send_stats(stats);
            json!({
                "id": req_id,
                "result": { "reset": true }
            }).to_string()
        }
        _ => {
            json!({
                "id": req_id,
                "error": { "code": -32601, "message": format!("Method not found: {}", method) }
            }).to_string()
        }
    }
}
