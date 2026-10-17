use crate::doh::{DohResolver, ParsedDohUrl, PrivateDnsConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;

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

impl Default for EngineState {
    fn default() -> Self {
        Self::new()
    }
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
