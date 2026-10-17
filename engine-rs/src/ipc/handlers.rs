use super::models::{EngineState, EventBroadcaster, QueryLogEntry, RpcRequest};
use crate::doh::{ParsedDohUrl, PrivateDnsConfig};
use crate::rules::SharedRuleStore;
use serde_json::json;
use std::io::BufRead;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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

pub async fn handle_request_line(
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
            broadcaster.send_stats(stats);
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

#[cfg(test)]
mod tests {
    use super::handle_request_line;
    use crate::ipc::models::{EngineState, EventBroadcaster, RpcRequest};
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
