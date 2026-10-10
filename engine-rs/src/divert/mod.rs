pub mod ffi;

use crate::ipc::{EngineState, EventBroadcaster, QueryLogEntry};
use crate::packet::dns::{build_dns_nxdomain, parse_dns_question};
use crate::packet::tls::build_tcp_rst;
use crate::packet::{parse_tcp_details, tls, TcpFlowKey};
use crate::rules::SharedRuleStore;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use windivert::layer::NetworkLayer;
use windivert::prelude::*;
use windivert_sys::ChecksumFlags;

/// Narrow filter as specified: outbound and (udp.DstPort == 53 or tcp.DstPort == 443)
pub const FILTER_STRING: &str = "outbound and (udp.DstPort == 53 or tcp.DstPort == 443)";

/// Active TCP 443 flow tracker to ensure only the first data packet of a 443 flow is inspected
struct FlowTracker {
    allowed_flows: HashMap<TcpFlowKey, Instant>,
    last_cleanup: Instant,
}

impl FlowTracker {
    fn new() -> Self {
        Self {
            allowed_flows: HashMap::with_capacity(1024),
            last_cleanup: Instant::now(),
        }
    }

    fn is_allowed(&mut self, key: &TcpFlowKey) -> bool {
        self.allowed_flows.contains_key(key)
    }

    fn mark_allowed(&mut self, key: TcpFlowKey) {
        self.allowed_flows.insert(key, Instant::now());
        self.maybe_prune();
    }

    fn remove(&mut self, key: &TcpFlowKey) {
        self.allowed_flows.remove(key);
    }

    fn maybe_prune(&mut self) {
        if self.last_cleanup.elapsed() > Duration::from_secs(30) || self.allowed_flows.len() > 10000 {
            let now = Instant::now();
            self.allowed_flows.retain(|_, last_seen| now.duration_since(*last_seen) < Duration::from_secs(120));
            self.last_cleanup = now;
        }
    }
}

pub fn run_packet_loop(
    state: Arc<EngineState>,
    rules: SharedRuleStore,
    broadcaster: EventBroadcaster,
) {
    info!("Opening WinDivert capture on narrow filter: {}", FILTER_STRING);

    // Fail-open behavior: if WinDivert driver fails to open (e.g. non-elevated),
    // log cleanly and continue running in fail-open mode without blocking network traffic.
    let divert = match WinDivert::network(FILTER_STRING, 0, Default::default()) {
        Ok(handle) => {
            info!("WinDivert capture started successfully. Monitoring DNS and TLS 443 traffic.");
            Some(handle)
        }
        Err(err) => {
            warn!(
                "WinDivert driver failed to open (admin privileges required: {}). Running in fail-open mode without packet interception.",
                err
            );
            None
        }
    };

    if divert.is_none() {
        // Fail-open loop: stay alive, respond to IPC, wait for stop signal
        while !state.stop_requested.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(500));
        }
        info!("WinDivert fail-open worker exiting.");
        return;
    }

    let divert = divert.unwrap();
    let mut packet_buffer = vec![0u8; 65535];
    let mut flow_tracker = FlowTracker::new();

    while !state.stop_requested.load(Ordering::Relaxed) {
        let packet = match divert.recv(&mut packet_buffer) {
            Ok(p) => p,
            Err(WinDivertError::Recv(WinDivertRecvError::NoData)) => {
                // Handle shut down cleanly
                break;
            }
            Err(e) => {
                warn!("WinDivert receive error: {}", e);
                continue;
            }
        };

        // Fail-open: If the engine is paused, forward packet immediately
        if state.is_paused.load(Ordering::Relaxed) {
            let _ = divert.send(&packet);
            continue;
        }

        let raw = packet.data.as_ref();
        if raw.len() < 20 {
            // Malformed packet: fail-open forward
            let _ = divert.send(&packet);
            continue;
        }

        let version = raw[0] >> 4;
        let is_ipv6 = version == 6;
        let ip_hdr_len = if is_ipv6 { 40 } else { ((raw[0] & 0x0F) as usize) * 4 };
        let protocol = if is_ipv6 { raw[6] } else { raw[9] };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if protocol == 17 {
            // ==========================================
            // 1. DNS (UDP Port 53) Outbound Interception
            // ==========================================
            if raw.len() >= ip_hdr_len + 8 {
                let dst_port = u16::from_be_bytes([raw[ip_hdr_len + 2], raw[ip_hdr_len + 3]]);
                if dst_port == 53 {
                    state.stats.dns_queries.fetch_add(1, Ordering::Relaxed);
                    let dns_payload = &raw[ip_hdr_len + 8..];
                    let client_ip = if is_ipv6 {
                        "ipv6-client".to_string()
                    } else {
                        format!("{}.{}.{}.{}", raw[12], raw[13], raw[14], raw[15])
                    };

                    let qname = parse_dns_question(dns_payload).map(|q| q.qname);
                    let mut is_blocked = false;

                    if let Some(ref domain) = qname {
                        let matched_rule = { rules.read().check(domain) };
                        if let Some(rule) = matched_rule {
                            is_blocked = true;
                            state.stats.dns_blocked.fetch_add(1, Ordering::Relaxed);

                            // Synthesize inbound NXDOMAIN response
                            if let Some(nxdomain_bytes) = build_dns_nxdomain(raw, is_ipv6) {
                                let mut resp_packet = unsafe { WinDivertPacket::<NetworkLayer>::new(nxdomain_bytes) };
                                resp_packet.address = packet.address.clone();
                                resp_packet.address.set_outbound(false); // Inbound to client
                                let _ = resp_packet.recalculate_checksums(ChecksumFlags::new());
                                let _ = divert.send(&resp_packet);
                            }

                            // Original query dropped
                            let log_id = state.next_log_id().to_string();
                            let entry = QueryLogEntry {
                                id: log_id,
                                timestamp,
                                protocol: "DNS".to_string(),
                                client_ip: client_ip.clone(),
                                domain: domain.clone(),
                                action: "blocked".to_string(),
                                reason: format!("Rule match: {}", rule),
                            };
                            state.record_blocked(entry.clone());
                            broadcaster.send_log(entry);
                        }
                    }

                    if !is_blocked {
                        // Forward clean packet
                        let _ = divert.send(&packet);
                        if let Some(domain) = qname {
                            let log_id = state.next_log_id().to_string();
                            broadcaster.send_log(QueryLogEntry {
                                id: log_id,
                                timestamp,
                                protocol: "DNS".to_string(),
                                client_ip,
                                domain,
                                action: "allowed".to_string(),
                                reason: "Allowed".to_string(),
                            });
                        }
                    }
                    continue;
                }
            }

            // Fallback for unexpected UDP packets: fail-open forward
            let _ = divert.send(&packet);
        } else if protocol == 6 {
            // ==========================================
            // 2. HTTPS (TCP Port 443) Outbound Interception
            // Only inspect the first data packet of a 443 flow!
            // ==========================================
            let details = match parse_tcp_details(raw) {
                Some(d) if d.flow_key.dst_port == 443 => d,
                _ => {
                    // Non-443 or unparseable TCP: fail-open forward
                    let _ = divert.send(&packet);
                    continue;
                }
            };

            let flow_key = details.flow_key;
            let (fin, rst) = (details.flags & 0x01 != 0, details.flags & 0x04 != 0);

            // If connection is tearing down (FIN or RST), clean up flow tracker
            if fin || rst {
                flow_tracker.remove(&flow_key);
                let _ = divert.send(&packet);
                continue;
            }

            // If packet has no payload (SYN, pure ACK, window probe):
            // It is not a data packet; bypass immediately.
            if details.payload_len == 0 {
                let _ = divert.send(&packet);
                continue;
            }

            // If flow has already been inspected on its first data packet and permitted:
            // Bypass immediately without parsing TLS.
            if flow_tracker.is_allowed(&flow_key) {
                let _ = divert.send(&packet);
                continue;
            }

            // --- THIS IS THE FIRST DATA PACKET OF A 443 FLOW ---
            state.stats.tls_queries.fetch_add(1, Ordering::Relaxed);
            let payload = &raw[details.payload_offset..];
            let sni = tls::parse_tls_sni(payload);
            let client_ip = flow_key.src_ip.to_string();

            let mut is_blocked = false;
            if let Some(ref domain) = sni {
                let matched_rule = { rules.read().check(domain) };
                if let Some(rule) = matched_rule {
                    is_blocked = true;
                    state.stats.tls_blocked.fetch_add(1, Ordering::Relaxed);

                    // Synthesize inbound TCP RST | ACK to client socket
                    if let Some(rst_bytes) = build_tcp_rst(raw, details.is_ipv6) {
                        let mut resp_packet = unsafe { WinDivertPacket::<NetworkLayer>::new(rst_bytes) };
                        resp_packet.address = packet.address.clone();
                        resp_packet.address.set_outbound(false); // Inbound
                        let _ = resp_packet.recalculate_checksums(ChecksumFlags::new());
                        let _ = divert.send(&resp_packet);
                    }

                    // Original ClientHello packet dropped
                    let log_id = state.next_log_id().to_string();
                    let entry = QueryLogEntry {
                        id: log_id,
                        timestamp,
                        protocol: "TLS".to_string(),
                        client_ip: client_ip.clone(),
                        domain: domain.clone(),
                        action: "blocked".to_string(),
                        reason: format!("Rule match: {}", rule),
                    };
                    state.record_blocked(entry.clone());
                    broadcaster.send_log(entry);
                }
            }

            if !is_blocked {
                // First data packet is allowed (clean domain or non-SNI TLS payload)
                // Mark flow as allowed so subsequent packets in this stream bypass inspection!
                flow_tracker.mark_allowed(flow_key);
                let _ = divert.send(&packet);

                if let Some(domain) = sni {
                    let log_id = state.next_log_id().to_string();
                    broadcaster.send_log(QueryLogEntry {
                        id: log_id,
                        timestamp,
                        protocol: "TLS".to_string(),
                        client_ip,
                        domain,
                        action: "allowed".to_string(),
                        reason: "Allowed".to_string(),
                    });
                }
            }
        } else {
            // Any other packet: fail-open forward
            let _ = divert.send(&packet);
        }
    }

    info!("WinDivert packet loop terminated gracefully.");
}
