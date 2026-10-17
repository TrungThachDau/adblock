use super::models::{FlowTracker, FILTER_STRING};
use crate::ipc::{EngineState, EventBroadcaster, QueryLogEntry};
use crate::packet::dns::{build_dns_nxdomain, build_dns_response, parse_dns_question};
use crate::packet::tls::build_tcp_rst;
use crate::packet::{parse_tcp_details, tls};
use crate::rules::SharedRuleStore;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use windivert::layer::NetworkLayer;
use windivert::prelude::*;
use windivert_sys::ChecksumFlags;

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

    let divert = Arc::new(divert.unwrap());
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

                    let parsed_question = parse_dns_question(dns_payload);
                    let qname = parsed_question.as_ref().map(|q| q.qname.clone());
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
                        let active_doh = {
                            let guard = state.private_dns.read();
                            if guard.0.enabled {
                                guard.1.clone()
                            } else {
                                None
                            }
                        };

                        // Forward via Private DNS (DoH) if enabled and not querying the DoH bootstrap host itself
                        if let (Some(doh_target), Some(q)) = (active_doh, parsed_question) {
                            if !q.qname.eq_ignore_ascii_case(&doh_target.host) {
                                let raw_owned = raw.to_vec();
                                let dns_payload_owned = dns_payload.to_vec();
                                let addr_owned = packet.address.clone();
                                let divert_clone = Arc::clone(&divert);
                                let state_clone = Arc::clone(&state);
                                let broadcaster_clone = broadcaster.clone();

                                std::thread::spawn(move || {
                                    match state_clone.doh_resolver.resolve(
                                        &doh_target,
                                        &q.qname,
                                        q.qtype,
                                        q.qclass,
                                        &dns_payload_owned,
                                    ) {
                                        Ok(doh_wire) => {
                                            if let Some(resp_bytes) =
                                                build_dns_response(&raw_owned, &doh_wire, is_ipv6)
                                            {
                                                let mut resp_packet = unsafe {
                                                    WinDivertPacket::<NetworkLayer>::new(resp_bytes)
                                                };
                                                resp_packet.address = addr_owned;
                                                resp_packet.address.set_outbound(false);
                                                let _ = resp_packet
                                                    .recalculate_checksums(ChecksumFlags::new());
                                                let _ = divert_clone.send(&resp_packet);
                                            }
                                            let log_id = state_clone.next_log_id().to_string();
                                            broadcaster_clone.send_log(QueryLogEntry {
                                                id: log_id,
                                                timestamp,
                                                protocol: "DoH".to_string(),
                                                client_ip,
                                                domain: q.qname,
                                                action: "allowed".to_string(),
                                                reason: format!("Private DNS ({})", doh_target.host),
                                            });
                                        }
                                        Err(err) => {
                                            warn!("Private DNS resolution failed for {}: {}", q.qname, err);
                                        }
                                    }
                                });
                                continue;
                            }
                        }

                        // Forward clean packet directly (standard DNS or DoH bootstrap host)
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

            // Recheck established flows so rules added after connection setup take effect.
            if let Some(existing_domain) = flow_tracker.domain(&flow_key) {
                if let Some(domain) = existing_domain {
                    let matched_rule = { rules.read().check(&domain) };
                    if let Some(rule) = matched_rule {
                        let first_block = flow_tracker.mark_blocked(&flow_key);
                        if let Some(rst_bytes) = build_tcp_rst(raw, details.is_ipv6) {
                            let mut resp_packet = unsafe { WinDivertPacket::<NetworkLayer>::new(rst_bytes) };
                            resp_packet.address = packet.address.clone();
                            resp_packet.address.set_outbound(false);
                            let _ = resp_packet.recalculate_checksums(ChecksumFlags::new());
                            let _ = divert.send(&resp_packet);
                        }

                        if first_block {
                            state.stats.tls_blocked.fetch_add(1, Ordering::Relaxed);
                            let log_id = state.next_log_id().to_string();
                            let entry = QueryLogEntry {
                                id: log_id,
                                timestamp,
                                protocol: "TLS".to_string(),
                                client_ip: flow_key.src_ip.to_string(),
                                domain,
                                action: "blocked".to_string(),
                                reason: format!("Rule match: {} (active connection terminated)", rule),
                            };
                            state.record_blocked(entry.clone());
                            broadcaster.send_log(entry);
                        }
                        continue;
                    }
                }

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
                flow_tracker.mark_allowed(flow_key, sni.clone());
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
