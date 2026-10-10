pub mod ffi;

use ffi::{WinDivertAddress, WinDivertApi, WINDIVERT_LAYER_NETWORK, WINDIVERT_PRIORITY_NORMAL};
use crate::packet::dns::build_dns_nxdomain;
use crate::packet::tls::build_tcp_rst;
use crate::packet::{inspect_packet, PacketProtocol};
use crate::rules::SharedRuleStore;
use crate::ipc::{EngineState, EventBroadcaster, QueryLogEntry};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

pub const FILTER_STRING: &str =
    "outbound and !loopback and (udp.DstPort == 53 or (tcp.DstPort == 443 and tcp.PayloadLength > 0) or udp.DstPort == 443)";

pub fn run_packet_loop(
    state: Arc<EngineState>,
    rules: SharedRuleStore,
    broadcaster: EventBroadcaster,
) {
    let api = match WinDivertApi::load() {
        Ok(api) => api,
        Err(err) => {
            error!("Cannot initialize WinDivert: {}", err);
            warn!("Engine running in test/mock mode without packet capture driver.");
            return;
        }
    };

    let handle = match api.open(FILTER_STRING, WINDIVERT_LAYER_NETWORK, WINDIVERT_PRIORITY_NORMAL, 0) {
        Ok(h) => {
            info!("WinDivert initialized successfully with filter: {}", FILTER_STRING);
            h
        }
        Err(err) => {
            error!("Failed to open WinDivert handle: {}. Are you running as Administrator?", err);
            return;
        }
    };

    let mut packet_buffer = vec![0u8; 65535];
    let mut addr = WinDivertAddress::default();

    while !state.stop_requested.load(Ordering::Relaxed) {
        let recv_len = match api.recv(handle, &mut packet_buffer, &mut addr) {
            Ok(len) => len,
            Err(e) => {
                warn!("WinDivertRecv error: {}", e);
                continue;
            }
        };

        let packet = &packet_buffer[..recv_len];

        // If paused, pass packet through untouched
        if state.is_paused.load(Ordering::Relaxed) {
            let _ = api.send(handle, packet, &addr);
            continue;
        }

        let is_ipv6 = addr.is_ipv6();

        // Inspect packet
        let info = match inspect_packet(packet) {
            Some(info) => info,
            None => {
                // Not a packet we care to modify, reinject
                let _ = api.send(handle, packet, &addr);
                continue;
            }
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        match info.protocol {
            PacketProtocol::Dns => {
                state.stats.dns_queries.fetch_add(1, Ordering::Relaxed);
                let domain = info.domain.unwrap_or_default();
                let matched_rule = {
                    let r = rules.read();
                    r.check(&domain)
                };

                if let Some(rule) = matched_rule {
                    // Blocked! Synthesize NXDOMAIN
                    state.stats.dns_blocked.fetch_add(1, Ordering::Relaxed);
                    if let Some(mut nxdomain) = build_dns_nxdomain(packet, is_ipv6) {
                        let mut resp_addr = addr;
                        resp_addr.set_outbound(false); // Inbound direction
                        api.calc_checksums(&mut nxdomain, &resp_addr, 0);
                        let _ = api.send(handle, &nxdomain, &resp_addr);
                    }
                    // Original query is DROPPED

                    let log_id = state.next_log_id().to_string();
                    broadcaster.send_log(QueryLogEntry {
                        id: log_id,
                        timestamp,
                        protocol: "DNS".to_string(),
                        client_ip: info.client_ip,
                        domain,
                        action: "blocked".to_string(),
                        reason: format!("Rule match: {}", rule),
                    });
                } else {
                    // Allowed
                    let _ = api.send(handle, packet, &addr);
                    let log_id = state.next_log_id().to_string();
                    broadcaster.send_log(QueryLogEntry {
                        id: log_id,
                        timestamp,
                        protocol: "DNS".to_string(),
                        client_ip: info.client_ip,
                        domain,
                        action: "allowed".to_string(),
                        reason: "Allowed".to_string(),
                    });
                }
            }
            PacketProtocol::Tls => {
                state.stats.tls_queries.fetch_add(1, Ordering::Relaxed);
                if let Some(sni) = info.domain {
                    let matched_rule = {
                        let r = rules.read();
                        r.check(&sni)
                    };

                    if let Some(rule) = matched_rule {
                        // Blocked! Synthesize TCP RST to client
                        state.stats.tls_blocked.fetch_add(1, Ordering::Relaxed);
                        if let Some(mut rst) = build_tcp_rst(packet, is_ipv6) {
                            let mut resp_addr = addr;
                            resp_addr.set_outbound(false); // Inbound direction to client
                            api.calc_checksums(&mut rst, &resp_addr, 0);
                            let _ = api.send(handle, &rst, &resp_addr);
                        }
                        // Original ClientHello is DROPPED

                        let log_id = state.next_log_id().to_string();
                        broadcaster.send_log(QueryLogEntry {
                            id: log_id,
                            timestamp,
                            protocol: "TLS".to_string(),
                            client_ip: info.client_ip,
                            domain: sni,
                            action: "blocked".to_string(),
                            reason: format!("Rule match: {}", rule),
                        });
                    } else {
                        // Allowed
                        let _ = api.send(handle, packet, &addr);
                        let log_id = state.next_log_id().to_string();
                        broadcaster.send_log(QueryLogEntry {
                            id: log_id,
                            timestamp,
                            protocol: "TLS".to_string(),
                            client_ip: info.client_ip,
                            domain: sni,
                            action: "allowed".to_string(),
                            reason: "Allowed".to_string(),
                        });
                    }
                } else {
                    // Not a ClientHello or could not parse SNI, reinject untouched
                    let _ = api.send(handle, packet, &addr);
                }
            }
            PacketProtocol::Quic => {
                // Drop UDP 443 to force fallback to TCP 443
                state.stats.quic_dropped.fetch_add(1, Ordering::Relaxed);
                let log_id = state.next_log_id().to_string();
                broadcaster.send_log(QueryLogEntry {
                    id: log_id,
                    timestamp,
                    protocol: "QUIC".to_string(),
                    client_ip: info.client_ip,
                    domain: "[quic-port-443]".to_string(),
                    action: "dropped".to_string(),
                    reason: "QUIC dropped to force TCP fallback".to_string(),
                });
                // Original packet is DROPPED
            }
            PacketProtocol::Other => {
                let _ = api.send(handle, packet, &addr);
            }
        }
    }

    api.close(handle);
    info!("WinDivert packet loop terminated.");
}
