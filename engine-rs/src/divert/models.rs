use crate::packet::TcpFlowKey;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Narrow filter as specified: outbound and (udp.DstPort == 53 or tcp.DstPort == 443)
pub const FILTER_STRING: &str = "outbound and (udp.DstPort == 53 or tcp.DstPort == 443)";

/// Active TCP 443 flow tracker retaining SNI so new rules can terminate existing flows.
pub(crate) struct AllowedFlow {
    pub domain: Option<String>,
    pub last_seen: Instant,
    pub blocked: bool,
}

pub(crate) struct FlowTracker {
    allowed_flows: HashMap<TcpFlowKey, AllowedFlow>,
    last_cleanup: Instant,
}

impl FlowTracker {
    pub(crate) fn new() -> Self {
        Self {
            allowed_flows: HashMap::with_capacity(1024),
            last_cleanup: Instant::now(),
        }
    }

    pub(crate) fn domain(&mut self, key: &TcpFlowKey) -> Option<Option<String>> {
        self.allowed_flows.get_mut(key).map(|flow| {
            flow.last_seen = Instant::now();
            flow.domain.clone()
        })
    }

    pub(crate) fn mark_allowed(&mut self, key: TcpFlowKey, domain: Option<String>) {
        self.allowed_flows.insert(
            key,
            AllowedFlow {
                domain,
                last_seen: Instant::now(),
                blocked: false,
            },
        );
        self.maybe_prune();
    }

    pub(crate) fn mark_blocked(&mut self, key: &TcpFlowKey) -> bool {
        let Some(flow) = self.allowed_flows.get_mut(key) else {
            return false;
        };
        if flow.blocked {
            return false;
        }
        flow.blocked = true;
        true
    }

    pub(crate) fn remove(&mut self, key: &TcpFlowKey) {
        self.allowed_flows.remove(key);
    }

    fn maybe_prune(&mut self) {
        if self.last_cleanup.elapsed() > Duration::from_secs(30) || self.allowed_flows.len() > 10000
        {
            let now = Instant::now();
            self.allowed_flows
                .retain(|_, flow| now.duration_since(flow.last_seen) < Duration::from_secs(120));
            self.last_cleanup = now;
        }
    }
}
