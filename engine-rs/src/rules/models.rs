use parking_lot::RwLock;
use std::collections::HashSet;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedRule {
    Block(String),
    Allow(String),
}

/// Keys are already FNV-1a hashes, so the set must not hash them again.
#[derive(Debug, Default, Clone, Copy)]
pub struct IdentityHasher(u64);

impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 << 8) | u64::from(b);
        }
    }

    fn write_u64(&mut self, i: u64) {
        self.0 = i;
    }
}

pub(crate) type HashSet64 = HashSet<u64, BuildHasherDefault<IdentityHasher>>;

/// FNV-1a 64-bit; must match engine-cs so both engines agree on rule identity.
pub(crate) fn hash_domain(domain: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in domain.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Normalized domains are ASCII, so one byte per char in a single buffer avoids a heap allocation per rule.
#[derive(Debug, Clone, Default)]
pub(crate) struct DomainList {
    buf: Vec<u8>,
    ends: Vec<u32>,
}

impl DomainList {
    pub(crate) fn len(&self) -> usize {
        self.ends.len()
    }

    pub(crate) fn push(&mut self, domain: &str) {
        self.buf.extend_from_slice(domain.as_bytes());
        self.ends.push(self.buf.len() as u32);
    }

    pub(crate) fn remove(&mut self, domain: &str) -> bool {
        let mut start = 0usize;
        for i in 0..self.ends.len() {
            let end = self.ends[i] as usize;
            if end - start == domain.len() && &self.buf[start..end] == domain.as_bytes() {
                self.buf.drain(start..end);
                let removed = domain.len() as u32;
                for e in &mut self.ends[i + 1..] {
                    *e -= removed;
                }
                self.ends.remove(i);
                return true;
            }
            start = end;
        }
        false
    }

    pub(crate) fn range(&self, offset: usize, end: usize) -> Vec<String> {
        (offset..end)
            .map(|i| {
                let start = if i == 0 { 0 } else { self.ends[i - 1] as usize };
                String::from_utf8_lossy(&self.buf[start..self.ends[i] as usize]).into_owned()
            })
            .collect()
    }

    pub(crate) fn shrink_to_fit(&mut self) {
        self.buf.shrink_to_fit();
        self.ends.shrink_to_fit();
    }

    pub(crate) fn clear(&mut self) {
        self.buf = Vec::new();
        self.ends = Vec::new();
    }
}

pub type SharedRuleStore = Arc<RwLock<super::repository::RuleStore>>;
