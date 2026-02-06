//! Compact port-list type used by `Probe::ports` / `Probe::ssl_ports`.

use std::collections::BTreeSet;

#[derive(Clone, Debug, Default)]
pub struct PortList {
    pub set: BTreeSet<u16>,
    pub all: bool,
}

impl PortList {
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn all() -> Self {
        Self { all: true, ..Default::default() }
    }
    pub fn parse(text: &str) -> Self {
        if text.trim() == "*" {
            return Self::all();
        }
        let mut s = BTreeSet::new();
        for chunk in text.split(',') {
            let chunk = chunk.trim();
            if let Some((lo, hi)) = chunk.split_once('-') {
                let lo: u16 = lo.parse().unwrap_or(0);
                let hi: u16 = hi.parse().unwrap_or(0);
                for p in lo..=hi {
                    s.insert(p);
                }
            } else if let Ok(p) = chunk.parse::<u16>() {
                s.insert(p);
            }
        }
        Self { set: s, all: false }
    }
    pub fn contains(&self, port: u16) -> bool {
        self.all || self.set.contains(&port)
    }
    pub fn is_empty(&self) -> bool {
        !self.all && self.set.is_empty()
    }
}
