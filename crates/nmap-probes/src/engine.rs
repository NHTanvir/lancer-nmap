//! Service-version detection engine — orchestrates probes and match-rule
//! evaluation. Matches upstream `service_scan.cc`'s NULL → port-hinted →
//! rarity-sweep → fallback flow.

use crate::parser::{parse_probes, MatchKind, MatchRule, Probe, ProbeProtocol};
use crate::tls::plain_probe;
use nmap_core::result::ServiceInfo;
use parking_lot::RwLock;
use regex::bytes::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::trace;

#[derive(Clone, Debug)]
pub enum ProbeOutcome {
    Hard(ServiceInfo),
    Soft(ServiceInfo),
    NoMatch,
    Timeout,
    Error(String),
}

#[derive(Clone)]
pub struct ServiceEngine {
    pub probes: Arc<Vec<Probe>>,
    cache: Arc<RwLock<HashMap<String, Regex>>>,
    pub intensity: u8,
}

impl ServiceEngine {
    pub fn load_builtin() -> Self {
        let probes = parse_probes(nmap_data::service_probes_db::BUILTIN);
        Self {
            probes: Arc::new(probes),
            cache: Arc::new(RwLock::new(HashMap::new())),
            intensity: 7,
        }
    }

    pub fn load_text(text: &str) -> Self {
        let probes = parse_probes(text);
        Self {
            probes: Arc::new(probes),
            cache: Arc::new(RwLock::new(HashMap::new())),
            intensity: 7,
        }
    }

    pub fn with_intensity(mut self, n: u8) -> Self {
        self.intensity = n.min(9);
        self
    }

    fn regex_for(&self, rule: &MatchRule) -> Option<Regex> {
        let key = format!(
            "{}{}{}",
            if rule.case_insensitive { "(?i)" } else { "" },
            if rule.multiline { "(?s)" } else { "" },
            rule.pattern
        );
        if let Some(r) = self.cache.read().get(&key).cloned() {
            return Some(r);
        }
        let r = Regex::new(&key).ok()?;
        self.cache.write().insert(key, r.clone());
        Some(r)
    }

    pub async fn probe(
        &self,
        host: std::net::IpAddr,
        port: u16,
        protocol_is_tcp: bool,
    ) -> ProbeOutcome {
        let mut softmatch: Option<ServiceInfo> = None;
        let mut tried: Vec<String> = Vec::new();

        for probe in self
            .probes
            .iter()
            .filter(|p| match (protocol_is_tcp, p.protocol) {
                (true, ProbeProtocol::Tcp) => true,
                (false, ProbeProtocol::Udp) => true,
                _ => false,
            })
        {
            if probe.rarity > self.intensity {
                continue;
            }
            if !probe.ports.is_empty() && !probe.ports.contains(port) {
                continue;
            }
            tried.push(probe.name.clone());
            let wait = Duration::from_millis(probe.total_wait_ms.max(1000) as u64);
            let bytes = match plain_probe(host, port, probe, wait).await {
                Ok(v) => v,
                Err(e) => {
                    trace!(?e, "probe failed");
                    continue;
                }
            };
            if let Some(outcome) = self.match_bytes(probe, &bytes) {
                match outcome.0 {
                    MatchKind::Hard => return ProbeOutcome::Hard(outcome.1),
                    MatchKind::Soft => {
                        if softmatch.is_none() {
                            softmatch = Some(outcome.1);
                        }
                    }
                }
            }
        }
        match softmatch {
            Some(s) => ProbeOutcome::Soft(s),
            None => ProbeOutcome::NoMatch,
        }
    }

    fn match_bytes(&self, probe: &Probe, bytes: &[u8]) -> Option<(MatchKind, ServiceInfo)> {
        for rule in &probe.matches {
            let re = self.regex_for(rule)?;
            if let Some(caps) = re.captures(bytes) {
                let mut info = ServiceInfo::default();
                info.name = Some(rule.service.clone());
                info.method = Some("probed".into());
                info.conf = 10;
                info.soft = matches!(rule.kind, MatchKind::Soft);
                for (key, raw_val) in &rule.fields {
                    let mut val = raw_val.clone();
                    for (i, c) in caps.iter().enumerate() {
                        if let Some(c) = c {
                            let s = String::from_utf8_lossy(c.as_bytes()).into_owned();
                            val = val.replace(&format!("${i}"), &s);
                        }
                    }
                    match *key {
                        "product" => info.product = Some(val),
                        "version" => info.version = Some(val),
                        "info" => info.extra_info = Some(val),
                        "ostype" => info.os_type = Some(val),
                        "devicetype" => info.device_type = Some(val),
                        "hostname" => info.hostname = Some(val),
                        _ => {}
                    }
                }
                for c in &rule.cpe {
                    info.cpe.push(c.clone());
                }
                return Some((rule.kind, info));
            }
        }
        None
    }
}
