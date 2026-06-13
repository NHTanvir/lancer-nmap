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
        let cache = Arc::new(RwLock::new(HashMap::new()));
        precompile(&probes, &cache);
        Self {
            probes: Arc::new(probes),
            cache,
            intensity: 7,
        }
    }

    /// Load the complete embedded upstream `nmap-service-probes` database
    /// (v7.99 — 1,246 protocols, ~8,000 match lines). This is the default for
    /// real scans; `-sV` matches at full fidelity.
    pub fn load_full() -> Self {
        Self::load_text(nmap_data::service_probes_db::FULL)
    }

    /// Load probes from a `--datadir` directory if it contains
    /// `nmap-service-probes`, otherwise the full embedded database.
    pub fn from_datadir(datadir: Option<&std::path::Path>) -> Self {
        Self::load_text(&nmap_data::load_service_probes(datadir))
    }

    pub fn with_intensity(mut self, n: u8) -> Self {
        self.intensity = n.min(9);
        self
    }

    fn regex_for(&self, rule: &MatchRule) -> Option<Regex> {
        let key = cache_key(rule);
        if let Some(r) = self.cache.read().get(&key).cloned() {
            return Some(r);
        }
        let r = build_regex(&key)?;
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
        // Bound the per-port version sweep: this engine probes serially, so an
        // unbounded rarity sweep against a silent port would stall. Cap total
        // wall-time and return any softmatch we already have.
        let port_deadline = std::time::Instant::now() + Duration::from_secs(15);

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
            if std::time::Instant::now() > port_deadline {
                break;
            }
            tried.push(probe.name.clone());
            // Cap each probe's read wait so a silent port doesn't burn the full
            // upstream `totalwaitms` (often 6s) per probe in our serial loop.
            let wait = Duration::from_millis(probe.total_wait_ms.clamp(1000, 2500) as u64);
            let bytes = match plain_probe(host, port, probe, wait).await {
                Ok(v) => v,
                Err(e) => {
                    trace!(?e, "probe failed");
                    continue;
                }
            };
            if let Some(outcome) = self.match_bytes(probe, &bytes, port_deadline) {
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

    fn match_bytes(
        &self,
        probe: &Probe,
        bytes: &[u8],
        deadline: std::time::Instant,
    ) -> Option<(MatchKind, ServiceInfo)> {
        for (i, rule) in probe.matches.iter().enumerate() {
            // Bail if this probe's match sweep has blown the per-port budget
            // (cold-cache regex compilation of thousands of rules is costly).
            if i % 128 == 0 && std::time::Instant::now() > deadline {
                break;
            }
            // Skip patterns the Rust `regex` engine can't compile (the upstream
            // DB uses PCRE features like backrefs/look-around) rather than
            // aborting the whole probe's match list.
            let re = match self.regex_for(rule) {
                Some(r) => r,
                None => continue,
            };
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

/// Cache key for a match rule's compiled regex (flags + pattern).
fn cache_key(rule: &MatchRule) -> String {
    format!(
        "{}{}{}",
        if rule.case_insensitive { "(?i)" } else { "" },
        if rule.multiline { "(?s)" } else { "" },
        rule.pattern
    )
}

/// Compile a probe pattern with a bounded program size so pathological
/// upstream patterns (the DB has ~8000, some PCRE-heavy) fail to build fast
/// instead of costing seconds each. Returns `None` for patterns the Rust
/// `regex` engine can't represent (backreferences, look-around).
fn build_regex(key: &str) -> Option<Regex> {
    regex::bytes::RegexBuilder::new(key)
        // nmap-service-probes patterns are byte-oriented; Unicode-aware
        // compilation builds far larger/slower programs for the same pattern.
        .unicode(false)
        .size_limit(1 << 18)
        .dfa_size_limit(1 << 18)
        .build()
        .ok()
}

/// Pre-compile every match rule's regex once, in parallel across CPU cores, so
/// the per-port version sweep runs against a hot cache instead of paying the
/// cold-compile cost (tens of seconds) on the first scanned port.
fn precompile(probes: &[Probe], cache: &RwLock<HashMap<String, Regex>>) {
    let mut seen = std::collections::HashSet::new();
    let mut keys: Vec<String> = Vec::new();
    for p in probes {
        for r in &p.matches {
            let k = cache_key(r);
            if seen.insert(k.clone()) {
                keys.push(k);
            }
        }
    }
    if keys.is_empty() {
        return;
    }
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(keys.len());
    let chunk = keys.len().div_ceil(workers);
    let compiled: Vec<(String, Regex)> = std::thread::scope(|s| {
        let handles: Vec<_> = keys
            .chunks(chunk)
            .map(|c| {
                s.spawn(move || {
                    c.iter()
                        .filter_map(|k| build_regex(k).map(|r| (k.clone(), r)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });
    let mut c = cache.write();
    for (k, r) in compiled {
        c.insert(k, r);
    }
}
