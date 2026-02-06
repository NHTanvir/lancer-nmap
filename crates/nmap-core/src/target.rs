//! Target enumeration — mirrors upstream `TargetGroup.cc` plus the
//! 7.96+/7.97+ enhancements (`--unique`, `--resolve-all`, `--discovery-ignore-rst`,
//! combined CLI + `-iL`, `/etc/hosts` localhost preference).

use crate::error::{Error, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// A single resolved target with bookkeeping for output and traceroute.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Target {
    pub ip: IpAddr,
    /// The original hostname (if any) that produced this IP.
    pub hostname: Option<String>,
    /// Other names this IP resolves under, accumulated from `--resolve-all`.
    pub aliases: Vec<String>,
}

impl Target {
    pub fn new(ip: IpAddr) -> Self {
        Self { ip, hostname: None, aliases: Vec::new() }
    }
    pub fn with_hostname(ip: IpAddr, host: impl Into<String>) -> Self {
        Self {
            ip,
            hostname: Some(host.into()),
            aliases: Vec::new(),
        }
    }
}

/// One parse element. The expander walks a `Vec<TargetSpec>` to produce
/// concrete `Target`s.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TargetSpec {
    /// Single IP, no resolution needed.
    Ip(IpAddr),
    /// CIDR block, both v4 and v6.
    Cidr(IpNet),
    /// Octet range like `192.168.1.1-100` or `10.1-3.0-255.50`.
    OctetRange(String),
    /// Hostname that must be resolved.
    Host(String),
    /// `-iL file` line-by-line list.
    File(std::path::PathBuf),
    /// `-iR N` random Internet targets.
    Random(usize),
}

/// A collection of `TargetSpec`s plus exclusion + flag state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TargetGroup {
    pub specs: Vec<TargetSpec>,
    pub exclude: Vec<TargetSpec>,
    /// `--resolve-all` — emit one Target per resolved IP, not just the first.
    pub resolve_all: bool,
    /// `--unique` — dedupe IPs across hostname expansions (7.96+).
    pub unique: bool,
    /// `-n` — never reverse-resolve.
    pub no_dns: bool,
    /// `-R` — always reverse-resolve even for IPs.
    pub always_dns: bool,
    /// `--system-dns` — call the OS resolver, not hickory.
    pub system_dns: bool,
    /// `--dns-servers ...`.
    pub dns_servers: Vec<IpAddr>,
}

impl TargetGroup {
    pub fn add_spec(&mut self, spec: TargetSpec) {
        self.specs.push(spec);
    }
    pub fn add_exclude(&mut self, spec: TargetSpec) {
        self.exclude.push(spec);
    }
}

/// Parse one CLI positional / `-iL` line into a `TargetSpec`. Hosts get the
/// `Host` variant — resolution happens later via `expand`.
pub fn parse_target(token: &str) -> Result<TargetSpec> {
    let t = token.trim();
    if t.is_empty() {
        return Err(Error::InvalidTarget("empty".into()));
    }
    if let Ok(net) = t.parse::<IpNet>() {
        return Ok(TargetSpec::Cidr(net));
    }
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Ok(TargetSpec::Ip(ip));
    }
    // octet-range: contains `-` AND looks like an IPv4 expression
    if looks_like_octet_range(t) {
        return Ok(TargetSpec::OctetRange(t.to_string()));
    }
    // otherwise treat as hostname
    Ok(TargetSpec::Host(t.to_string()))
}

fn looks_like_octet_range(t: &str) -> bool {
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        p.split(',').all(|chunk| {
            let chunk = chunk.trim();
            if let Some((lo, hi)) = chunk.split_once('-') {
                lo.parse::<u16>().is_ok() && (hi.is_empty() || hi.parse::<u16>().is_ok())
            } else {
                chunk.parse::<u16>().is_ok()
            }
        })
    })
}

/// Expand an octet-range like `192.168.1-3.10-20` into all v4 addresses.
pub fn expand_octet_range(spec: &str) -> Result<Vec<Ipv4Addr>> {
    let parts: Vec<&str> = spec.split('.').collect();
    if parts.len() != 4 {
        return Err(Error::InvalidTarget(format!("not 4 octets: {spec}")));
    }
    let mut octets: Vec<Vec<u8>> = Vec::with_capacity(4);
    for p in parts {
        let mut accum: Vec<u8> = Vec::new();
        for chunk in p.split(',') {
            let chunk = chunk.trim();
            if let Some((lo, hi)) = chunk.split_once('-') {
                let lo: u16 = lo
                    .parse()
                    .map_err(|_| Error::InvalidTarget(format!("bad octet: {lo}")))?;
                let hi: u16 = if hi.is_empty() {
                    255
                } else {
                    hi.parse()
                        .map_err(|_| Error::InvalidTarget(format!("bad octet: {hi}")))?
                };
                if lo > hi || hi > 255 {
                    return Err(Error::InvalidTarget(format!("octet range bad: {chunk}")));
                }
                accum.extend((lo as u8)..=(hi as u8));
            } else if chunk == "*" {
                accum.extend(0u8..=255);
            } else {
                let n: u16 = chunk
                    .parse()
                    .map_err(|_| Error::InvalidTarget(format!("bad octet: {chunk}")))?;
                if n > 255 {
                    return Err(Error::InvalidTarget(format!("octet > 255: {chunk}")));
                }
                accum.push(n as u8);
            }
        }
        accum.sort_unstable();
        accum.dedup();
        octets.push(accum);
    }
    let mut out = Vec::with_capacity(octets.iter().map(|o| o.len()).product());
    for &a in &octets[0] {
        for &b in &octets[1] {
            for &c in &octets[2] {
                for &d in &octets[3] {
                    out.push(Ipv4Addr::new(a, b, c, d));
                }
            }
        }
    }
    Ok(out)
}

/// Load a target file (`-iL`), one target per line. Blank lines and
/// `#`-prefixed comments are ignored.
pub fn load_target_file(path: &Path) -> Result<Vec<TargetSpec>> {
    let text = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for token in line.split_whitespace() {
            out.push(parse_target(token)?);
        }
    }
    Ok(out)
}

/// Generate N random public Internet IPv4 addresses, mirroring upstream `-iR`.
/// Avoids RFC-1918/loopback/link-local/multicast/reserved blocks.
pub fn random_targets(n: usize) -> Vec<Ipv4Addr> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let octets: [u8; 4] = rng.gen();
        let addr = Ipv4Addr::from(octets);
        if !is_reserved_v4(addr) {
            out.push(addr);
        }
    }
    out
}

fn is_reserved_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation()
        || a.is_unspecified()
        || o[0] == 0
        || o[0] == 127
        || (o[0] >= 224)
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64.0.0/10
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

/// CIDR iteration helper that works for both v4 and v6.
pub fn iter_cidr(net: IpNet) -> Box<dyn Iterator<Item = IpAddr>> {
    match net {
        IpNet::V4(v) => Box::new(iter_v4_net(v).map(IpAddr::V4)),
        IpNet::V6(v) => Box::new(iter_v6_net(v).map(IpAddr::V6)),
    }
}

fn iter_v4_net(net: Ipv4Net) -> impl Iterator<Item = Ipv4Addr> {
    net.hosts()
}

fn iter_v6_net(net: Ipv6Net) -> Box<dyn Iterator<Item = Ipv6Addr>> {
    // For very large v6 nets, cap to first ~65536 hosts so we don't try to
    // materialize a 2^64 iterator (this matches upstream-style guardrails).
    let prefix = net.prefix_len();
    if prefix >= 112 {
        Box::new(net.hosts())
    } else {
        let base = net.network();
        Box::new((0u32..=65535).map(move |i| {
            let mut o = base.octets();
            let bi = i as u16;
            o[14] = (bi >> 8) as u8;
            o[15] = bi as u8;
            Ipv6Addr::from(o)
        }))
    }
}

/// Dedupe `Target` list in-place using IP as key (mirrors `--unique`).
pub fn dedupe_targets(targets: &mut Vec<Target>) {
    let mut seen = HashSet::new();
    targets.retain(|t| seen.insert(t.ip));
}

/// Synchronously expand non-DNS targets (IP, CIDR, OctetRange, Random, File).
/// Hostname resolution is deferred to the async resolver, since DNS dominates
/// scan setup time for large hostname lists.
pub fn expand_offline(group: &TargetGroup) -> Result<(Vec<Target>, Vec<String>)> {
    let mut out = Vec::new();
    let mut hosts_pending = Vec::new();

    for spec in &group.specs {
        match spec {
            TargetSpec::Ip(ip) => out.push(Target::new(*ip)),
            TargetSpec::Cidr(net) => {
                for ip in iter_cidr(*net) {
                    out.push(Target::new(ip));
                }
            }
            TargetSpec::OctetRange(s) => {
                for ip in expand_octet_range(s)? {
                    out.push(Target::new(IpAddr::V4(ip)));
                }
            }
            TargetSpec::File(path) => {
                let nested = load_target_file(path)?;
                for sub in nested {
                    match sub {
                        TargetSpec::Ip(ip) => out.push(Target::new(ip)),
                        TargetSpec::Cidr(net) => {
                            for ip in iter_cidr(net) {
                                out.push(Target::new(ip));
                            }
                        }
                        TargetSpec::OctetRange(s) => {
                            for ip in expand_octet_range(&s)? {
                                out.push(Target::new(IpAddr::V4(ip)));
                            }
                        }
                        TargetSpec::Host(h) => hosts_pending.push(h),
                        TargetSpec::Random(n) => {
                            for ip in random_targets(n) {
                                out.push(Target::new(IpAddr::V4(ip)));
                            }
                        }
                        TargetSpec::File(_) => {
                            // Nested file: deliberately disallowed
                            return Err(Error::InvalidTarget(
                                "nested -iL files not supported".into(),
                            ));
                        }
                    }
                }
            }
            TargetSpec::Host(h) => hosts_pending.push(h.clone()),
            TargetSpec::Random(n) => {
                for ip in random_targets(*n) {
                    out.push(Target::new(IpAddr::V4(ip)));
                }
            }
        }
    }

    if group.unique {
        dedupe_targets(&mut out);
    }

    Ok((out, hosts_pending))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_ip() {
        let s = parse_target("10.0.0.1").unwrap();
        assert!(matches!(s, TargetSpec::Ip(_)));
    }

    #[test]
    fn parse_cidr() {
        let s = parse_target("10.0.0.0/24").unwrap();
        assert!(matches!(s, TargetSpec::Cidr(_)));
    }

    #[test]
    fn parse_hostname() {
        let s = parse_target("example.com").unwrap();
        assert!(matches!(s, TargetSpec::Host(_)));
    }

    #[test]
    fn octet_range_expand() {
        let v = expand_octet_range("10.0.0.1-3").unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(v[2], Ipv4Addr::new(10, 0, 0, 3));
    }

    #[test]
    fn octet_range_with_list() {
        let v = expand_octet_range("10.1,2.0.1").unwrap();
        assert_eq!(v.len(), 2);
    }
}
