//! Port spec parsing — implements upstream `-p`, `--top-ports`, `-F`,
//! `--port-ratio`, `--exclude-ports`, plus the protocol-tagged
//! `T:80,U:53,S:5432` syntax.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
    /// IP protocol number sweep target (used by `-sO`).
    Ip,
}

impl Protocol {
    pub fn short(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
            Self::Ip => "ip",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Port {
    pub number: u16,
    pub protocol: Protocol,
}

impl Port {
    pub const fn tcp(number: u16) -> Self {
        Self { number, protocol: Protocol::Tcp }
    }

    pub const fn udp(number: u16) -> Self {
        Self { number, protocol: Protocol::Udp }
    }

    pub const fn sctp(number: u16) -> Self {
        Self { number, protocol: Protocol::Sctp }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
    pub protocol: Protocol,
}

impl PortRange {
    pub fn iter(&self) -> impl Iterator<Item = Port> + '_ {
        (self.start..=self.end).map(|n| Port { number: n, protocol: self.protocol })
    }
}

/// Output of parsing a `-p`-style spec.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PortSpec {
    pub tcp: BTreeSet<u16>,
    pub udp: BTreeSet<u16>,
    pub sctp: BTreeSet<u16>,
    pub ip_proto: BTreeSet<u16>,
}

impl PortSpec {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn all_tcp() -> Self {
        let mut s = Self::default();
        s.tcp = (1..=65535).collect();
        s
    }

    pub fn all_udp() -> Self {
        let mut s = Self::default();
        s.udp = (1..=65535).collect();
        s
    }

    pub fn iter(&self) -> impl Iterator<Item = Port> + '_ {
        self.tcp
            .iter()
            .map(|&p| Port::tcp(p))
            .chain(self.udp.iter().map(|&p| Port::udp(p)))
            .chain(self.sctp.iter().map(|&p| Port::sctp(p)))
            .chain(
                self.ip_proto
                    .iter()
                    .map(|&p| Port { number: p, protocol: Protocol::Ip }),
            )
    }

    pub fn len(&self) -> usize {
        self.tcp.len() + self.udp.len() + self.sctp.len() + self.ip_proto.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn merge(&mut self, other: PortSpec) {
        self.tcp.extend(other.tcp);
        self.udp.extend(other.udp);
        self.sctp.extend(other.sctp);
        self.ip_proto.extend(other.ip_proto);
    }

    pub fn remove(&mut self, other: &PortSpec) {
        for p in &other.tcp {
            self.tcp.remove(p);
        }
        for p in &other.udp {
            self.udp.remove(p);
        }
        for p in &other.sctp {
            self.sctp.remove(p);
        }
        for p in &other.ip_proto {
            self.ip_proto.remove(p);
        }
    }

    pub fn contains(&self, port: Port) -> bool {
        match port.protocol {
            Protocol::Tcp => self.tcp.contains(&port.number),
            Protocol::Udp => self.udp.contains(&port.number),
            Protocol::Sctp => self.sctp.contains(&port.number),
            Protocol::Ip => self.ip_proto.contains(&port.number),
        }
    }
}

/// Parse one upstream-style `-p` spec like `80,443,1-1024`, `T:22-25,U:53`,
/// or `-` (alias for `1-65535`). When no protocol tags appear, the default is
/// inferred from `default_proto`. The trailing `*` is silently dropped — same
/// as upstream.
pub fn parse_port_spec(spec: &str, default_proto: Protocol) -> Result<PortSpec> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(Error::InvalidPort("empty".into()));
    }
    if spec == "-" {
        return Ok(match default_proto {
            Protocol::Tcp => PortSpec::all_tcp(),
            Protocol::Udp => PortSpec::all_udp(),
            Protocol::Sctp => {
                let mut s = PortSpec::default();
                s.sctp = (1..=65535).collect();
                s
            }
            Protocol::Ip => {
                let mut s = PortSpec::default();
                s.ip_proto = (0..=255).collect();
                s
            }
        });
    }
    let mut out = PortSpec::default();
    let mut current_proto = default_proto;
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        // Protocol-tag prefix:  T: / U: / S: / P:
        let (proto, body) = if let Some(rest) = token.strip_prefix("T:") {
            (Some(Protocol::Tcp), rest)
        } else if let Some(rest) = token.strip_prefix("U:") {
            (Some(Protocol::Udp), rest)
        } else if let Some(rest) = token.strip_prefix("S:") {
            (Some(Protocol::Sctp), rest)
        } else if let Some(rest) = token.strip_prefix("P:") {
            (Some(Protocol::Ip), rest)
        } else {
            (None, token)
        };
        if let Some(p) = proto {
            current_proto = p;
        }
        if body.is_empty() {
            continue;
        }

        // Range or single port
        if let Some((lo, hi)) = body.split_once('-') {
            let lo: u16 = if lo.is_empty() {
                1
            } else {
                lo.parse()
                    .map_err(|_| Error::InvalidPort(format!("bad port low: {lo}")))?
            };
            let hi: u16 = if hi.is_empty() {
                65535
            } else {
                hi.parse()
                    .map_err(|_| Error::InvalidPort(format!("bad port high: {hi}")))?
            };
            if lo > hi {
                return Err(Error::InvalidPort(format!("{lo}-{hi} reversed")));
            }
            insert_range(&mut out, current_proto, lo, hi);
        } else if body == "*" {
            insert_range(&mut out, current_proto, 1, 65535);
        } else {
            let n: u16 = body
                .parse()
                .map_err(|_| Error::InvalidPort(format!("not a port: {body}")))?;
            insert(&mut out, current_proto, n);
        }
    }
    Ok(out)
}

fn insert(out: &mut PortSpec, proto: Protocol, n: u16) {
    match proto {
        Protocol::Tcp => {
            out.tcp.insert(n);
        }
        Protocol::Udp => {
            out.udp.insert(n);
        }
        Protocol::Sctp => {
            out.sctp.insert(n);
        }
        Protocol::Ip => {
            out.ip_proto.insert(n);
        }
    }
}

fn insert_range(out: &mut PortSpec, proto: Protocol, lo: u16, hi: u16) {
    match proto {
        Protocol::Tcp => out.tcp.extend(lo..=hi),
        Protocol::Udp => out.udp.extend(lo..=hi),
        Protocol::Sctp => out.sctp.extend(lo..=hi),
        Protocol::Ip => out.ip_proto.extend(lo..=hi),
    }
}

/// Build a port spec from the upstream-style `--top-ports N` option using the
/// `nmap-services` frequency ranking.
pub fn top_ports(n: usize) -> PortSpec {
    let mut s = PortSpec::default();
    for &p in nmap_data::services::top_n_tcp(n) {
        s.tcp.insert(p);
    }
    for &p in nmap_data::services::top_n_udp(n.max(8)) {
        s.udp.insert(p);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_list() {
        let s = parse_port_spec("80,443", Protocol::Tcp).unwrap();
        assert!(s.tcp.contains(&80));
        assert!(s.tcp.contains(&443));
        assert_eq!(s.tcp.len(), 2);
    }

    #[test]
    fn range_and_proto_tag() {
        let s = parse_port_spec("T:22-25,U:53", Protocol::Tcp).unwrap();
        assert!(s.tcp.contains(&22));
        assert!(s.tcp.contains(&25));
        assert!(s.udp.contains(&53));
    }

    #[test]
    fn dash_means_all() {
        let s = parse_port_spec("-", Protocol::Tcp).unwrap();
        assert_eq!(s.tcp.len(), 65535);
    }

    #[test]
    fn open_ended_range() {
        let s = parse_port_spec("100-", Protocol::Tcp).unwrap();
        assert!(s.tcp.contains(&100));
        assert!(s.tcp.contains(&65535));
    }
}
