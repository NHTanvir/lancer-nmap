//! Parser for the `nmap-service-probes` DSL.
//!
//! Grammar overview (compact, see upstream `nmap-service-probes(5)` for full
//! reference):
//!
//! ```text
//! Exclude T:9100-9107
//!
//! Probe TCP NULL q||
//! rarity 1
//! ports 1-65535
//! sslports 443,465
//! totalwaitms 6000
//! tcpwrappedms 3000
//! rarity 1
//! fallback NULL,GenericLines
//!
//! match  http  m|^HTTP/1\.([01])| p/HTTP/v/$1/ cpe:/a:apache:http_server/
//! softmatch unknown m|^.+|s p/unknown/
//! ```

use crate::ports::PortList;
use indexmap::IndexMap;
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Debug)]
pub struct Probe {
    pub protocol: ProbeProtocol,
    pub name: String,
    pub probe_string: Vec<u8>,
    pub no_payload: bool,
    pub rarity: u8,
    pub ports: PortList,
    pub ssl_ports: PortList,
    pub total_wait_ms: u32,
    pub tcp_wrapped_ms: u32,
    pub fallback: Vec<String>,
    pub matches: Vec<MatchRule>,
}

impl Probe {
    pub fn null() -> Self {
        Self {
            protocol: ProbeProtocol::Tcp,
            name: "NULL".into(),
            probe_string: Vec::new(),
            no_payload: true,
            rarity: 1,
            ports: PortList::all(),
            ssl_ports: PortList::empty(),
            total_wait_ms: 6000,
            tcp_wrapped_ms: 3000,
            fallback: Vec::new(),
            matches: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchKind {
    Hard,
    Soft,
}

#[derive(Clone, Debug)]
pub struct MatchRule {
    pub kind: MatchKind,
    pub service: String,
    pub pattern: String,
    pub case_insensitive: bool,
    pub multiline: bool,
    pub fields: IndexMap<&'static str, String>,
    pub cpe: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ProbeMatch<'a> {
    pub rule: &'a MatchRule,
    pub captures: Vec<String>,
}

pub fn parse_probes(text: &str) -> Vec<Probe> {
    let mut probes: Vec<Probe> = Vec::new();
    let mut excludes = HashSet::new();
    let mut cur: Option<Probe> = None;
    for raw in text.lines() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("Exclude ") {
            for tok in rest.split(',') {
                excludes.insert(tok.trim().to_string());
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("Probe ") {
            if let Some(p) = cur.take() {
                probes.push(p);
            }
            cur = Some(parse_probe_header(rest));
            continue;
        }
        let cur_ref = match cur.as_mut() {
            Some(p) => p,
            None => continue,
        };
        if let Some(rest) = line.strip_prefix("rarity ") {
            cur_ref.rarity = rest.trim().parse().unwrap_or(1);
        } else if let Some(rest) = line.strip_prefix("ports ") {
            cur_ref.ports = PortList::parse(rest.trim());
        } else if let Some(rest) = line.strip_prefix("sslports ") {
            cur_ref.ssl_ports = PortList::parse(rest.trim());
        } else if let Some(rest) = line.strip_prefix("totalwaitms ") {
            cur_ref.total_wait_ms = rest.trim().parse().unwrap_or(6000);
        } else if let Some(rest) = line.strip_prefix("tcpwrappedms ") {
            cur_ref.tcp_wrapped_ms = rest.trim().parse().unwrap_or(3000);
        } else if let Some(rest) = line.strip_prefix("fallback ") {
            cur_ref.fallback = rest.split(',').map(|s| s.trim().to_string()).collect();
        } else if let Some(rest) = line.strip_prefix("match ") {
            if let Some(m) = parse_match(MatchKind::Hard, rest) {
                cur_ref.matches.push(m);
            }
        } else if let Some(rest) = line.strip_prefix("softmatch ") {
            if let Some(m) = parse_match(MatchKind::Soft, rest) {
                cur_ref.matches.push(m);
            }
        }
        // ignore unrecognized directives — match upstream's permissive behaviour
    }
    if let Some(p) = cur.take() {
        probes.push(p);
    }
    probes
}

fn parse_probe_header(rest: &str) -> Probe {
    // Format:  Probe <protocol> <name> q|<bytes>|
    let mut probe = Probe::null();
    let mut iter = rest.splitn(3, ' ');
    if let Some(proto) = iter.next() {
        probe.protocol = match proto {
            "TCP" => ProbeProtocol::Tcp,
            "UDP" => ProbeProtocol::Udp,
            _ => ProbeProtocol::Tcp,
        };
    }
    if let Some(name) = iter.next() {
        probe.name = name.to_string();
    }
    if let Some(qbody) = iter.next() {
        if let Some(bytes) = parse_q_string(qbody.trim()) {
            probe.probe_string = bytes;
            probe.no_payload = probe.probe_string.is_empty();
        }
    }
    probe
}

fn parse_q_string(body: &str) -> Option<Vec<u8>> {
    let bytes = body.as_bytes();
    let q_pos = bytes.iter().position(|&b| b == b'q')?;
    let mut i = q_pos + 1;
    if i >= bytes.len() {
        return Some(Vec::new());
    }
    let delim = bytes[i];
    i += 1;
    let mut out = Vec::new();
    while i < bytes.len() && bytes[i] != delim {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let esc = bytes[i + 1];
            match esc {
                b'\\' => out.push(b'\\'),
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'0' => out.push(0),
                b'x' if i + 3 < bytes.len() => {
                    let hex = &body[i + 2..i + 4];
                    if let Ok(v) = u8::from_str_radix(hex, 16) {
                        out.push(v);
                    }
                    i += 2;
                }
                _ => out.push(esc),
            }
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

fn parse_match(kind: MatchKind, line: &str) -> Option<MatchRule> {
    // Format: <service> m|<regex>|[s][i] <fields>
    let line = line.trim();
    let (service, rest) = line.split_once(' ')?;
    let rest = rest.trim();
    let m_pos = rest.find('m')?;
    let after_m = &rest[m_pos + 1..];
    let delim = after_m.chars().next()?;
    let mut end = None;
    let bytes = after_m.as_bytes();
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == delim as u8 && bytes.get(i - 1) != Some(&b'\\') {
            end = Some(i);
            break;
        }
        i += 1;
    }
    let end_idx = end?;
    let pattern = &after_m[1..end_idx];
    let mut flags_end = end_idx + 1;
    let mut case_i = false;
    let mut multi = false;
    while flags_end < after_m.len() {
        let c = after_m.as_bytes()[flags_end];
        match c {
            b'i' => case_i = true,
            b's' => multi = true,
            b' ' => break,
            _ => break,
        }
        flags_end += 1;
    }
    let fields_text = after_m[flags_end..].trim();
    let (fields, cpes) = parse_match_fields(fields_text);
    Some(MatchRule {
        kind,
        service: service.to_string(),
        pattern: pattern.to_string(),
        case_insensitive: case_i,
        multiline: multi,
        fields,
        cpe: cpes,
    })
}

fn parse_match_fields(text: &str) -> (IndexMap<&'static str, String>, Vec<String>) {
    let mut fields: IndexMap<&'static str, String> = IndexMap::new();
    let mut cpes: Vec<String> = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        if let Some(stripped) = rest.strip_prefix("cpe:") {
            // cpe:/...
            let (val, tail) = read_delimited(stripped);
            cpes.push(format!("cpe:{val}"));
            rest = tail;
            continue;
        }
        let first = rest.chars().next().unwrap();
        let key: &'static str = match first {
            'p' => "product",
            'v' => "version",
            'i' => "info",
            'o' => "ostype",
            'd' => "devicetype",
            'h' => "hostname",
            _ => {
                rest = &rest[1..];
                continue;
            }
        };
        rest = &rest[1..];
        let (val, tail) = read_delimited(rest);
        fields.insert(key, val);
        rest = tail;
    }
    (fields, cpes)
}

fn read_delimited(text: &str) -> (String, &str) {
    if text.is_empty() {
        return (String::new(), text);
    }
    let delim = text.as_bytes()[0];
    let body = &text[1..];
    let mut out = String::new();
    let mut i = 0;
    let bytes = body.as_bytes();
    while i < bytes.len() {
        if bytes[i] == delim {
            return (out, &body[i + 1..]);
        }
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            out.push(bytes[i + 1] as char);
            i += 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    (out, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_builtin() {
        let probes = parse_probes(nmap_data::service_probes_db::BUILTIN);
        assert!(probes.len() >= 3, "got {} probes", probes.len());
        let null = probes.iter().find(|p| p.name == "NULL").expect("NULL");
        assert!(!null.matches.is_empty());
    }
}
