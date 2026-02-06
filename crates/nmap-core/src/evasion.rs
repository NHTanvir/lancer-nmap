//! Firewall / IDS evasion helpers. Most of these only matter once raw
//! sockets are wired up — this module collects the policy logic so the
//! raw scanners can consume it uniformly.

use crate::options::{DecoySpec, EvasionOptions};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug)]
pub struct EvasionPlan {
    pub decoys: Vec<IpAddr>,
    pub fragment_size: Option<u16>,
    pub source_port: Option<u16>,
    pub data_padding: Vec<u8>,
    pub ttl: Option<u8>,
    pub spoof_mac: Option<[u8; 6]>,
    pub badsum: bool,
    pub randomize_hosts: bool,
}

impl EvasionPlan {
    pub fn from(opts: &EvasionOptions) -> Self {
        let mut decoys = Vec::new();
        for d in &opts.decoys {
            match d {
                DecoySpec::Me => decoys.push(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                DecoySpec::Ip(ip) => decoys.push(*ip),
                DecoySpec::Random(n) => {
                    let mut rng = rand::thread_rng();
                    for _ in 0..*n {
                        let b: [u8; 4] = rng.gen();
                        decoys.push(IpAddr::V4(Ipv4Addr::from(b)));
                    }
                }
            }
        }
        let fragment_size = opts.mtu.or_else(|| match opts.fragment {
            1 => Some(8),
            2 => Some(16),
            _ => None,
        });
        let mut padding = Vec::new();
        if let Some(s) = &opts.data_string {
            padding.extend(s.as_bytes());
        } else if let Some(d) = &opts.data {
            padding.extend(d);
        } else if let Some(n) = opts.data_length {
            let mut rng = rand::thread_rng();
            padding = (0..n).map(|_| rng.gen::<u8>()).collect();
        }
        let spoof_mac = opts.spoof_mac.as_deref().and_then(parse_mac);
        Self {
            decoys,
            fragment_size,
            source_port: opts.source_port,
            data_padding: padding,
            ttl: opts.ttl,
            spoof_mac,
            badsum: opts.badsum,
            randomize_hosts: opts.randomize_hosts,
        }
    }
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    if s == "0" {
        let mut rng = rand::thread_rng();
        let b: [u8; 6] = rng.gen();
        return Some(b);
    }
    if s.eq_ignore_ascii_case("apple") {
        // Apple OUI 00:1B:63 + random tail
        let mut rng = rand::thread_rng();
        return Some([0x00, 0x1B, 0x63, rng.gen(), rng.gen(), rng.gen()]);
    }
    if s.eq_ignore_ascii_case("cisco") {
        let mut rng = rand::thread_rng();
        return Some([0x00, 0x01, 0x42, rng.gen(), rng.gen(), rng.gen()]);
    }
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}
