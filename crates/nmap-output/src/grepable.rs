//! `-oG` grepable output. One line per host.

use crate::common::open_ports;
use nmap_core::result::{HostState, ScanResult};
use std::fmt::Write;

pub fn emit(r: &ScanResult) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# {} {} scan initiated {} as: {}",
        r.scanner,
        r.version,
        r.start.format("%Y-%m-%d %H:%M:%S UTC"),
        r.args
    );
    for h in &r.hosts {
        let host = if h.hostnames.is_empty() {
            String::new()
        } else {
            h.hostnames[0].clone()
        };
        let state = match h.state {
            HostState::Up => "Up",
            HostState::Down => "Down",
            _ => "Unknown",
        };
        let opens = open_ports(h);
        let mut ports = String::new();
        for p in opens {
            let _ = write!(
                ports,
                "{}/{}/{}/{}/{}//, ",
                p.port.number,
                p.state.as_str(),
                p.port.protocol.short(),
                p.service
                    .as_ref()
                    .and_then(|s| s.name.clone())
                    .unwrap_or_default(),
                p.service
                    .as_ref()
                    .and_then(|s| s.product.clone())
                    .unwrap_or_default()
            );
        }
        let _ = writeln!(
            out,
            "Host: {} ({})\tStatus: {}\tPorts: {}",
            h.address, host, state, ports
        );
    }
    let _ = writeln!(
        out,
        "# Nmap done at {} -- {} IP address ({} hosts up) scanned in {:.2} seconds",
        r.end.format("%Y-%m-%d %H:%M:%S UTC"),
        r.summary_total,
        r.summary_up,
        r.elapsed.as_secs_f64()
    );
    out
}
