//! `-oN` normal (interactive) output. Matches upstream's plaintext look.

use crate::common::open_ports;
use nmap_core::result::{HostState, PortState, ScanResult};
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
        let _ = writeln!(out);
        let host_str = if h.hostnames.is_empty() {
            h.address.to_string()
        } else {
            format!("{} ({})", h.hostnames[0], h.address)
        };
        let _ = writeln!(
            out,
            "Nmap scan report for {host_str}"
        );
        let state = match h.state {
            HostState::Up => "up",
            HostState::Down => "down",
            HostState::Unknown => "unknown",
            HostState::SkippedDiscovery => "up (-Pn assumed)",
        };
        if let Some(reason) = &h.state_reason {
            let _ = writeln!(out, "Host is {state} ({reason})", reason = reason.reason);
        } else {
            let _ = writeln!(out, "Host is {state}.");
        }
        if !h.ports.is_empty() {
            let _ = writeln!(out, "PORT     STATE         SERVICE         VERSION");
            for p in &h.ports {
                let state = p.state.as_str();
                let port_proto = format!("{}/{}", p.port.number, p.port.protocol.short());
                let service = p
                    .service
                    .as_ref()
                    .and_then(|s| s.name.clone())
                    .or_else(|| {
                        nmap_data::services::service_name(p.port.number, p.port.protocol.short())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_default();
                // VERSION column mirrors nmap: "product version (extrainfo)".
                let version = p
                    .service
                    .as_ref()
                    .map(|s| {
                        let mut v = String::new();
                        if let Some(pr) = &s.product {
                            v.push_str(pr);
                        }
                        if let Some(ver) = &s.version {
                            if !v.is_empty() {
                                v.push(' ');
                            }
                            v.push_str(ver);
                        }
                        if let Some(ei) = &s.extra_info {
                            if !ei.is_empty() {
                                v.push_str(&format!(" ({ei})"));
                            }
                        }
                        v.trim().to_string()
                    })
                    .unwrap_or_default();
                let _ = writeln!(
                    out,
                    "{:<9}{:<14}{:<16}{}",
                    port_proto, state, service, version
                );
                for s in &p.scripts {
                    let _ = writeln!(out, "| {}: {}", s.id, s.output);
                }
            }
        }
        let open = open_ports(h);
        let _ = writeln!(
            out,
            "Open ports: {} (of {} scanned)",
            open.len(),
            h.ports.len()
        );
        for om in &h.os_matches {
            let _ = writeln!(out, "OS match: {} ({}%)", om.name, om.accuracy);
        }
        for s in &h.host_scripts {
            let _ = writeln!(out, "|_{}: {}", s.id, s.output);
        }
    }
    let _ = writeln!(out);
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
