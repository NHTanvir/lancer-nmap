//! `lancer-ndiff` — compare two scan results, emit a delta report.

use anyhow::{anyhow, Result};
use clap::Parser;
use nmap_core::result::ScanResult;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "lancer-ndiff", version, about = "Compare two lancer-nmap (or nmap) result files")]
struct Args {
    /// Old scan (XML or JSON)
    old: PathBuf,
    /// New scan (XML or JSON)
    new: PathBuf,
    /// Emit JSON instead of human-readable diff.
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let args = Args::parse();
    let old = load(&args.old)?;
    let new = load(&args.new)?;
    let diff = compare(&old, &new);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&diff)?);
    } else {
        print_human(&diff);
    }
    Ok(())
}

fn load(path: &std::path::Path) -> Result<ScanResult> {
    let text = std::fs::read_to_string(path)?;
    if text.trim_start().starts_with('{') {
        Ok(serde_json::from_str(&text)?)
    } else {
        // XML — fall through to a placeholder. A full XML reader would parse
        // upstream's schema; for now we leave that to the GUI's loader.
        Err(anyhow!("XML scan parsing not yet wired into ndiff; please pass --oJ JSON"))
    }
}

#[derive(Debug, Default, serde::Serialize)]
struct Diff {
    added_hosts: Vec<String>,
    removed_hosts: Vec<String>,
    changed: BTreeMap<String, HostDiff>,
}

#[derive(Debug, Default, serde::Serialize)]
struct HostDiff {
    added_ports: Vec<String>,
    removed_ports: Vec<String>,
    changed_ports: Vec<String>,
}

fn compare(a: &ScanResult, b: &ScanResult) -> Diff {
    let mut d = Diff::default();
    let map_a: BTreeMap<_, _> = a.hosts.iter().map(|h| (h.address, h)).collect();
    let map_b: BTreeMap<_, _> = b.hosts.iter().map(|h| (h.address, h)).collect();
    for (ip, hb) in &map_b {
        if !map_a.contains_key(ip) {
            d.added_hosts.push(ip.to_string());
        }
        if let Some(ha) = map_a.get(ip) {
            let host_diff = diff_host(ha, hb);
            if !host_diff.added_ports.is_empty()
                || !host_diff.removed_ports.is_empty()
                || !host_diff.changed_ports.is_empty()
            {
                d.changed.insert(ip.to_string(), host_diff);
            }
        }
    }
    for ip in map_a.keys() {
        if !map_b.contains_key(ip) {
            d.removed_hosts.push(ip.to_string());
        }
    }
    d
}

fn diff_host(
    a: &nmap_core::result::HostResult,
    b: &nmap_core::result::HostResult,
) -> HostDiff {
    let mut d = HostDiff::default();
    let map_a: BTreeMap<_, _> = a.ports.iter().map(|p| ((p.port.number, p.port.protocol), p)).collect();
    let map_b: BTreeMap<_, _> = b.ports.iter().map(|p| ((p.port.number, p.port.protocol), p)).collect();
    for k in map_b.keys() {
        if !map_a.contains_key(k) {
            d.added_ports.push(format!("{}/{}", k.0, k.1.short()));
        }
    }
    for (k, p_a) in &map_a {
        if let Some(p_b) = map_b.get(k) {
            if p_a.state != p_b.state {
                d.changed_ports.push(format!(
                    "{}/{}: {} -> {}",
                    k.0,
                    k.1.short(),
                    p_a.state.as_str(),
                    p_b.state.as_str()
                ));
            }
        } else {
            d.removed_ports.push(format!("{}/{}", k.0, k.1.short()));
        }
    }
    d
}

fn print_human(d: &Diff) {
    println!("Added hosts:");
    for h in &d.added_hosts {
        println!("  + {h}");
    }
    println!("Removed hosts:");
    for h in &d.removed_hosts {
        println!("  - {h}");
    }
    println!("Changed hosts:");
    for (h, hd) in &d.changed {
        println!("  ~ {h}");
        for p in &hd.added_ports {
            println!("      +{p}");
        }
        for p in &hd.removed_ports {
            println!("      -{p}");
        }
        for p in &hd.changed_ports {
            println!("      *{p}");
        }
    }
}
