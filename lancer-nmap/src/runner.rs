//! Output dispatcher used by the CLI plus the post-scan enrichment that
//! wires `nmap-probes` (-sV), `nmap-osdb` (-O), and `nmap-nse` (-sC /
//! --script) into the orchestrator's `HostResult`s.

use anyhow::Result;
use nmap_core::options::ScanOptions;
use nmap_core::result::{HostResult, PortState, ScanResult};
use std::path::Path;
use std::sync::Arc;

use crate::cli::CliArgs;

pub async fn enrich(result: &mut ScanResult, opts: &ScanOptions) {
    // Service detection (-sV).
    if opts.service_scan.enabled {
        let engine = nmap_probes::ServiceEngine::from_datadir(opts.datadir.as_deref())
            .with_intensity(opts.service_scan.effective_intensity());
        for host in &mut result.hosts {
            run_service_detection(host, &engine).await;
        }
    }

    // OS detection (-O). We don't have a raw-socket probe sender on every
    // platform, but we still score against the embedded DB using whatever
    // features were observable (TTL hints + open-port profile). This gives
    // operators a directional answer even on connect-only platforms.
    if opts.os_scan.enabled {
        let db = nmap_osdb::parse_db(&nmap_data::load_os_db(opts.datadir.as_deref()));
        for host in &mut result.hosts {
            let fv = synthesize_features(host);
            let matches = nmap_osdb::score(&db, &fv, 5);
            host.os_matches = matches;
        }
    }

    // NSE — default scripts (-sC) or explicit --script spec.
    if opts.nse.default_scripts || !opts.nse.script_spec.is_empty() {
        let engine = nmap_nse::Engine::new();
        let filter = if opts.nse.default_scripts && opts.nse.script_spec.is_empty() {
            let mut f = nmap_nse::categories::CategoryFilter::default();
            f.include.insert(nmap_nse::categories::Category::Default);
            f
        } else {
            let mut filter = nmap_nse::categories::CategoryFilter::default();
            for spec in &opts.nse.script_spec {
                let parsed = nmap_nse::categories::CategoryFilter::parse(spec);
                filter.include.extend(parsed.include);
                filter.exclude.extend(parsed.exclude);
                filter.include_names.extend(parsed.include_names);
                filter.exclude_names.extend(parsed.exclude_names);
            }
            filter
        };
        let selected = engine.registry.filter(&filter);
        for host in &mut result.hosts {
            run_nse(host, &engine, &selected, opts).await;
        }
    }
}

async fn run_service_detection(host: &mut HostResult, engine: &nmap_probes::ServiceEngine) {
    for port in &mut host.ports {
        if !matches!(port.state, PortState::Open | PortState::OpenFiltered) {
            continue;
        }
        let proto_is_tcp = matches!(port.port.protocol, nmap_core::port::Protocol::Tcp);
        let outcome = engine.probe(host.address, port.port.number, proto_is_tcp).await;
        match outcome {
            nmap_probes::ProbeOutcome::Hard(info) | nmap_probes::ProbeOutcome::Soft(info) => {
                port.service = Some(info);
            }
            _ => {
                if port.service.is_none() {
                    if let Some(name) = nmap_data::services::service_name(
                        port.port.number,
                        port.port.protocol.short(),
                    ) {
                        let mut info = nmap_core::result::ServiceInfo::default();
                        info.name = Some(name.to_string());
                        info.method = Some("table".into());
                        info.conf = 3;
                        port.service = Some(info);
                    }
                }
            }
        }
    }
}

async fn run_nse(
    host: &mut HostResult,
    engine: &nmap_nse::Engine,
    scripts: &[nmap_nse::Script],
    opts: &ScanOptions,
) {
    if scripts.is_empty() {
        return;
    }
    let host_arc = Arc::new(host.clone());
    let mut args = indexmap::IndexMap::new();
    for (k, v) in &opts.nse.script_args {
        args.insert(k.clone(), v.clone());
    }
    // Per-port scripts (anything with a portrule).
    let ports_snapshot = host.ports.clone();
    for port in ports_snapshot {
        if !matches!(port.state, PortState::Open) {
            continue;
        }
        for script in scripts {
            let inv = nmap_nse::ScriptInvocation {
                host: host_arc.clone(),
                port: Some(port.clone()),
                args: args.clone(),
                timeout: std::time::Duration::from_secs(60),
            };
            let out = engine.run_script(script, inv).await;
            if let Some(p) = host.ports.iter_mut().find(|p| p.port == port.port) {
                p.scripts.push(out.result);
            }
        }
    }
}

fn synthesize_features(host: &HostResult) -> nmap_osdb::FeatureVector {
    use nmap_osdb::FeatureVector;
    let mut fv = FeatureVector::default();
    // Crude inference from observed TTLs. Real impl would gather these via
    // the 16 OS-detection probes.
    let ttl = host
        .ports
        .iter()
        .filter_map(|p| p.reason.as_ref().and_then(|r| r.ttl))
        .next();
    if let Some(t) = ttl {
        let approx_initial = match t {
            0..=64 => 64u32,
            65..=128 => 128,
            _ => 255,
        };
        fv.set("T1", "T", format!("{approx_initial:X}"));
        fv.set("ECN", "T", format!("{approx_initial:X}"));
        fv.set("IE", "T", format!("{approx_initial:X}"));
    }
    fv
}

pub fn emit_outputs(r: &ScanResult, args: &CliArgs) -> Result<()> {
    // Always echo normal output to stdout.
    let normal = nmap_output::emit_normal(r);
    println!("{normal}");

    if let Some(p) = &args.on {
        write_file(p, &normal, args.append_output)?;
    }
    if let Some(p) = &args.ox {
        write_file(p, &nmap_output::emit_xml(r), args.append_output)?;
    }
    if let Some(p) = &args.og {
        write_file(p, &nmap_output::emit_grepable(r), args.append_output)?;
    }
    if let Some(p) = &args.os {
        write_file(p, &nmap_output::emit_script_kiddie(r), args.append_output)?;
    }
    if let Some(p) = &args.oj {
        write_file(p, &nmap_output::emit_json(r), args.append_output)?;
    }
    if let Some(p) = &args.osarif {
        write_file(p, &nmap_output::emit_sarif(r), args.append_output)?;
    }
    if let Some(p) = &args.ocsv {
        write_file(p, &nmap_output::emit_csv(r), args.append_output)?;
    }
    if let Some(base) = &args.oa {
        let base_str = base.to_string_lossy();
        write_file(Path::new(&format!("{base_str}.nmap")), &normal, args.append_output)?;
        write_file(Path::new(&format!("{base_str}.xml")), &nmap_output::emit_xml(r), args.append_output)?;
        write_file(Path::new(&format!("{base_str}.gnmap")), &nmap_output::emit_grepable(r), args.append_output)?;
    }
    Ok(())
}

fn write_file(path: &Path, contents: &str, append: bool) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(!append)
        .append(append)
        .open(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}
