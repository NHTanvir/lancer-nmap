//! Output dispatcher used by the CLI plus the post-scan enrichment that
//! wires `nmap-probes` (-sV), `nmap-osdb` (-O), and `nmap-nse` (-sC /
//! --script) into the orchestrator's `HostResult`s.

use anyhow::Result;
use nmap_core::result::ScanResult;
use std::path::Path;

use crate::cli::CliArgs;

pub use nmap_engine::enrich;

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
