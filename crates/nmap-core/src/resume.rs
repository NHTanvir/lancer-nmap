//! Resume + checkpoint state: `--resume scan.nmap` reads the per-host
//! completion log and skips already-finished hosts.

use crate::error::Result;
use crate::result::ScanResult;
use std::path::Path;

pub fn load_checkpoint(path: &Path) -> Result<ScanResult> {
    let text = std::fs::read_to_string(path)?;
    // Prefer JSON checkpoint, fall back to attempting to parse XML in future.
    if let Ok(v) = serde_json::from_str::<ScanResult>(&text) {
        return Ok(v);
    }
    Ok(ScanResult::default())
}

pub fn save_checkpoint(path: &Path, result: &ScanResult) -> Result<()> {
    let text = serde_json::to_string_pretty(result)
        .map_err(|e| crate::error::Error::Other(e.to_string()))?;
    std::fs::write(path, text)?;
    Ok(())
}

/// Returns the set of host addresses to skip given a previously-saved scan.
pub fn completed_hosts(prev: &ScanResult) -> std::collections::HashSet<std::net::IpAddr> {
    prev.hosts.iter().map(|h| h.address).collect()
}
