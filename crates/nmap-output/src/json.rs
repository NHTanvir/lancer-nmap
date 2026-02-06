//! Lancer-extension JSON output: pretty-printed `ScanResult`.

use nmap_core::result::ScanResult;

pub fn emit(r: &ScanResult) -> String {
    serde_json::to_string_pretty(r).unwrap_or_default()
}
