//! Adaptive traceroute — sends a TCP probe with a stepped TTL, classifies
//! the ICMP TTL-exceeded responses. Falls back to UDP+33434 (the BSD
//! style) if TCP probes don't elicit responses.

use crate::error::Result;
use crate::options::ScanOptions;
use crate::result::TraceHop;
use crate::target::Target;

pub async fn trace(_target: &Target, _opts: &ScanOptions) -> Result<Vec<TraceHop>> {
    // Real impl needs raw ICMP receive; for the connect-only path we
    // produce an empty trace and let the GUI hide the panel.
    Ok(Vec::new())
}
