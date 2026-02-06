//! `-sI zombie:port` idle/zombie scan — IPID side-channel scan via a
//! third-party "zombie" host with predictable IPIDs.

use crate::error::{Error, Result};
use crate::options::ScanOptions;
use crate::port::Port;
use crate::result::HostResult;
use crate::target::Target;

pub struct IdleScanner {
    pub zombie: String,
}

impl IdleScanner {
    pub fn new(zombie: impl Into<String>) -> Self {
        Self { zombie: zombie.into() }
    }

    pub async fn scan_host(
        &self,
        _target: &Target,
        _ports: &[Port],
        _opts: &ScanOptions,
    ) -> Result<HostResult> {
        Err(Error::Unsupported(format!(
            "idle/zombie scan requires raw sockets + a stable IPID host (`{}`) — not available in this environment",
            self.zombie
        )))
    }
}
