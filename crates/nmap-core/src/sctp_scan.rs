//! `-sY` SCTP INIT and `-sZ` SCTP COOKIE-ECHO scans.

use crate::error::{Error, Result};
use crate::options::ScanOptions;
use crate::port::Port;
use crate::result::HostResult;
use crate::target::Target;

#[derive(Clone, Copy, Debug)]
pub enum SctpKind {
    Init,
    CookieEcho,
}

pub struct SctpScanner {
    pub kind: SctpKind,
}

impl SctpScanner {
    pub fn new(kind: SctpKind) -> Self {
        Self { kind }
    }

    pub async fn scan_host(
        &self,
        _target: &Target,
        _ports: &[Port],
        _opts: &ScanOptions,
    ) -> Result<HostResult> {
        Err(Error::Unsupported(format!(
            "SCTP scan ({:?}) requires raw SCTP support",
            self.kind
        )))
    }
}
