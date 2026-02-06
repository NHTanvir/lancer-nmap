//! `-sO` IP protocol scan — enumerate which IP protocol numbers are
//! supported by the target's network stack.

use crate::error::{Error, Result};
use crate::options::ScanOptions;
use crate::port::Port;
use crate::result::HostResult;
use crate::target::Target;

pub struct IpProtoScanner;

impl IpProtoScanner {
    pub fn new() -> Self {
        Self
    }

    pub async fn scan_host(
        &self,
        _target: &Target,
        _ports: &[Port],
        _opts: &ScanOptions,
    ) -> Result<HostResult> {
        Err(Error::Unsupported(
            "IP-protocol scan needs raw socket support".into(),
        ))
    }
}
