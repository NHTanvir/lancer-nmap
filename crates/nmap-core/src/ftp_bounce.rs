//! `-b ftp.example.com` FTP bounce scan.
//!
//! Uses an open FTP server's PORT command to direct it to make connections
//! to a third-party target, exposing whether the third party port is open.

use crate::error::{Error, Result};
use crate::options::ScanOptions;
use crate::port::Port;
use crate::result::HostResult;
use crate::target::Target;

pub struct FtpBounceScanner {
    pub relay: String,
}

impl FtpBounceScanner {
    pub fn new(relay: impl Into<String>) -> Self {
        Self { relay: relay.into() }
    }

    pub async fn scan_host(
        &self,
        _target: &Target,
        _ports: &[Port],
        _opts: &ScanOptions,
    ) -> Result<HostResult> {
        Err(Error::Unsupported(
            "FTP bounce scan needs a relay with PORT-command support".into(),
        ))
    }
}
