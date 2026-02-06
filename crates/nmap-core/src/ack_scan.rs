//! `-sA` TCP ACK scan — firewall mapping. RST = unfiltered, no-response = filtered.

use crate::congestion::CongestionBook;
use crate::error::Result;
use crate::options::ScanOptions;
use crate::port::Port;
use crate::ratelimit::RateGate;
use crate::result::HostResult;
use crate::rtt::RttBook;
use crate::target::Target;
use crate::timing::TimingProfile;
use crate::stealth_scan::{raw_tcp_scan, TcpFlavor};

pub struct AckScanner {
    pub timing: TimingProfile,
    pub rate: RateGate,
    pub rtt: RttBook,
    pub cwnd: CongestionBook,
}

impl AckScanner {
    pub fn new(opts: &ScanOptions) -> Self {
        Self {
            timing: TimingProfile::from_options(&opts.timing),
            rate: match opts.timing.max_rate {
                Some(r) => RateGate::pps(r),
                None => RateGate::unlimited(),
            },
            rtt: RttBook::new(),
            cwnd: CongestionBook::default(),
        }
    }

    pub async fn scan_host(
        &self,
        target: &Target,
        ports: &[Port],
        opts: &ScanOptions,
    ) -> Result<HostResult> {
        raw_tcp_scan(
            target,
            ports,
            opts,
            &self.timing,
            &self.rate,
            &self.rtt,
            &self.cwnd,
            TcpFlavor::Ack,
        )
        .await
    }
}
