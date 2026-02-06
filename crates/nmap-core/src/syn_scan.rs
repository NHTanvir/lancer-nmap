//! `-sS` TCP SYN stealth scan.
//!
//! Half-open scan: send SYN, classify on SYN-ACK → open, RST → closed,
//! no-response → filtered. Sends from raw IPv4/IPv6 sockets and receives
//! via pcap. Falls back to TCP connect when the raw path isn't usable.

use crate::capability::detect_raw;
use crate::congestion::CongestionBook;
use crate::connect_scan::ConnectScanner;
use crate::error::Result;
use crate::options::ScanOptions;
use crate::port::Port;
use crate::ratelimit::RateGate;
use crate::result::HostResult;
use crate::rtt::RttBook;
use crate::target::Target;
use crate::timing::TimingProfile;
use tracing::warn;

pub struct SynScanner {
    pub timing: TimingProfile,
    pub rate: RateGate,
    pub rtt: RttBook,
    pub cwnd: CongestionBook,
    privileged: bool,
}

impl SynScanner {
    pub fn new(opts: &ScanOptions) -> Self {
        let timing = TimingProfile::from_options(&opts.timing);
        let rate = match opts.timing.max_rate {
            Some(r) => RateGate::pps(r),
            None => RateGate::unlimited(),
        };
        let privileged = opts.privileged.unwrap_or_else(detect_raw);
        Self {
            timing,
            rate,
            rtt: RttBook::new(),
            cwnd: CongestionBook::default(),
            privileged,
        }
    }

    /// Scan one host. When no raw capability is available, falls back to
    /// `-sT` (TCP connect) — this matches upstream's quiet fallback path.
    pub async fn scan_host(
        &self,
        target: &Target,
        ports: &[Port],
        opts: &ScanOptions,
    ) -> Result<HostResult> {
        if !self.privileged {
            warn!("SYN scan requested but raw sockets unavailable — falling back to -sT");
            let connect = ConnectScanner::new(opts);
            return connect.scan_host(target, ports, opts).await;
        }
        #[cfg(feature = "raw")]
        {
            crate::stealth_scan::raw_tcp_scan(
                target,
                ports,
                opts,
                &self.timing,
                &self.rate,
                &self.rtt,
                &self.cwnd,
                crate::stealth_scan::TcpFlavor::Syn,
            )
            .await
        }
        #[cfg(not(feature = "raw"))]
        {
            let connect = ConnectScanner::new(opts);
            connect.scan_host(target, ports, opts).await
        }
    }
}
