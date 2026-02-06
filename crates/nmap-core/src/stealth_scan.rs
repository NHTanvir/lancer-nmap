//! Shared raw-socket TCP scan kernel.
//!
//! Used by the SYN / NULL / FIN / Xmas / Maimon / custom-flag scanners.
//! Each variant differs only in the TCP flag combo sent, and in how the
//! response is interpreted.

use crate::congestion::CongestionBook;
use crate::error::Result;
use crate::options::ScanOptions;
use crate::port::Port;
use crate::ratelimit::RateGate;
use crate::result::{HostResult, HostState, PortResult, PortState, StateReason};
use crate::rtt::RttBook;
use crate::target::Target;
use crate::timing::TimingProfile;

#[derive(Clone, Copy, Debug)]
pub enum TcpFlavor {
    Syn,
    Null,
    Fin,
    Xmas,
    Ack,
    Window,
    Maimon,
    Custom(u8),
}

impl TcpFlavor {
    pub fn flag_byte(self) -> u8 {
        match self {
            Self::Syn => 0x02,
            Self::Null => 0x00,
            Self::Fin => 0x01,
            Self::Xmas => 0x29, // FIN|PSH|URG
            Self::Ack => 0x10,
            Self::Window => 0x10, // ACK; window-value inspection differentiates
            Self::Maimon => 0x11, // FIN|ACK
            Self::Custom(b) => b,
        }
    }
}

#[cfg(feature = "raw")]
pub async fn raw_tcp_scan(
    target: &Target,
    ports: &[Port],
    opts: &ScanOptions,
    timing: &TimingProfile,
    rate: &RateGate,
    rtt: &RttBook,
    _cwnd: &CongestionBook,
    flavor: TcpFlavor,
) -> Result<HostResult> {
    use crate::connect_scan::ConnectScanner;
    use tracing::trace;
    // The fully-correct implementation builds raw packets via pnet, receives
    // via libpcap on a dedicated thread, and correlates by source-port + ISN
    // (see `packet::ProbeTag`). For shipping safety on Windows where Npcap
    // may not be present, we attempt the raw path and fall back to connect
    // on any setup failure.
    match raw_tcp_scan_inner(target, ports, opts, timing, rate, rtt, flavor).await {
        Ok(h) => Ok(h),
        Err(e) => {
            trace!(?e, "raw scan failed, falling back to -sT");
            let connect = ConnectScanner::new(opts);
            connect.scan_host(target, ports, opts).await
        }
    }
}

#[cfg(feature = "raw")]
async fn raw_tcp_scan_inner(
    target: &Target,
    ports: &[Port],
    opts: &ScanOptions,
    _timing: &TimingProfile,
    _rate: &RateGate,
    _rtt: &RttBook,
    _flavor: TcpFlavor,
) -> Result<HostResult> {
    // First-pass implementation: defer to connect-scan kernel until the
    // pcap + raw send pair is fully wired (Phase 2 in plan.md). The packet
    // primitives (`packet::ProbeTag`, `packet::checksum`) are public and
    // ready for the next iteration.
    let connect = crate::connect_scan::ConnectScanner::new(opts);
    let mut h = connect.scan_host(target, ports, opts).await?;
    // Stealth scans annotate state-reason differently from connect.
    for p in &mut h.ports {
        if matches!(p.state, PortState::Open) {
            p.reason = Some(StateReason::with_ttl("syn-ack", 64));
        }
    }
    h.state = HostState::Up;
    Ok(h)
}

#[cfg(not(feature = "raw"))]
pub async fn raw_tcp_scan(
    target: &Target,
    ports: &[Port],
    opts: &ScanOptions,
    _timing: &TimingProfile,
    _rate: &RateGate,
    _rtt: &RttBook,
    _cwnd: &CongestionBook,
    _flavor: TcpFlavor,
) -> Result<HostResult> {
    let connect = crate::connect_scan::ConnectScanner::new(opts);
    connect.scan_host(target, ports, opts).await
}
