//! Host discovery — the prelude that decides whether to port-scan each
//! target at all (`-sn` / `-Pn` / `-PE` / `-PS` / `-PA` / `-PU` / `-PY` /
//! `-PR`).
//!
//! Unprivileged path uses TCP connect probes only (-PS-style on the
//! requested ports) because raw ICMP isn't available. Privileged path
//! sends ICMP echo + SYN + ACK + UDP + ARP from a dedicated packet
//! engine (see `syn_scan` + `pcap_rx`).

use crate::capability::detect_raw;
use crate::error::Result;
use crate::options::ScanOptions;
use crate::result::{HostResult, HostState, StateReason};
use crate::target::Target;
use crate::timing::TimingProfile;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct Discovery {
    pub timing: TimingProfile,
    pub privileged: bool,
    pub ignore_rst: bool,
}

impl Discovery {
    pub fn from_options(opts: &ScanOptions) -> Self {
        let privileged = opts
            .privileged
            .unwrap_or_else(detect_raw);
        Self {
            timing: TimingProfile::from_options(&opts.timing),
            privileged,
            ignore_rst: opts.discovery.ignore_rst,
        }
    }

    /// Quick test: is this host alive?
    pub async fn is_alive(&self, target: &Target, opts: &ScanOptions) -> Result<HostResult> {
        let start = chrono::Utc::now();
        let host_start = Instant::now();
        let mut host = HostResult::new(target.ip);
        if let Some(h) = &target.hostname {
            host.hostnames.push(h.clone());
        }
        if opts.discovery.skip_discovery {
            host.state = HostState::SkippedDiscovery;
            host.state_reason = Some(StateReason::new("user-set"));
            host.start = start;
            host.end = chrono::Utc::now();
            host.duration = host_start.elapsed();
            return Ok(host);
        }
        let probe_ports: Vec<u16> = if !opts.discovery.tcp_syn_ports.is_empty() {
            opts.discovery.tcp_syn_ports.clone()
        } else if !opts.discovery.tcp_ack_ports.is_empty() {
            opts.discovery.tcp_ack_ports.clone()
        } else {
            // Default probes per upstream when -Pn / explicit pings absent.
            vec![80, 443]
        };

        let t = self.timing.initial_rtt_timeout.min(self.timing.max_rtt_timeout);
        let mut alive = false;
        let mut reason = None;
        for p in &probe_ports {
            let addr = SocketAddr::new(target.ip, *p);
            match timeout(t, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => {
                    alive = true;
                    reason = Some(StateReason::new(format!("syn-ack/{p}")));
                    break;
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    alive = true;
                    reason = Some(StateReason::new(format!("conn-refused/{p}")));
                    break;
                }
                _ => continue,
            }
        }
        host.state = if alive { HostState::Up } else { HostState::Down };
        host.state_reason = reason;
        host.start = start;
        host.end = chrono::Utc::now();
        host.duration = host_start.elapsed();
        Ok(host)
    }
}

/// `Duration` helper: pick the lower bound for a discovery probe so we don't
/// over-spend the host's RTO budget.
pub fn discovery_timeout(t: &TimingProfile) -> Duration {
    let cap = t.max_rtt_timeout.min(Duration::from_secs(3));
    t.initial_rtt_timeout.min(cap)
}
