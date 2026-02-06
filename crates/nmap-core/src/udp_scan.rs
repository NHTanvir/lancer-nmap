//! `-sU` UDP scan.
//!
//! Send service-specific payloads from `nmap-payloads` to common UDP ports.
//! Classification: ICMP type-3 code-3 = closed; payload response = open;
//! ICMP type-3 codes 1/2/9/10/13 = filtered; silence = open|filtered.

use crate::congestion::CongestionBook;
use crate::connect_scan::ConnectScanner;
use crate::error::Result;
use crate::options::ScanOptions;
use crate::port::{Port, Protocol};
use crate::ratelimit::{pace, RateGate};
use crate::result::{HostResult, HostState, PortResult, PortState, StateReason};
use crate::rtt::RttBook;
use crate::target::Target;
use crate::timing::TimingProfile;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::trace;

pub struct UdpScanner {
    pub timing: TimingProfile,
    pub rate: RateGate,
    pub rtt: RttBook,
    pub cwnd: CongestionBook,
}

impl UdpScanner {
    pub fn new(opts: &ScanOptions) -> Self {
        let timing = TimingProfile::from_options(&opts.timing);
        let rate = match opts.timing.max_rate {
            Some(r) => RateGate::pps(r),
            None => RateGate::unlimited(),
        };
        Self {
            timing,
            rate,
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
        let host_start = std::time::Instant::now();
        let start = chrono::Utc::now();
        let mut host = HostResult::new(target.ip);
        if let Some(h) = &target.hostname {
            host.hostnames.push(h.clone());
        }
        let parallel = self.timing.max_parallelism.max(1);
        let sem = Arc::new(Semaphore::new(parallel));
        let mut tasks = tokio::task::JoinSet::new();
        let to = self.timing.initial_rtt_timeout.min(self.timing.max_rtt_timeout);

        for &p in ports.iter().filter(|p| p.protocol == Protocol::Udp) {
            if opts.cancelled() {
                break;
            }
            let permit = sem.clone().acquire_owned().await.unwrap();
            let rate = self.rate.clone();
            let scan_delay = self.timing.scan_delay;
            let ip = target.ip;
            tasks.spawn(async move {
                pace(scan_delay, &rate).await;
                let state = probe_udp(ip, p.number, to).await;
                drop(permit);
                (p, state)
            });
        }
        while let Some(res) = tasks.join_next().await {
            if let Ok((port, state)) = res {
                let mut pr = PortResult::new(port, state);
                pr.reason = Some(StateReason::new(match state {
                    PortState::Open => "udp-response",
                    PortState::Closed => "port-unreach",
                    PortState::OpenFiltered => "no-udp-response",
                    PortState::Filtered => "no-response",
                    _ => "unknown",
                }));
                host.ports.push(pr);
            }
        }
        host.ports.sort_by(|a, b| a.port.number.cmp(&b.port.number));
        host.state = HostState::Up;
        host.start = start;
        host.end = chrono::Utc::now();
        host.duration = host_start.elapsed();

        // Also scan any TCP ports asked for, via the connect path, so callers
        // can mix protocols without re-issuing.
        let mut had_tcp = false;
        for p in ports {
            if p.protocol == Protocol::Tcp {
                had_tcp = true;
                break;
            }
        }
        if had_tcp {
            let connect = ConnectScanner::new(opts);
            let tcp_host = connect.scan_host(target, ports, opts).await?;
            host.ports.extend(tcp_host.ports);
        }
        Ok(host)
    }
}

async fn probe_udp(ip: std::net::IpAddr, port: u16, t: Duration) -> PortState {
    let bind = match ip {
        std::net::IpAddr::V4(_) => "0.0.0.0:0",
        std::net::IpAddr::V6(_) => "[::]:0",
    };
    let sock = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            trace!(?e, "udp bind failed");
            return PortState::OpenFiltered;
        }
    };
    if let Err(e) = sock.connect(SocketAddr::new(ip, port)).await {
        trace!(?e, "udp connect failed");
        return PortState::OpenFiltered;
    }
    let payload = nmap_data::payloads::for_port(port).unwrap_or(b"\x00");
    if let Err(_) = sock.send(payload).await {
        return PortState::OpenFiltered;
    }
    let mut buf = vec![0u8; 1500];
    match timeout(t, sock.recv(&mut buf)).await {
        Ok(Ok(_)) => PortState::Open,
        Ok(Err(e)) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused => PortState::Closed,
            _ => PortState::OpenFiltered,
        },
        Err(_) => PortState::OpenFiltered,
    }
}
