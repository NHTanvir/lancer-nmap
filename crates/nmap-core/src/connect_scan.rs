//! `-sT` TCP connect scan — the unprivileged default.
//!
//! Drives an arbitrary `(host, port)` matrix through `tokio::net::TcpStream::connect`
//! with per-host SRTT/RTTVAR + congestion control + a global rate gate. This
//! is the path that always works regardless of caps; every other scanner
//! falls back to this when raw sockets aren't available.

use crate::congestion::CongestionBook;
use crate::error::Result;
use crate::options::ScanOptions;
use crate::port::{Port, Protocol};
use crate::ratelimit::{pace, RateGate};
use crate::result::{HostResult, HostState, PortResult, PortState, StateReason};
use crate::rtt::RttBook;
use crate::target::Target;
use crate::timing::TimingProfile;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::trace;

pub struct ConnectScanner {
    pub timing: TimingProfile,
    pub rate: RateGate,
    pub rtt: RttBook,
    pub cwnd: CongestionBook,
}

impl ConnectScanner {
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

    /// Scan one host's worth of ports.
    pub async fn scan_host(
        &self,
        target: &Target,
        ports: &[Port],
        opts: &ScanOptions,
    ) -> Result<HostResult> {
        let start = chrono::Utc::now();
        let host_start = Instant::now();
        let mut host = HostResult::new(target.ip);
        if let Some(h) = &target.hostname {
            host.hostnames.push(h.clone());
        }
        let max_parallel = self
            .timing
            .max_parallelism
            .max(self.timing.min_parallelism)
            .max(1);
        let sem = Arc::new(Semaphore::new(max_parallel));
        let mut tasks = tokio::task::JoinSet::new();
        for &port in ports.iter().filter(|p| p.protocol == Protocol::Tcp) {
            if opts.cancelled() {
                break;
            }
            let sem = sem.clone();
            let permit = sem.acquire_owned().await.unwrap();
            let rate = self.rate.clone();
            let scan_delay = self.timing.scan_delay;
            let initial = self.timing.initial_rtt_timeout;
            let max_t = self.timing.max_rtt_timeout;
            let ip = target.ip;
            tasks.spawn(async move {
                pace(scan_delay, &rate).await;
                let s = probe_tcp(ip, port.number, initial.min(max_t)).await;
                drop(permit);
                (port, s)
            });
        }
        while let Some(res) = tasks.join_next().await {
            if let Ok((port, outcome)) = res {
                let pr = match outcome {
                    ProbeOutcome::Open(d) => {
                        self.rtt.record(target.ip, d, self.timing.min_rtt_timeout, self.timing.max_rtt_timeout);
                        let mut p = PortResult::new(port, PortState::Open);
                        p.reason = Some(StateReason::new("syn-ack"));
                        p
                    }
                    ProbeOutcome::Closed(d) => {
                        self.rtt.record(target.ip, d, self.timing.min_rtt_timeout, self.timing.max_rtt_timeout);
                        let mut p = PortResult::new(port, PortState::Closed);
                        p.reason = Some(StateReason::new("conn-refused"));
                        p
                    }
                    ProbeOutcome::Filtered => {
                        let mut p = PortResult::new(port, PortState::Filtered);
                        p.reason = Some(StateReason::new("no-response"));
                        p
                    }
                    ProbeOutcome::Error(e) => {
                        trace!(?e, "probe error");
                        let mut p = PortResult::new(port, PortState::Filtered);
                        p.reason = Some(StateReason::new("error"));
                        p
                    }
                };
                host.ports.push(pr);
            }
        }
        host.ports.sort_by(|a, b| a.port.number.cmp(&b.port.number));
        host.state = if host.ports.iter().any(|p| matches!(p.state, PortState::Open | PortState::Closed)) {
            HostState::Up
        } else if opts.discovery.skip_discovery {
            HostState::Up
        } else {
            HostState::Up // -sT cannot distinguish "down" from "filtered"
        };
        host.end = chrono::Utc::now();
        host.duration = host_start.elapsed();
        Ok(host)
    }
}

enum ProbeOutcome {
    Open(Duration),
    Closed(Duration),
    Filtered,
    Error(io::Error),
}

async fn probe_tcp(ip: IpAddr, port: u16, t: Duration) -> ProbeOutcome {
    let addr = SocketAddr::new(ip, port);
    let t0 = Instant::now();
    match timeout(t, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => ProbeOutcome::Open(t0.elapsed()),
        Ok(Err(e)) => match e.kind() {
            io::ErrorKind::ConnectionRefused => ProbeOutcome::Closed(t0.elapsed()),
            io::ErrorKind::TimedOut => ProbeOutcome::Filtered,
            io::ErrorKind::PermissionDenied
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::AddrNotAvailable => ProbeOutcome::Filtered,
            _ => ProbeOutcome::Error(e),
        },
        Err(_) => ProbeOutcome::Filtered,
    }
}
