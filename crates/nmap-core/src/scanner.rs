//! `Scanner` — the orchestrator that wires together target enumeration,
//! discovery, port-scan, traceroute, and (via downstream crates) service
//! detection, OS detection, NSE scripts, and output emission.
//!
//! Public surface used by `lancer-nmap` (binary), `nmap-gui`, and any
//! external embedder (Lancer §37 Bulk Probe pipeline).

use crate::ack_scan::AckScanner;
use crate::connect_scan::ConnectScanner;
use crate::discovery::Discovery;
use crate::error::Result;
use crate::evasion::EvasionPlan;
use crate::ftp_bounce::FtpBounceScanner;
use crate::idle_scan::IdleScanner;
use crate::ipproto_scan::IpProtoScanner;
use crate::maimon_scan::MaimonScanner;
use crate::options::ScanOptions;
use crate::port::{Port, PortSpec, Protocol};
use crate::resolver::Resolver;
use crate::result::{HostResult, HostState, ScanResult, StateReason};
use crate::resume;
use crate::scan::ScanType;
use crate::sctp_scan::{SctpKind, SctpScanner};
use crate::stealth_scan::{raw_tcp_scan, TcpFlavor};
use crate::syn_scan::SynScanner;
use crate::target::{expand_offline, Target, TargetGroup};
use crate::timing::TimingProfile;
use crate::udp_scan::UdpScanner;
use crate::window_scan::WindowScanner;
use chrono::Utc;
use futures::stream::{FuturesUnordered, StreamExt};
use rand::seq::SliceRandom;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{info, warn};

#[derive(Clone)]
pub struct Scanner {
    opts: Arc<ScanOptions>,
}

impl Scanner {
    pub fn new(opts: ScanOptions) -> Self {
        Self { opts: Arc::new(opts) }
    }

    /// Resolve targets, optionally apply `--unique`/`--resolve-all`, and
    /// optionally apply `--randomize-hosts`.
    pub async fn resolve_targets(&self) -> Result<Vec<Target>> {
        let (mut offline, hosts_pending) = expand_offline(&self.opts.targets)?;
        if !hosts_pending.is_empty() {
            let resolver = Resolver::from_options(
                &self.opts.targets.dns_servers,
                self.opts.targets.system_dns,
                self.opts.targets.resolve_all,
            )?;
            for h in &hosts_pending {
                match resolver.lookup(h).await {
                    Ok(v) => offline.extend(v),
                    Err(e) => warn!(host=%h, error=%e, "resolution failed"),
                }
            }
        }
        if self.opts.targets.unique {
            crate::target::dedupe_targets(&mut offline);
        }
        if self.opts.evasion.randomize_hosts {
            offline.shuffle(&mut rand::thread_rng());
        }
        Ok(offline)
    }

    /// Final, materialised list of ports to scan, after `--top-ports`,
    /// `-F`, `--exclude-ports`.
    pub fn port_plan(&self) -> PortSpec {
        let ps = &self.opts.port_scan;
        let mut spec = if ps.fast {
            crate::port::top_ports(100)
        } else if let Some(n) = ps.top_ports {
            crate::port::top_ports(n)
        } else {
            ps.ports.clone()
        };
        if spec.is_empty() {
            spec = crate::port::top_ports(1000);
        }
        spec.remove(&ps.exclude_ports);
        spec
    }

    /// Stream results host-by-host.
    pub async fn scan_stream(&self) -> Result<mpsc::Receiver<HostResult>> {
        let (tx, rx) = mpsc::channel(128);
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = me.scan_drive(tx).await {
                warn!(error=%e, "scan stream aborted");
            }
        });
        Ok(rx)
    }

    async fn scan_drive(&self, tx: mpsc::Sender<HostResult>) -> Result<()> {
        let targets = self.resolve_targets().await?;
        let port_plan = self.port_plan();
        let ports: Vec<Port> = port_plan.iter().collect();
        let discovery = Discovery::from_options(&self.opts);
        let mut futs = FuturesUnordered::new();
        let timing = TimingProfile::from_options(&self.opts.timing);
        let _evasion = EvasionPlan::from(&self.opts.evasion);

        let max_hosts = timing.max_hostgroup.max(timing.min_hostgroup).max(1);
        let prev = self
            .opts
            .resume_file
            .as_ref()
            .and_then(|p| resume::load_checkpoint(p).ok());
        let skip = prev
            .as_ref()
            .map(resume::completed_hosts)
            .unwrap_or_default();

        let mut iter = targets.into_iter().filter(|t| !skip.contains(&t.ip));
        loop {
            while futs.len() < max_hosts {
                let Some(t) = iter.next() else { break };
                let me = self.clone();
                let ports = ports.clone();
                let discovery = Discovery::from_options(&self.opts);
                futs.push(tokio::spawn(async move {
                    me.scan_single(t, &ports, &discovery).await
                }));
            }
            tokio::select! {
                Some(done) = futs.next() => {
                    match done {
                        Ok(Ok(h)) => {
                            let _ = tx.send(h).await;
                        }
                        Ok(Err(e)) => warn!(error=%e, "host scan failed"),
                        Err(e) => warn!(error=%e, "host task panicked"),
                    }
                }
                else => break,
            }
            if self.opts.cancelled() {
                break;
            }
            if futs.is_empty() && iter.size_hint().0 == 0 {
                break;
            }
        }
        Ok(())
    }

    async fn scan_single(
        &self,
        target: Target,
        ports: &[Port],
        discovery: &Discovery,
    ) -> Result<HostResult> {
        // Discovery prelude.
        let host_pre = discovery.is_alive(&target, &self.opts).await?;
        if matches!(host_pre.state, HostState::Down) && !self.opts.discovery.skip_discovery {
            return Ok(host_pre);
        }
        let scan_types = self.scan_types();
        let mut merged = host_pre.clone();
        merged.state = HostState::Up;
        for st in scan_types {
            let res = match st {
                ScanType::TcpConnect => ConnectScanner::new(&self.opts)
                    .scan_host(&target, ports, &self.opts)
                    .await?,
                ScanType::SynStealth => SynScanner::new(&self.opts)
                    .scan_host(&target, ports, &self.opts)
                    .await?,
                ScanType::Udp => UdpScanner::new(&self.opts)
                    .scan_host(&target, ports, &self.opts)
                    .await?,
                ScanType::Null => raw_tcp_scan(
                    &target,
                    ports,
                    &self.opts,
                    &TimingProfile::from_options(&self.opts.timing),
                    &crate::ratelimit::RateGate::unlimited(),
                    &crate::rtt::RttBook::new(),
                    &crate::congestion::CongestionBook::default(),
                    TcpFlavor::Null,
                )
                .await?,
                ScanType::Fin => raw_tcp_scan(
                    &target,
                    ports,
                    &self.opts,
                    &TimingProfile::from_options(&self.opts.timing),
                    &crate::ratelimit::RateGate::unlimited(),
                    &crate::rtt::RttBook::new(),
                    &crate::congestion::CongestionBook::default(),
                    TcpFlavor::Fin,
                )
                .await?,
                ScanType::Xmas => raw_tcp_scan(
                    &target,
                    ports,
                    &self.opts,
                    &TimingProfile::from_options(&self.opts.timing),
                    &crate::ratelimit::RateGate::unlimited(),
                    &crate::rtt::RttBook::new(),
                    &crate::congestion::CongestionBook::default(),
                    TcpFlavor::Xmas,
                )
                .await?,
                ScanType::Ack => AckScanner::new(&self.opts)
                    .scan_host(&target, ports, &self.opts)
                    .await?,
                ScanType::Window => WindowScanner::new(&self.opts)
                    .scan_host(&target, ports, &self.opts)
                    .await?,
                ScanType::Maimon => MaimonScanner::new(&self.opts)
                    .scan_host(&target, ports, &self.opts)
                    .await?,
                ScanType::IdleZombie => {
                    let z = self
                        .opts
                        .port_scan
                        .idle_zombie
                        .clone()
                        .unwrap_or_else(|| "unknown".into());
                    IdleScanner::new(z)
                        .scan_host(&target, ports, &self.opts)
                        .await
                        .unwrap_or_else(|_| host_pre.clone())
                }
                ScanType::IpProtocol => IpProtoScanner::new()
                    .scan_host(&target, ports, &self.opts)
                    .await
                    .unwrap_or_else(|_| host_pre.clone()),
                ScanType::SctpInit => SctpScanner::new(SctpKind::Init)
                    .scan_host(&target, ports, &self.opts)
                    .await
                    .unwrap_or_else(|_| host_pre.clone()),
                ScanType::SctpCookieEcho => SctpScanner::new(SctpKind::CookieEcho)
                    .scan_host(&target, ports, &self.opts)
                    .await
                    .unwrap_or_else(|_| host_pre.clone()),
                ScanType::FtpBounce => {
                    let r = self
                        .opts
                        .port_scan
                        .ftp_bounce
                        .clone()
                        .unwrap_or_else(|| "ftp.localhost".into());
                    FtpBounceScanner::new(r)
                        .scan_host(&target, ports, &self.opts)
                        .await
                        .unwrap_or_else(|_| host_pre.clone())
                }
                ScanType::Custom => raw_tcp_scan(
                    &target,
                    ports,
                    &self.opts,
                    &TimingProfile::from_options(&self.opts.timing),
                    &crate::ratelimit::RateGate::unlimited(),
                    &crate::rtt::RttBook::new(),
                    &crate::congestion::CongestionBook::default(),
                    TcpFlavor::Custom(0x02),
                )
                .await?,
                ScanType::PingOnly => host_pre.clone(),
            };
            merge_host(&mut merged, res);
        }
        Ok(merged)
    }

    pub fn scan_types(&self) -> Vec<ScanType> {
        let st = &self.opts.port_scan.scan_types;
        if st.is_empty() {
            vec![ScanType::TcpConnect]
        } else {
            st.clone()
        }
    }

    /// One-shot scan that collects into a `ScanResult` (used by tests, GUI,
    /// and Lancer §37 / §35 / §36 batch wiring).
    pub async fn run(&self) -> Result<ScanResult> {
        let started = Instant::now();
        let start_utc = Utc::now();
        let mut rx = self.scan_stream().await?;
        let mut result = ScanResult::default();
        while let Some(h) = rx.recv().await {
            if matches!(h.state, HostState::Up) {
                result.summary_up += 1;
            } else if matches!(h.state, HostState::Down) {
                result.summary_down += 1;
            }
            result.summary_total += 1;
            result.hosts.push(h);
        }
        result.start = start_utc;
        result.end = Utc::now();
        result.elapsed = started.elapsed();
        if let Some(p) = &self.opts.resume_file {
            let _ = resume::save_checkpoint(p, &result);
        }
        Ok(result)
    }

    pub fn options(&self) -> &ScanOptions {
        &self.opts
    }
}

fn merge_host(into: &mut HostResult, mut other: HostResult) {
    if into.state != HostState::Up {
        into.state = other.state;
    }
    into.ports.append(&mut other.ports);
    into.host_scripts.append(&mut other.host_scripts);
    into.os_matches.append(&mut other.os_matches);
    if into.state_reason.is_none() && other.state_reason.is_some() {
        into.state_reason = other.state_reason;
    }
    if into.mac.is_none() {
        into.mac = other.mac;
    }
    if into.vendor.is_none() {
        into.vendor = other.vendor;
    }
    if into.distance.is_none() {
        into.distance = other.distance;
    }
    if into.trace.is_empty() {
        into.trace = other.trace;
    }
    if into.last_boot.is_none() {
        into.last_boot = other.last_boot;
    }
    if into.uptime_seconds.is_none() {
        into.uptime_seconds = other.uptime_seconds;
    }
    if into.end < other.end {
        into.end = other.end;
    }
    into.duration += other.duration;
    if into.state_reason.is_none() && matches!(into.state, HostState::Up) {
        into.state_reason = Some(StateReason::new("user-set"));
    }
    let _ = Duration::ZERO; // keep the import alive in case scanner skeleton evolves
}
