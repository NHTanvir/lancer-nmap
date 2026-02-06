//! T0..T5 timing templates — the upstream knob values, intact.
//!
//! Reference: `timing.cc` in upstream nmap. The hard rule is **defaults must
//! match exactly** so behaviour is unsurprising to operators who memorised
//! `-T4` years ago.

use crate::options::{TimingOptions, TimingTemplate};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct TimingProfile {
    pub initial_rtt_timeout: Duration,
    pub min_rtt_timeout: Duration,
    pub max_rtt_timeout: Duration,
    pub max_retries: u32,
    pub host_timeout: Option<Duration>,
    pub scan_delay: Duration,
    pub max_scan_delay: Duration,
    pub min_hostgroup: usize,
    pub max_hostgroup: usize,
    pub min_parallelism: usize,
    pub max_parallelism: usize,
    pub min_rate: Option<u64>,
    pub max_rate: Option<u64>,
}

impl TimingProfile {
    pub fn from_template(t: TimingTemplate) -> Self {
        match t {
            TimingTemplate::Paranoid => Self {
                initial_rtt_timeout: Duration::from_millis(300_000),
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(300),
                max_retries: 10,
                host_timeout: None,
                scan_delay: Duration::from_secs(300),
                max_scan_delay: Duration::from_secs(300),
                min_hostgroup: 1,
                max_hostgroup: 1,
                min_parallelism: 1,
                max_parallelism: 1,
                min_rate: None,
                max_rate: Some(1),
            },
            TimingTemplate::Sneaky => Self {
                initial_rtt_timeout: Duration::from_millis(15_000),
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(15),
                max_retries: 10,
                host_timeout: None,
                scan_delay: Duration::from_secs(15),
                max_scan_delay: Duration::from_secs(15),
                min_hostgroup: 1,
                max_hostgroup: 1,
                min_parallelism: 1,
                max_parallelism: 1,
                min_rate: None,
                max_rate: Some(10),
            },
            TimingTemplate::Polite => Self {
                initial_rtt_timeout: Duration::from_millis(1_000),
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                max_retries: 10,
                host_timeout: None,
                scan_delay: Duration::from_millis(400),
                max_scan_delay: Duration::from_secs(1),
                min_hostgroup: 4,
                max_hostgroup: 100,
                min_parallelism: 1,
                max_parallelism: 1,
                min_rate: None,
                max_rate: Some(100),
            },
            TimingTemplate::Normal => Self {
                initial_rtt_timeout: Duration::from_millis(1_000),
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                max_retries: 10,
                host_timeout: None,
                scan_delay: Duration::ZERO,
                max_scan_delay: Duration::from_secs(1),
                min_hostgroup: 4,
                max_hostgroup: 1024,
                min_parallelism: 5,
                max_parallelism: 1024,
                min_rate: None,
                max_rate: None,
            },
            TimingTemplate::Aggressive => Self {
                initial_rtt_timeout: Duration::from_millis(500),
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_millis(1_250),
                max_retries: 6,
                host_timeout: Some(Duration::from_secs(900)),
                scan_delay: Duration::ZERO,
                max_scan_delay: Duration::from_millis(10),
                min_hostgroup: 256,
                max_hostgroup: 4096,
                min_parallelism: 10,
                max_parallelism: 4096,
                min_rate: Some(1),
                max_rate: None,
            },
            TimingTemplate::Insane => Self {
                initial_rtt_timeout: Duration::from_millis(250),
                min_rtt_timeout: Duration::from_millis(50),
                max_rtt_timeout: Duration::from_millis(300),
                max_retries: 2,
                host_timeout: Some(Duration::from_secs(900)),
                scan_delay: Duration::ZERO,
                max_scan_delay: Duration::from_millis(5),
                min_hostgroup: 1024,
                max_hostgroup: 16384,
                min_parallelism: 100,
                max_parallelism: 16384,
                min_rate: Some(100),
                max_rate: None,
            },
        }
    }

    /// Layer per-flag overrides on top of the template baseline.
    pub fn apply_overrides(mut self, opts: &TimingOptions) -> Self {
        if let Some(v) = opts.initial_rtt_timeout {
            self.initial_rtt_timeout = v;
        }
        if let Some(v) = opts.min_rtt_timeout {
            self.min_rtt_timeout = v;
        }
        if let Some(v) = opts.max_rtt_timeout {
            self.max_rtt_timeout = v;
        }
        if let Some(v) = opts.max_retries {
            self.max_retries = v;
        }
        if let Some(v) = opts.host_timeout {
            self.host_timeout = Some(v);
        }
        if let Some(v) = opts.scan_delay {
            self.scan_delay = v;
        }
        if let Some(v) = opts.max_scan_delay {
            self.max_scan_delay = v;
        }
        if let Some(v) = opts.min_hostgroup {
            self.min_hostgroup = v;
        }
        if let Some(v) = opts.max_hostgroup {
            self.max_hostgroup = v;
        }
        if let Some(v) = opts.min_parallelism {
            self.min_parallelism = v;
        }
        if let Some(v) = opts.max_parallelism {
            self.max_parallelism = v;
        }
        if let Some(v) = opts.min_rate {
            self.min_rate = Some(v);
        }
        if let Some(v) = opts.max_rate {
            self.max_rate = Some(v);
        }
        self
    }

    pub fn from_options(opts: &TimingOptions) -> Self {
        Self::from_template(opts.template).apply_overrides(opts)
    }
}
