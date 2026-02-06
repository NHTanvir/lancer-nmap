//! Result types — the structured output of a scan, consumed by every
//! emitter, by the GUI, and by the Lancer §37 Bulk Probe pipeline.

use crate::port::{Port, Protocol};
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum HostState {
    Up,
    Down,
    Unknown,
    SkippedDiscovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
    ClosedFiltered,
}

impl PortState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Filtered => "filtered",
            Self::Unfiltered => "unfiltered",
            Self::OpenFiltered => "open|filtered",
            Self::ClosedFiltered => "closed|filtered",
        }
    }
}

/// Reason annotation, used by `--reason`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateReason {
    pub reason: String,
    pub ttl: Option<u8>,
}

impl StateReason {
    pub fn new(reason: impl Into<String>) -> Self {
        Self { reason: reason.into(), ttl: None }
    }
    pub fn with_ttl(reason: impl Into<String>, ttl: u8) -> Self {
        Self { reason: reason.into(), ttl: Some(ttl) }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub hostname: Option<String>,
    pub os_type: Option<String>,
    pub device_type: Option<String>,
    pub cpe: Vec<String>,
    pub tunnel: Option<String>,
    pub method: Option<String>,
    pub conf: u8,
    pub fingerprint: Option<String>,
    pub soft: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScriptResult {
    pub id: String,
    pub output: String,
    pub elements: IndexMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortResult {
    pub port: Port,
    pub state: PortState,
    pub reason: Option<StateReason>,
    pub service: Option<ServiceInfo>,
    pub scripts: Vec<ScriptResult>,
}

impl PortResult {
    pub fn new(port: Port, state: PortState) -> Self {
        Self {
            port,
            state,
            reason: None,
            service: None,
            scripts: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OsMatch {
    pub name: String,
    pub accuracy: u8,
    pub line: u32,
    pub cpe: Vec<String>,
    pub os_class: Vec<OsClass>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OsClass {
    pub vendor: String,
    pub osfamily: String,
    pub osgen: Option<String>,
    pub kind: Option<String>,
    pub accuracy: u8,
    pub cpe: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceHop {
    pub ttl: u8,
    pub rtt_ms: f32,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostResult {
    pub address: IpAddr,
    pub mac: Option<String>,
    pub hostnames: Vec<String>,
    pub state: HostState,
    pub state_reason: Option<StateReason>,
    pub ports: Vec<PortResult>,
    pub extraports: Vec<(PortState, Protocol, usize)>,
    pub host_scripts: Vec<ScriptResult>,
    pub os_matches: Vec<OsMatch>,
    pub uptime_seconds: Option<u64>,
    pub last_boot: Option<DateTime<Utc>>,
    pub trace: Vec<TraceHop>,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub duration: Duration,
    pub distance: Option<u8>,
    pub vendor: Option<String>,
}

impl HostResult {
    pub fn new(address: IpAddr) -> Self {
        let now = Utc::now();
        Self {
            address,
            mac: None,
            hostnames: Vec::new(),
            state: HostState::Unknown,
            state_reason: None,
            ports: Vec::new(),
            extraports: Vec::new(),
            host_scripts: Vec::new(),
            os_matches: Vec::new(),
            uptime_seconds: None,
            last_boot: None,
            trace: Vec::new(),
            start: now,
            end: now,
            duration: Duration::ZERO,
            distance: None,
            vendor: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub args: String,
    pub command_line: Vec<String>,
    pub scanner: String,
    pub version: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub elapsed: Duration,
    pub hosts: Vec<HostResult>,
    pub summary_up: usize,
    pub summary_down: usize,
    pub summary_total: usize,
}

impl Default for ScanResult {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            args: String::new(),
            command_line: Vec::new(),
            scanner: "lancer-nmap".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            start: now,
            end: now,
            elapsed: Duration::ZERO,
            hosts: Vec::new(),
            summary_up: 0,
            summary_down: 0,
            summary_total: 0,
        }
    }
}
