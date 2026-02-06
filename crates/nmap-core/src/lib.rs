//! nmap-core — the engine behind lancer-nmap.
//!
//! Provides the type system shared across every other workspace crate
//! (`nmap-probes`, `nmap-osdb`, `nmap-nse`, `nmap-output`, `nmap-gui`,
//! `lancer-nmap`) plus the orchestrator that drives target enumeration,
//! host discovery, port scanning, service detection, OS detection,
//! NSE script execution, and result fan-out.

#![allow(clippy::too_many_arguments)]

pub mod error;
pub mod target;
pub mod port;
pub mod scan;
pub mod options;
pub mod result;
pub mod timing;
pub mod discovery;
pub mod connect_scan;
pub mod syn_scan;
pub mod udp_scan;
pub mod stealth_scan;
pub mod ack_scan;
pub mod window_scan;
pub mod maimon_scan;
pub mod idle_scan;
pub mod sctp_scan;
pub mod ipproto_scan;
pub mod ftp_bounce;
pub mod evasion;
pub mod ratelimit;
pub mod resolver;
pub mod rtt;
pub mod congestion;
pub mod capability;
pub mod scanner;
pub mod packet;
pub mod traceroute;
pub mod resume;

pub use error::{Error, Result};
pub use target::{Target, TargetGroup, TargetSpec};
pub use port::{Port, PortRange, PortSpec, Protocol};
pub use scan::{ScanType, ScanFamily};
pub use options::{
    DiscoveryOptions, EvasionOptions, NseOptions, OsScanOptions, OutputOptions, PortScanOptions,
    ScanOptions, ServiceScanOptions, TimingOptions, TimingTemplate,
};
pub use result::{
    HostResult, HostState, OsMatch, PortResult, PortState, ScanResult, ScriptResult, ServiceInfo,
    StateReason, TraceHop,
};
pub use scanner::Scanner;
