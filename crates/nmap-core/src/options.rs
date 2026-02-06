//! `ScanOptions` is the single source of truth that every scanner consumes.
//! It is intentionally allowed to be large — there are 200+ upstream flags
//! and parity is non-negotiable.

use crate::port::{PortSpec, Protocol};
use crate::scan::ScanType;
use crate::target::TargetGroup;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScanOptions {
    pub targets: TargetGroup,
    pub discovery: DiscoveryOptions,
    pub port_scan: PortScanOptions,
    pub service_scan: ServiceScanOptions,
    pub os_scan: OsScanOptions,
    pub nse: NseOptions,
    pub timing: TimingOptions,
    pub evasion: EvasionOptions,
    pub output: OutputOptions,
    /// `-6` — operate in IPv6 mode.
    pub ipv6: bool,
    /// `--privileged` / `--unprivileged` override.
    pub privileged: Option<bool>,
    /// `--datadir` override for embedded data files.
    pub datadir: Option<PathBuf>,
    /// Soft-cancel signal observed by every scanner.
    #[serde(skip)]
    pub cancel: Option<tokio_util::sync::CancellationToken>,
    /// `--vpn-passthrough` — auto-detect and bind to TAP/WireGuard adapter.
    pub vpn_passthrough: bool,
    /// `--resume <file>`
    pub resume_file: Option<PathBuf>,
}

impl ScanOptions {
    pub fn cancelled(&self) -> bool {
        self.cancel.as_ref().map(|t| t.is_cancelled()).unwrap_or(false)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DiscoveryOptions {
    /// `-Pn` — skip host discovery (assume alive).
    pub skip_discovery: bool,
    /// `-sn` — discovery only, no port scan.
    pub no_port_scan: bool,
    /// `-PE`
    pub icmp_echo: bool,
    /// `-PP`
    pub icmp_timestamp: bool,
    /// `-PM`
    pub icmp_mask: bool,
    /// `-PS22,80,443`
    pub tcp_syn_ports: Vec<u16>,
    /// `-PA80,443`
    pub tcp_ack_ports: Vec<u16>,
    /// `-PU53,161`
    pub udp_ports: Vec<u16>,
    /// `-PY80`
    pub sctp_ports: Vec<u16>,
    /// `-PO1,2,4`
    pub ip_protos: Vec<u8>,
    /// `-PR` — ARP ping; auto-on for local subnets.
    pub arp_ping: bool,
    /// `--traceroute`
    pub traceroute: bool,
    /// `--discovery-ignore-rst` (7.97+).
    pub ignore_rst: bool,
}

impl DiscoveryOptions {
    pub fn any_probe(&self) -> bool {
        self.icmp_echo
            || self.icmp_timestamp
            || self.icmp_mask
            || !self.tcp_syn_ports.is_empty()
            || !self.tcp_ack_ports.is_empty()
            || !self.udp_ports.is_empty()
            || !self.sctp_ports.is_empty()
            || !self.ip_protos.is_empty()
            || self.arp_ping
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortScanOptions {
    pub scan_types: Vec<ScanType>,
    pub ports: PortSpec,
    pub exclude_ports: PortSpec,
    pub default_proto: Protocol,
    /// `--top-ports N`
    pub top_ports: Option<usize>,
    /// `-F` (alias for top-100)
    pub fast: bool,
    /// `--port-ratio f`
    pub port_ratio: Option<f32>,
    /// `--scanflags URGACKPSHRSTSYNFIN`
    pub scanflags: Option<String>,
    /// `-sI zombie:port`
    pub idle_zombie: Option<String>,
    /// `-b ftp.example.com`
    pub ftp_bounce: Option<String>,
    /// `--badsum` (testing only, also evasion)
    pub badsum: bool,
}

impl Default for PortScanOptions {
    fn default() -> Self {
        Self {
            scan_types: vec![],
            ports: PortSpec::default(),
            exclude_ports: PortSpec::default(),
            default_proto: Protocol::Tcp,
            top_ports: None,
            fast: false,
            port_ratio: None,
            scanflags: None,
            idle_zombie: None,
            ftp_bounce: None,
            badsum: false,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServiceScanOptions {
    /// `-sV`
    pub enabled: bool,
    /// `--version-intensity 0-9`
    pub intensity: u8,
    /// `--version-light` → intensity 2
    pub light: bool,
    /// `--version-all` → intensity 9
    pub all_probes: bool,
    /// `--version-trace`
    pub trace: bool,
    /// `--allports`
    pub all_ports: bool,
    /// DTLS scanning for UDP+SSL (7.96+).
    pub dtls: bool,
}

impl ServiceScanOptions {
    pub fn effective_intensity(&self) -> u8 {
        if self.all_probes {
            9
        } else if self.light {
            2
        } else if self.intensity == 0 {
            7
        } else {
            self.intensity.min(9)
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OsScanOptions {
    /// `-O`
    pub enabled: bool,
    /// `--osscan-limit`
    pub limit: bool,
    /// `--osscan-guess`
    pub guess: bool,
    /// `--max-os-tries`
    pub max_tries: Option<u32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NseOptions {
    /// `-sC` / `--script default`
    pub default_scripts: bool,
    /// `--script "category1,category2,!exclude"`
    pub script_spec: Vec<String>,
    /// `--script-args ...`
    pub script_args: Vec<(String, String)>,
    /// `--script-args-file path`
    pub script_args_file: Option<PathBuf>,
    /// `--script-trace`
    pub trace: bool,
    /// `--script-updatedb`
    pub update_db: bool,
    /// `--script-help name`
    pub script_help: Vec<String>,
    /// Search path overrides.
    pub script_paths: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TimingTemplate {
    Paranoid,  // T0
    Sneaky,    // T1
    Polite,    // T2
    Normal,    // T3 (default)
    Aggressive, // T4
    Insane,    // T5
}

impl Default for TimingTemplate {
    fn default() -> Self {
        Self::Normal
    }
}

impl TimingTemplate {
    pub fn from_n(n: u8) -> Self {
        match n {
            0 => Self::Paranoid,
            1 => Self::Sneaky,
            2 => Self::Polite,
            4 => Self::Aggressive,
            5 => Self::Insane,
            _ => Self::Normal,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TimingOptions {
    pub template: TimingTemplate,
    pub min_hostgroup: Option<usize>,
    pub max_hostgroup: Option<usize>,
    pub min_parallelism: Option<usize>,
    pub max_parallelism: Option<usize>,
    pub min_rtt_timeout: Option<Duration>,
    pub max_rtt_timeout: Option<Duration>,
    pub initial_rtt_timeout: Option<Duration>,
    pub max_retries: Option<u32>,
    pub host_timeout: Option<Duration>,
    pub scan_delay: Option<Duration>,
    pub max_scan_delay: Option<Duration>,
    pub min_rate: Option<u64>,
    pub max_rate: Option<u64>,
    pub defeat_rst_ratelimit: bool,
    pub defeat_icmp_ratelimit: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvasionOptions {
    /// `-f` count: 0 = off, 1 = `-f` (8-byte fragments), 2 = `-ff` (16-byte).
    pub fragment: u8,
    /// `--mtu N`
    pub mtu: Option<u16>,
    /// `-D RND:N | decoy1,decoy2,ME,decoy3`
    pub decoys: Vec<DecoySpec>,
    /// `-S spoofed`
    pub source_addr: Option<IpAddr>,
    /// `-e iface`
    pub iface: Option<String>,
    /// `--source-port N`
    pub source_port: Option<u16>,
    /// `--data <hex>`
    pub data: Option<Vec<u8>>,
    /// `--data-string s`
    pub data_string: Option<String>,
    /// `--data-length N` — random padding
    pub data_length: Option<u16>,
    /// `--ip-options "..."`
    pub ip_options: Option<String>,
    /// `--ttl N`
    pub ttl: Option<u8>,
    /// `--spoof-mac AA:BB:..., Apple, 0`
    pub spoof_mac: Option<String>,
    /// `--badsum`
    pub badsum: bool,
    /// `--randomize-hosts`
    pub randomize_hosts: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DecoySpec {
    Me,
    Ip(IpAddr),
    Random(usize),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OutputOptions {
    pub normal: Option<PathBuf>,        // -oN
    pub xml: Option<PathBuf>,           // -oX
    pub grepable: Option<PathBuf>,      // -oG
    pub script_kiddie: Option<PathBuf>, // -oS
    pub all_basename: Option<PathBuf>,  // -oA
    pub json: Option<PathBuf>,          // lancer
    pub sarif: Option<PathBuf>,         // lancer
    pub csv: Option<PathBuf>,           // lancer
    pub verbosity: u8,
    pub debug_level: u8,
    pub reason: bool,
    pub open_only: bool,
    pub packet_trace: bool,
    pub iflist: bool,
    pub append_output: bool,
    pub stylesheet: Option<String>,
    pub no_stylesheet: bool,
    pub webxml: bool,
}
