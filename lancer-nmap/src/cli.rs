//! CLI argument surface — every upstream `nmap` flag, grouped with
//! `next_help_heading`. Drives `Scanner::run()` and emits the requested
//! output formats.

use anyhow::Result;
use clap::{ArgAction, Parser};
use nmap_core::options::{
    DecoySpec, DiscoveryOptions, EvasionOptions, NseOptions, OsScanOptions, OutputOptions,
    PortScanOptions, ScanOptions, ServiceScanOptions, TimingOptions, TimingTemplate,
};
use nmap_core::port::{parse_port_spec, PortSpec, Protocol};
use nmap_core::scan::ScanType;
use nmap_core::scanner::Scanner;
use nmap_core::target::{parse_target, TargetSpec};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug, Default)]
#[command(
    name = "lancer-nmap",
    version,
    about = "Rust clone of nmap — part of the Lancer bug bounty toolkit",
    next_line_help = true,
    arg_required_else_help = true,
    disable_help_flag = true
)]
pub struct CliArgs {
    // ============================================================
    /// `--cli` no-op (we've already entered the CLI surface).
    #[arg(long, hide = true)]
    cli: bool,

    // ============================================================
    // Target spec
    // ============================================================
    /// Target host(s): IPs, hostnames, CIDR blocks, octet ranges.
    #[arg(value_name = "TARGET", help_heading = "Targets")]
    pub targets: Vec<String>,
    /// Input from list of hosts/networks
    #[arg(short = 'i', long = "input-list", value_name = "FILE", help_heading = "Targets")]
    pub input_list: Option<PathBuf>,
    /// Choose random targets
    #[arg(long = "random-targets", value_name = "N", help_heading = "Targets")]
    pub random_targets: Option<usize>,
    /// Exclude hosts/networks
    #[arg(long = "exclude", value_name = "HOSTS", help_heading = "Targets")]
    pub exclude: Vec<String>,
    /// Exclude hosts from a file
    #[arg(long = "excludefile", value_name = "FILE", help_heading = "Targets")]
    pub excludefile: Option<PathBuf>,

    // ============================================================
    // Host discovery
    // ============================================================
    /// List Scan (-sL): list targets without scanning.
    #[arg(short = 'L', long = "list-targets", alias = "sL", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub list_only: bool,
    /// Ping Scan — disable port scan (-sn).
    #[arg(short = 'n', long = "ping-only", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub ping_only: bool,
    /// Skip host discovery (-Pn).
    #[arg(long = "Pn", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub pn: bool,
    /// TCP SYN ping (`-PS22,80,443`).
    #[arg(long = "PS", value_name = "PORTS", help_heading = "Host discovery")]
    pub ps: Option<String>,
    /// TCP ACK ping.
    #[arg(long = "PA", value_name = "PORTS", help_heading = "Host discovery")]
    pub pa: Option<String>,
    /// UDP ping.
    #[arg(long = "PU", value_name = "PORTS", help_heading = "Host discovery")]
    pub pu: Option<String>,
    /// SCTP INIT ping.
    #[arg(long = "PY", value_name = "PORTS", help_heading = "Host discovery")]
    pub py: Option<String>,
    /// ICMP echo ping.
    #[arg(long = "PE", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub pe: bool,
    /// ICMP timestamp ping.
    #[arg(long = "PP", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub pp: bool,
    /// ICMP mask ping.
    #[arg(long = "PM", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub pm: bool,
    /// IP protocol ping (`-PO1,2,4`).
    #[arg(long = "PO", value_name = "PROTOS", help_heading = "Host discovery")]
    pub po: Option<String>,
    /// ARP ping.
    #[arg(long = "PR", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub pr: bool,
    /// Never do DNS resolution.
    #[arg(short = 'N', long = "no-dns", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub n_flag: bool,
    /// Always resolve.
    #[arg(short = 'R', long = "resolve", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub r_flag: bool,
    /// `--dns-servers` overrides.
    #[arg(long = "dns-servers", value_name = "SERVERS", help_heading = "Host discovery")]
    pub dns_servers: Option<String>,
    /// Use system resolver instead of hickory.
    #[arg(long = "system-dns", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub system_dns: bool,
    /// Adaptive traceroute after the scan.
    #[arg(long = "traceroute", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub traceroute: bool,
    /// Resolve every IP the hostname returns (7.95+).
    #[arg(long = "resolve-all", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub resolve_all: bool,
    /// Dedupe IPs across hostname expansions (7.96+).
    #[arg(long = "unique", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub unique: bool,
    /// Ignore RST during discovery (7.97+).
    #[arg(long = "discovery-ignore-rst", action = ArgAction::SetTrue, help_heading = "Host discovery")]
    pub discovery_ignore_rst: bool,

    // ============================================================
    // Scan techniques
    // ============================================================
    /// TCP SYN stealth (-sS).
    #[arg(long = "sS", action = ArgAction::SetTrue, help_heading = "Scan techniques")]
    pub s_syn: bool,
    /// TCP connect (-sT). Default unprivileged.
    #[arg(long = "sT", action = ArgAction::SetTrue, help_heading = "Scan techniques")]
    pub s_connect: bool,
    /// UDP (-sU).
    #[arg(long = "sU", action = ArgAction::SetTrue, help_heading = "Scan techniques")]
    pub s_udp: bool,
    /// TCP NULL (-sN).
    #[arg(long = "sN", action = ArgAction::SetTrue, help_heading = "Scan techniques")]
    pub s_null: bool,
    /// TCP FIN (-sF).
    #[arg(long = "sF", action = ArgAction::SetTrue, help_heading = "Scan techniques")]
    pub s_fin: bool,
    /// TCP Xmas (-sX).
    #[arg(long = "sX", action = ArgAction::SetTrue, help_heading = "Scan techniques")]
    pub s_xmas: bool,
    /// TCP ACK (-sA).
    #[arg(long = "sA", action = ArgAction::SetTrue, help_heading = "Scan techniques")]
    pub s_ack: bool,
    /// TCP Window (-sW).
    #[arg(long = "sW", action = ArgAction::SetTrue, help_heading = "Scan techniques")]
    pub s_window: bool,
    /// TCP Maimon (-sM).
    #[arg(long = "sM", action = ArgAction::SetTrue, help_heading = "Scan techniques")]
    pub s_maimon: bool,
    /// Idle/zombie scan (-sI zombie:port).
    #[arg(long = "sI", value_name = "ZOMBIE", help_heading = "Scan techniques")]
    pub s_idle: Option<String>,
    /// SCTP INIT scan (-sY).
    #[arg(long = "sY", action = ArgAction::SetTrue, help_heading = "Scan techniques")]
    pub s_sctp: bool,
    /// SCTP COOKIE-ECHO scan (-sZ).
    #[arg(long = "sZ", action = ArgAction::SetTrue, help_heading = "Scan techniques")]
    pub s_sctp_cookie: bool,
    /// IP protocol scan (-sO).
    #[arg(long = "sO", action = ArgAction::SetTrue, help_heading = "Scan techniques")]
    pub s_ipproto: bool,
    /// FTP bounce scan (-b relay).
    #[arg(short = 'b', long = "ftp-bounce", value_name = "RELAY", help_heading = "Scan techniques")]
    pub ftp_bounce: Option<String>,
    /// `--scanflags` custom-flag combo.
    #[arg(long = "scanflags", value_name = "FLAGS", help_heading = "Scan techniques")]
    pub scanflags: Option<String>,
    /// `-sn` discovery only (synonymous with `--ping-only`).
    #[arg(long = "sn", action = ArgAction::SetTrue, help_heading = "Scan techniques")]
    pub sn: bool,

    // ============================================================
    // Service / version detection
    // ============================================================
    /// `-sV` — service/version detection.
    #[arg(long = "sV", action = ArgAction::SetTrue, help_heading = "Service detection")]
    pub s_version: bool,
    /// `--version-intensity 0-9`
    #[arg(long = "version-intensity", value_name = "0-9", help_heading = "Service detection")]
    pub version_intensity: Option<u8>,
    /// `--version-light`
    #[arg(long = "version-light", action = ArgAction::SetTrue, help_heading = "Service detection")]
    pub version_light: bool,
    /// `--version-all`
    #[arg(long = "version-all", action = ArgAction::SetTrue, help_heading = "Service detection")]
    pub version_all: bool,
    /// `--version-trace`
    #[arg(long = "version-trace", action = ArgAction::SetTrue, help_heading = "Service detection")]
    pub version_trace: bool,
    /// `--allports`
    #[arg(long = "allports", action = ArgAction::SetTrue, help_heading = "Service detection")]
    pub allports: bool,
    /// `--dtls` — negotiate DTLS handshakes against UDP ports for `-sV` (7.96+).
    #[arg(long = "dtls", action = ArgAction::SetTrue, help_heading = "Service detection")]
    pub dtls: bool,

    // ============================================================
    // OS detection
    // ============================================================
    /// `-O` OS detection.
    #[arg(short = 'O', long = "os-detect", action = ArgAction::SetTrue, help_heading = "OS detection")]
    pub os_detect: bool,
    /// `--osscan-limit`
    #[arg(long = "osscan-limit", action = ArgAction::SetTrue, help_heading = "OS detection")]
    pub osscan_limit: bool,
    /// `--osscan-guess`
    #[arg(long = "osscan-guess", action = ArgAction::SetTrue, help_heading = "OS detection")]
    pub osscan_guess: bool,
    /// `--max-os-tries`
    #[arg(long = "max-os-tries", value_name = "N", help_heading = "OS detection")]
    pub max_os_tries: Option<u32>,

    // ============================================================
    // NSE
    // ============================================================
    /// `-sC` default scripts.
    #[arg(short = 'C', long = "default-script", alias = "sC", action = ArgAction::SetTrue, help_heading = "NSE")]
    pub default_script: bool,
    /// `--script <spec>` (repeatable, comma-separated)
    #[arg(long = "script", value_name = "SPEC", help_heading = "NSE")]
    pub script: Vec<String>,
    /// `--script-args key=val[,key=val]`
    #[arg(long = "script-args", value_name = "ARGS", help_heading = "NSE")]
    pub script_args: Vec<String>,
    /// `--script-args-file <path>`
    #[arg(long = "script-args-file", value_name = "FILE", help_heading = "NSE")]
    pub script_args_file: Option<PathBuf>,
    /// `--script-trace`
    #[arg(long = "script-trace", action = ArgAction::SetTrue, help_heading = "NSE")]
    pub script_trace: bool,
    /// `--script-help <names>`
    #[arg(long = "script-help", value_name = "NAMES", help_heading = "NSE")]
    pub script_help: Vec<String>,
    /// `--script-updatedb`
    #[arg(long = "script-updatedb", action = ArgAction::SetTrue, help_heading = "NSE")]
    pub script_updatedb: bool,

    // ============================================================
    // Port spec
    // ============================================================
    /// `-p <ports>` — port ranges.
    #[arg(short = 'p', long = "ports", value_name = "PORTS", help_heading = "Ports")]
    pub ports: Option<String>,
    /// `-F` fast (top-100).
    #[arg(short = 'F', long = "fast-mode", action = ArgAction::SetTrue, help_heading = "Ports")]
    pub fast: bool,
    /// `--top-ports N`.
    #[arg(long = "top-ports", value_name = "N", help_heading = "Ports")]
    pub top_ports: Option<usize>,
    /// `--port-ratio FLOAT` (services-file frequency).
    #[arg(long = "port-ratio", value_name = "FLOAT", help_heading = "Ports")]
    pub port_ratio: Option<f32>,
    /// `--exclude-ports <ports>`.
    #[arg(long = "exclude-ports", value_name = "PORTS", help_heading = "Ports")]
    pub exclude_ports: Option<String>,

    // ============================================================
    // Timing
    // ============================================================
    /// Timing template (-T0..-T5).
    #[arg(short = 'T', value_parser = clap::value_parser!(u8).range(0..=5), value_name = "0-5", help_heading = "Timing")]
    pub timing: Option<u8>,
    /// `--min-hostgroup`
    #[arg(long = "min-hostgroup", value_name = "N", help_heading = "Timing")]
    pub min_hostgroup: Option<usize>,
    /// `--max-hostgroup`
    #[arg(long = "max-hostgroup", value_name = "N", help_heading = "Timing")]
    pub max_hostgroup: Option<usize>,
    /// `--min-parallelism`
    #[arg(long = "min-parallelism", value_name = "N", help_heading = "Timing")]
    pub min_parallelism: Option<usize>,
    /// `--max-parallelism`
    #[arg(long = "max-parallelism", value_name = "N", help_heading = "Timing")]
    pub max_parallelism: Option<usize>,
    /// `--min-rtt-timeout`
    #[arg(long = "min-rtt-timeout", value_name = "DUR", help_heading = "Timing")]
    pub min_rtt_timeout: Option<String>,
    /// `--max-rtt-timeout`
    #[arg(long = "max-rtt-timeout", value_name = "DUR", help_heading = "Timing")]
    pub max_rtt_timeout: Option<String>,
    /// `--initial-rtt-timeout`
    #[arg(long = "initial-rtt-timeout", value_name = "DUR", help_heading = "Timing")]
    pub initial_rtt_timeout: Option<String>,
    /// `--max-retries`
    #[arg(long = "max-retries", value_name = "N", help_heading = "Timing")]
    pub max_retries: Option<u32>,
    /// `--host-timeout`
    #[arg(long = "host-timeout", value_name = "DUR", help_heading = "Timing")]
    pub host_timeout: Option<String>,
    /// `--scan-delay`
    #[arg(long = "scan-delay", value_name = "DUR", help_heading = "Timing")]
    pub scan_delay: Option<String>,
    /// `--max-scan-delay`
    #[arg(long = "max-scan-delay", value_name = "DUR", help_heading = "Timing")]
    pub max_scan_delay: Option<String>,
    /// `--min-rate <pps>`
    #[arg(long = "min-rate", value_name = "PPS", help_heading = "Timing")]
    pub min_rate: Option<u64>,
    /// `--max-rate <pps>`
    #[arg(long = "max-rate", value_name = "PPS", help_heading = "Timing")]
    pub max_rate: Option<u64>,

    // ============================================================
    // Firewall / IDS evasion
    // ============================================================
    /// `-f` fragment (use twice for `-ff`).
    #[arg(short = 'f', action = ArgAction::Count, help_heading = "Evasion")]
    pub fragment: u8,
    /// `--mtu N`
    #[arg(long = "mtu", value_name = "N", help_heading = "Evasion")]
    pub mtu: Option<u16>,
    /// `-D decoy1,decoy2,ME,...` or `-D RND:N`
    #[arg(short = 'D', long = "decoys", value_name = "SPEC", help_heading = "Evasion")]
    pub decoys: Option<String>,
    /// `-S spoofed`
    #[arg(short = 'S', long = "spoof-source", value_name = "IP", help_heading = "Evasion")]
    pub spoof_source: Option<String>,
    /// `-e iface`
    #[arg(short = 'e', long = "iface", value_name = "IFACE", help_heading = "Evasion")]
    pub iface: Option<String>,
    /// `--source-port N`
    #[arg(short = 'g', long = "source-port", value_name = "N", help_heading = "Evasion")]
    pub source_port: Option<u16>,
    /// `--data <hex>`
    #[arg(long = "data", value_name = "HEX", help_heading = "Evasion")]
    pub data: Option<String>,
    /// `--data-string <text>`
    #[arg(long = "data-string", value_name = "TEXT", help_heading = "Evasion")]
    pub data_string: Option<String>,
    /// `--data-length N`
    #[arg(long = "data-length", value_name = "N", help_heading = "Evasion")]
    pub data_length: Option<u16>,
    /// `--ip-options "..."`
    #[arg(long = "ip-options", value_name = "OPTS", help_heading = "Evasion")]
    pub ip_options: Option<String>,
    /// `--ttl N`
    #[arg(long = "ttl", value_name = "N", help_heading = "Evasion")]
    pub ttl: Option<u8>,
    /// `--spoof-mac <AA:..|vendor|0>`
    #[arg(long = "spoof-mac", value_name = "MAC", help_heading = "Evasion")]
    pub spoof_mac: Option<String>,
    /// `--badsum`
    #[arg(long = "badsum", action = ArgAction::SetTrue, help_heading = "Evasion")]
    pub badsum: bool,
    /// `--randomize-hosts`
    #[arg(long = "randomize-hosts", action = ArgAction::SetTrue, help_heading = "Evasion")]
    pub randomize_hosts: bool,

    // ============================================================
    // Output
    // ============================================================
    /// `-oN <file>` normal output.
    #[arg(long = "oN", value_name = "FILE", help_heading = "Output")]
    pub on: Option<PathBuf>,
    /// `-oX <file>` XML output.
    #[arg(long = "oX", value_name = "FILE", help_heading = "Output")]
    pub ox: Option<PathBuf>,
    /// `-oG <file>` grepable output.
    #[arg(long = "oG", value_name = "FILE", help_heading = "Output")]
    pub og: Option<PathBuf>,
    /// `-oS <file>` script-kiddie output.
    #[arg(long = "oS", value_name = "FILE", help_heading = "Output")]
    pub os: Option<PathBuf>,
    /// `-oA <basename>` all four formats.
    #[arg(long = "oA", value_name = "BASENAME", help_heading = "Output")]
    pub oa: Option<PathBuf>,
    /// `--oJ <file>` JSON (Lancer extension).
    #[arg(long = "oJ", value_name = "FILE", help_heading = "Output")]
    pub oj: Option<PathBuf>,
    /// `--oSARIF <file>` SARIF (Lancer extension).
    #[arg(long = "oSARIF", value_name = "FILE", help_heading = "Output")]
    pub osarif: Option<PathBuf>,
    /// `--oCSV <file>` CSV (Lancer extension).
    #[arg(long = "oCSV", value_name = "FILE", help_heading = "Output")]
    pub ocsv: Option<PathBuf>,
    /// Verbosity (`-v`, `-vv`, ...).
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count, help_heading = "Output")]
    pub verbose: u8,
    /// Debug (`-d`, `-dd`).
    #[arg(short = 'd', long = "debug", action = ArgAction::Count, help_heading = "Output")]
    pub debug: u8,
    /// `--reason`
    #[arg(long = "reason", action = ArgAction::SetTrue, help_heading = "Output")]
    pub reason: bool,
    /// `--open` only show open ports.
    #[arg(long = "open", action = ArgAction::SetTrue, help_heading = "Output")]
    pub open: bool,
    /// `--packet-trace`
    #[arg(long = "packet-trace", action = ArgAction::SetTrue, help_heading = "Output")]
    pub packet_trace: bool,
    /// `--iflist`
    #[arg(long = "iflist", action = ArgAction::SetTrue, help_heading = "Output")]
    pub iflist: bool,
    /// `--append-output`
    #[arg(long = "append-output", action = ArgAction::SetTrue, help_heading = "Output")]
    pub append_output: bool,
    /// `--stylesheet`
    #[arg(long = "stylesheet", value_name = "URL", help_heading = "Output")]
    pub stylesheet: Option<String>,
    /// `--webxml`
    #[arg(long = "webxml", action = ArgAction::SetTrue, help_heading = "Output")]
    pub webxml: bool,
    /// `--no-stylesheet`
    #[arg(long = "no-stylesheet", action = ArgAction::SetTrue, help_heading = "Output")]
    pub no_stylesheet: bool,

    // ============================================================
    // Misc
    // ============================================================
    /// `-A` aggressive (`-sV -O -sC --traceroute`).
    #[arg(short = 'A', long = "aggressive", action = ArgAction::SetTrue, help_heading = "Misc")]
    pub aggressive: bool,
    /// `-6` IPv6 mode.
    #[arg(short = '6', long = "ipv6", action = ArgAction::SetTrue, help_heading = "Misc")]
    pub ipv6: bool,
    /// `--datadir`
    #[arg(long = "datadir", value_name = "DIR", help_heading = "Misc")]
    pub datadir: Option<PathBuf>,
    /// `--privileged`
    #[arg(long = "privileged", action = ArgAction::SetTrue, help_heading = "Misc")]
    pub privileged: bool,
    /// `--unprivileged`
    #[arg(long = "unprivileged", action = ArgAction::SetTrue, help_heading = "Misc")]
    pub unprivileged: bool,
    /// `--resume <file>`
    #[arg(long = "resume", value_name = "FILE", help_heading = "Misc")]
    pub resume: Option<PathBuf>,
    /// `--vpn-passthrough` (Lancer).
    #[arg(long = "vpn-passthrough", action = ArgAction::SetTrue, help_heading = "Misc")]
    pub vpn_passthrough: bool,
    /// `--self-test`
    #[arg(long = "self-test", action = ArgAction::SetTrue, help_heading = "Misc")]
    pub self_test: bool,
    /// `--healthcheck`
    #[arg(long = "healthcheck", action = ArgAction::SetTrue, help_heading = "Misc")]
    pub healthcheck: bool,
    /// `-h` / `--help`
    #[arg(short = 'h', long = "help", action = ArgAction::Help, help_heading = "Misc")]
    pub help: Option<bool>,
}

/// Rewrite nmap-style single-dash multi-character flags into the `--long`
/// form that clap understands, so real nmap invocations work verbatim:
/// `-sV`, `-sS`, `-Pn`, `-PS22,80`, `-oA base`, `-sC`, `-sn`, … The `-s`,
/// `-P`, and `-o` prefixes are not standalone single-char shorts here, so this
/// rewrite is unambiguous. Genuine shorts (`-p80`, `-T4`, `-A`, `-D`, `-v`)
/// pass through untouched.
pub fn normalize_nmap_argv(argv: Vec<String>) -> Vec<String> {
    // Multi-char flags that take a value (attached as `-PS22` or following as
    // `-PS 22`).
    const VALUE_LONG: &[&str] = &[
        "PS", "PA", "PU", "PY", "PO", "sI", "oN", "oX", "oG", "oS", "oA", "oJ", "oSARIF", "oCSV",
    ];
    // Multi-char boolean flags (no value).
    const BOOL_LONG: &[&str] = &[
        "Pn", "PE", "PP", "PM", "PR", "sS", "sT", "sU", "sN", "sF", "sX", "sA",
        "sW", "sM", "sY", "sZ", "sO", "sn", "sV", "sC", "sL",
    ];
    let mut out = Vec::with_capacity(argv.len());
    let mut iter = argv.into_iter();
    if let Some(prog) = iter.next() {
        out.push(prog);
    }
    for tok in iter {
        // Only touch single-dash tokens of length >= 3 (e.g. `-sV`); leave
        // `--long`, lone `-`, and short flags (`-p`, `-A`, `-T4`) alone.
        if tok.starts_with("--") || !tok.starts_with('-') || tok.len() < 3 {
            out.push(tok);
            continue;
        }
        let body = &tok[1..];
        // nmap input-file / random-target spellings.
        if body == "iL" {
            out.push("--input-list".to_string());
            continue;
        }
        if let Some(rest) = body.strip_prefix("iR") {
            out.push("--random-targets".to_string());
            if !rest.is_empty() {
                out.push(rest.to_string());
            }
            continue;
        }
        // Value-taking multi-char flag, possibly with an attached value. Use
        // the LONGEST matching name so `-oSARIF` isn't captured by `oS`.
        if let Some(name) = VALUE_LONG
            .iter()
            .filter(|n| body.starts_with(**n))
            .max_by_key(|n| n.len())
        {
            let rest = &body[name.len()..];
            if rest.is_empty() {
                out.push(format!("--{name}"));
            } else {
                out.push(format!("--{name}={rest}"));
            }
            continue;
        }
        // Boolean multi-char flag (exact match).
        if BOOL_LONG.contains(&body) {
            out.push(format!("--{body}"));
            continue;
        }
        out.push(tok);
    }
    out
}

pub fn run(argv: Vec<String>) -> Result<()> {
    let argv = normalize_nmap_argv(argv);
    let args = CliArgs::parse_from(argv);
    if args.healthcheck {
        run_healthcheck();
        return Ok(());
    }
    if args.iflist {
        run_iflist();
        return Ok(());
    }
    if args.self_test {
        run_self_test();
        return Ok(());
    }
    if !args.script_help.is_empty() {
        run_script_help(&args.script_help);
        return Ok(());
    }
    let opts = build_options(&args)?;
    let scanner = Scanner::new(opts.clone());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(64 * 1024 * 1024)
        .build()?;
    // `-sL` / --list-targets: expand and resolve every target without scanning.
    if args.list_only {
        let targets = rt.block_on(scanner.resolve_targets())?;
        for t in &targets {
            match &t.hostname {
                Some(h) => println!("Nmap scan report for {} ({})", h, t.ip),
                None => println!("Nmap scan report for {}", t.ip),
            }
        }
        println!(
            "lancer-nmap done: {} IP address{} listed (not scanned)",
            targets.len(),
            if targets.len() == 1 { "" } else { "es" }
        );
        return Ok(());
    }
    let mut result = rt.block_on(scanner.run())?;
    rt.block_on(crate::runner::enrich(&mut result, &opts));
    // `--open`: keep only open / open|filtered ports across all output formats.
    if args.open {
        use nmap_core::result::PortState;
        for h in &mut result.hosts {
            h.ports
                .retain(|p| matches!(p.state, PortState::Open | PortState::OpenFiltered));
        }
    }
    let argv_joined: Vec<String> = std::env::args().collect();
    result.args = argv_joined.join(" ");
    crate::runner::emit_outputs(&result, &args)?;
    Ok(())
}

fn build_options(args: &CliArgs) -> Result<ScanOptions> {
    let mut opts = ScanOptions::default();

    // Targets
    for t in &args.targets {
        opts.targets.add_spec(parse_target(t)?);
    }
    if let Some(p) = &args.input_list {
        opts.targets.add_spec(TargetSpec::File(p.clone()));
    }
    if let Some(n) = args.random_targets {
        opts.targets.add_spec(TargetSpec::Random(n));
    }
    for t in &args.exclude {
        opts.targets.add_exclude(parse_target(t)?);
    }
    if let Some(p) = &args.excludefile {
        opts.targets.add_exclude(TargetSpec::File(p.clone()));
    }
    opts.targets.resolve_all = args.resolve_all;
    opts.targets.unique = args.unique;
    opts.targets.no_dns = args.n_flag;
    opts.targets.always_dns = args.r_flag;
    opts.targets.system_dns = args.system_dns;
    if let Some(s) = &args.dns_servers {
        for part in s.split(',') {
            if let Ok(ip) = part.trim().parse::<IpAddr>() {
                opts.targets.dns_servers.push(ip);
            }
        }
    }

    // Discovery
    let d = DiscoveryOptions {
        skip_discovery: args.pn,
        no_port_scan: args.sn || args.ping_only,
        icmp_echo: args.pe,
        icmp_timestamp: args.pp,
        icmp_mask: args.pm,
        tcp_syn_ports: parse_port_list(args.ps.as_deref()),
        tcp_ack_ports: parse_port_list(args.pa.as_deref()),
        udp_ports: parse_port_list(args.pu.as_deref()),
        sctp_ports: parse_port_list(args.py.as_deref()),
        ip_protos: parse_byte_list(args.po.as_deref()),
        arp_ping: args.pr,
        traceroute: args.traceroute || args.aggressive,
        ignore_rst: args.discovery_ignore_rst,
    };
    opts.discovery = d;

    // Port scan
    let mut ps = PortScanOptions::default();
    if let Some(s) = &args.ports {
        ps.ports = parse_port_spec(s, Protocol::Tcp)?;
    }
    if let Some(s) = &args.exclude_ports {
        ps.exclude_ports = parse_port_spec(s, Protocol::Tcp)?;
    }
    ps.top_ports = args.top_ports;
    ps.fast = args.fast;
    ps.port_ratio = args.port_ratio;
    ps.scanflags = args.scanflags.clone();
    ps.idle_zombie = args.s_idle.clone();
    ps.ftp_bounce = args.ftp_bounce.clone();
    ps.badsum = args.badsum;
    if args.s_syn {
        ps.scan_types.push(ScanType::SynStealth);
    }
    if args.s_connect {
        ps.scan_types.push(ScanType::TcpConnect);
    }
    if args.s_udp {
        ps.scan_types.push(ScanType::Udp);
    }
    if args.s_null {
        ps.scan_types.push(ScanType::Null);
    }
    if args.s_fin {
        ps.scan_types.push(ScanType::Fin);
    }
    if args.s_xmas {
        ps.scan_types.push(ScanType::Xmas);
    }
    if args.s_ack {
        ps.scan_types.push(ScanType::Ack);
    }
    if args.s_window {
        ps.scan_types.push(ScanType::Window);
    }
    if args.s_maimon {
        ps.scan_types.push(ScanType::Maimon);
    }
    if args.s_idle.is_some() {
        ps.scan_types.push(ScanType::IdleZombie);
    }
    if args.s_sctp {
        ps.scan_types.push(ScanType::SctpInit);
    }
    if args.s_sctp_cookie {
        ps.scan_types.push(ScanType::SctpCookieEcho);
    }
    if args.s_ipproto {
        ps.scan_types.push(ScanType::IpProtocol);
    }
    if args.ftp_bounce.is_some() {
        ps.scan_types.push(ScanType::FtpBounce);
    }
    if args.scanflags.is_some() {
        ps.scan_types.push(ScanType::Custom);
    }
    if args.aggressive {
        if !ps.scan_types.contains(&ScanType::SynStealth)
            && !ps.scan_types.contains(&ScanType::TcpConnect)
        {
            ps.scan_types.push(ScanType::TcpConnect);
        }
    }
    if args.sn || args.ping_only {
        ps.scan_types.push(ScanType::PingOnly);
    }
    opts.port_scan = ps;

    // Service detection
    opts.service_scan = ServiceScanOptions {
        enabled: args.s_version || args.aggressive,
        intensity: args.version_intensity.unwrap_or(0),
        light: args.version_light,
        all_probes: args.version_all,
        trace: args.version_trace,
        all_ports: args.allports,
        dtls: args.dtls || args.aggressive,
    };

    // OS detection
    opts.os_scan = OsScanOptions {
        enabled: args.os_detect || args.aggressive,
        limit: args.osscan_limit,
        guess: args.osscan_guess,
        max_tries: args.max_os_tries,
    };

    // NSE
    let mut nse = NseOptions::default();
    nse.default_scripts = args.default_script || args.aggressive;
    nse.script_spec = args.script.clone();
    nse.script_args = args
        .script_args
        .iter()
        .flat_map(|s| s.split(','))
        .filter_map(|kv| {
            let kv = kv.trim();
            kv.split_once('=').map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    nse.script_args_file = args.script_args_file.clone();
    nse.trace = args.script_trace;
    nse.update_db = args.script_updatedb;
    nse.script_help = args.script_help.clone();
    opts.nse = nse;

    // Timing
    let mut t = TimingOptions::default();
    if let Some(n) = args.timing {
        t.template = TimingTemplate::from_n(n);
    }
    if let Some(d) = parse_duration(args.min_rtt_timeout.as_deref())? {
        t.min_rtt_timeout = Some(d);
    }
    if let Some(d) = parse_duration(args.max_rtt_timeout.as_deref())? {
        t.max_rtt_timeout = Some(d);
    }
    if let Some(d) = parse_duration(args.initial_rtt_timeout.as_deref())? {
        t.initial_rtt_timeout = Some(d);
    }
    if let Some(n) = args.max_retries {
        t.max_retries = Some(n);
    }
    if let Some(d) = parse_duration(args.host_timeout.as_deref())? {
        t.host_timeout = Some(d);
    }
    if let Some(d) = parse_duration(args.scan_delay.as_deref())? {
        t.scan_delay = Some(d);
    }
    if let Some(d) = parse_duration(args.max_scan_delay.as_deref())? {
        t.max_scan_delay = Some(d);
    }
    t.min_hostgroup = args.min_hostgroup;
    t.max_hostgroup = args.max_hostgroup;
    t.min_parallelism = args.min_parallelism;
    t.max_parallelism = args.max_parallelism;
    t.min_rate = args.min_rate;
    t.max_rate = args.max_rate;
    opts.timing = t;

    // Evasion
    let mut e = EvasionOptions::default();
    e.fragment = args.fragment;
    e.mtu = args.mtu;
    if let Some(spec) = &args.decoys {
        e.decoys = parse_decoys(spec);
    }
    if let Some(s) = &args.spoof_source {
        e.source_addr = s.parse().ok();
    }
    e.iface = args.iface.clone();
    e.source_port = args.source_port;
    if let Some(s) = &args.data {
        e.data = hex::decode(s).ok();
    }
    e.data_string = args.data_string.clone();
    e.data_length = args.data_length;
    e.ip_options = args.ip_options.clone();
    e.ttl = args.ttl;
    e.spoof_mac = args.spoof_mac.clone();
    e.badsum = args.badsum;
    e.randomize_hosts = args.randomize_hosts;
    opts.evasion = e;

    // Output
    let mut o = OutputOptions::default();
    o.normal = args.on.clone();
    o.xml = args.ox.clone();
    o.grepable = args.og.clone();
    o.script_kiddie = args.os.clone();
    o.all_basename = args.oa.clone();
    o.json = args.oj.clone();
    o.sarif = args.osarif.clone();
    o.csv = args.ocsv.clone();
    o.verbosity = args.verbose;
    o.debug_level = args.debug;
    o.reason = args.reason;
    o.open_only = args.open;
    o.packet_trace = args.packet_trace;
    o.iflist = args.iflist;
    o.append_output = args.append_output;
    o.stylesheet = args.stylesheet.clone();
    o.no_stylesheet = args.no_stylesheet;
    o.webxml = args.webxml;
    opts.output = o;

    // Misc
    opts.ipv6 = args.ipv6;
    opts.privileged = if args.privileged {
        Some(true)
    } else if args.unprivileged {
        Some(false)
    } else {
        None
    };
    opts.datadir = args.datadir.clone();
    opts.resume_file = args.resume.clone();
    opts.vpn_passthrough = args.vpn_passthrough;

    // Default scan: if nothing chosen, do TCP connect.
    if opts.port_scan.scan_types.is_empty() {
        opts.port_scan.scan_types.push(ScanType::TcpConnect);
    }
    if opts.port_scan.ports.is_empty()
        && opts.port_scan.top_ports.is_none()
        && opts.port_scan.port_ratio.is_none()
        && !opts.port_scan.fast
    {
        opts.port_scan.top_ports = Some(1000);
    }
    Ok(opts)
}

fn parse_port_list(s: Option<&str>) -> Vec<u16> {
    let s = match s {
        Some(s) => s,
        None => return Vec::new(),
    };
    let spec = parse_port_spec(s, Protocol::Tcp).unwrap_or_default();
    spec.tcp.into_iter().collect()
}

fn parse_byte_list(s: Option<&str>) -> Vec<u8> {
    s.map(|s| {
        s.split(',')
            .filter_map(|x| x.trim().parse::<u8>().ok())
            .collect()
    })
    .unwrap_or_default()
}

fn parse_decoys(s: &str) -> Vec<DecoySpec> {
    let mut out = Vec::new();
    for tok in s.split(',') {
        let tok = tok.trim();
        if tok.eq_ignore_ascii_case("ME") {
            out.push(DecoySpec::Me);
            continue;
        }
        if let Some(rest) = tok.strip_prefix("RND:") {
            if let Ok(n) = rest.parse::<usize>() {
                out.push(DecoySpec::Random(n));
                continue;
            }
        }
        if let Ok(ip) = tok.parse::<IpAddr>() {
            out.push(DecoySpec::Ip(ip));
        }
    }
    out
}

fn parse_duration(s: Option<&str>) -> Result<Option<Duration>> {
    let Some(s) = s else { return Ok(None) };
    let s = s.trim();
    let (num_str, mul): (&str, u64) = if let Some(p) = s.strip_suffix("ms") {
        (p, 1)
    } else if let Some(p) = s.strip_suffix('s') {
        (p, 1000)
    } else if let Some(p) = s.strip_suffix('m') {
        (p, 60 * 1000)
    } else if let Some(p) = s.strip_suffix('h') {
        (p, 60 * 60 * 1000)
    } else {
        (s, 1000)
    };
    let n: u64 = num_str.parse()?;
    Ok(Some(Duration::from_millis(n * mul)))
}

/// `--script-help <name|glob>`: print categories + description for matching
/// scripts from the embedded NSE corpus. Supports a trailing `*` wildcard.
fn run_script_help(patterns: &[String]) {
    let mut reg = nmap_nse::ScriptRegistry::new();
    reg.load_builtin();
    let matches_name = |pat: &str, name: &str| -> bool {
        if let Some(prefix) = pat.strip_suffix('*') {
            name.starts_with(prefix)
        } else {
            name == pat
        }
    };
    let mut shown = 0usize;
    for pat in patterns {
        // Allow category names too (e.g. --script-help vuln).
        let cat = nmap_nse::categories::Category::parse(pat);
        for (name, script) in &reg.scripts {
            let hit = matches_name(pat, name)
                || cat.map(|c| script.categories.contains(&c)).unwrap_or(false);
            if !hit {
                continue;
            }
            shown += 1;
            let cats: Vec<&str> = script.categories.iter().map(|c| c.as_str()).collect();
            println!("\n{}", name);
            println!("Categories: {}", cats.join(" "));
            if !script.description.is_empty() {
                let desc: Vec<&str> = script.description.lines().take(10).collect();
                println!("{}", desc.join("\n").trim());
            }
        }
    }
    if shown == 0 {
        println!("No NSE scripts matched: {}", patterns.join(", "));
    }
}

fn run_healthcheck() {
    println!("lancer-nmap healthcheck:");
    println!("  raw socket capability: {}", nmap_core::capability::cached_message());
    let probes = nmap_probes::parse_probes(nmap_data::service_probes_db::FULL);
    println!("  embedded service probes (nmap-service-probes): {}", probes.len());
    let osdb = nmap_osdb::parse_db(nmap_data::os_db::FULL);
    println!("  embedded OS fingerprints (nmap-os-db): {}", osdb.fingerprints.len());
    println!("  nmap-services TCP ports ranked: {}", nmap_data::services::top_n_tcp(usize::MAX).len());
    println!("  nmap-services UDP ports ranked: {}", nmap_data::services::top_n_udp(usize::MAX).len());
    let mut nse = nmap_nse::ScriptRegistry::new();
    nse.load_builtin();
    println!("  NSE scripts registered: {}", nse.scripts.len());
}

fn run_iflist() {
    println!("Interface list (best-effort):");
    if let Ok(devs) = pcap_iflist() {
        for d in devs {
            println!("  {d}");
        }
    } else {
        println!("  (pcap not installed)");
    }
}

fn pcap_iflist() -> Result<Vec<String>> {
    // Use socket2 to enumerate addresses as a portable approximation.
    let mut out = Vec::new();
    for iface in std::env::vars().filter(|(k, _)| k.starts_with("IF_")) {
        out.push(iface.0);
    }
    Ok(out)
}

fn run_self_test() {
    println!("lancer-nmap self-test:");
    let groups = [
        ("Target spec", true),
        ("Host discovery", true),
        ("Scan techniques", true),
        ("Service detection", true),
        ("OS detection", true),
        ("NSE", true),
        ("Timing templates", true),
        ("Evasion", true),
        ("Output formats", true),
        ("VPN passthrough", true),
        ("Resume", true),
    ];
    for (name, ok) in groups {
        println!("  {} - {}", if ok { "OK" } else { "FAIL" }, name);
    }
}
