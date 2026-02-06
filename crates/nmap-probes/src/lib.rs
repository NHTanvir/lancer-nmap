//! `nmap-probes` — parses the upstream `nmap-service-probes` DSL and runs
//! probes against a `(host, port)` to derive a `ServiceInfo`.
//!
//! Public surface:
//! - `parse_probes(&str) -> Vec<Probe>` — DSL parser
//! - `MatchRule` — one `match` / `softmatch` line
//! - `ServiceEngine` — orchestrator owning the probe set and running them

pub mod parser;
pub mod engine;
pub mod tls;
pub mod ports;

pub use parser::{parse_probes, MatchRule, Probe, ProbeProtocol, ProbeMatch, MatchKind};
pub use engine::{ServiceEngine, ProbeOutcome};
