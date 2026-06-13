//! nmap-data — embedded reference data tables.
//!
//! Bundles the freely-redistributable nmap data files (nmap-services,
//! nmap-payloads, nmap-mac-prefixes, nmap-rpc, nmap-protocols) via
//! `include_bytes!`, exposing them as parsed, queryable tables.

pub mod services;
pub mod payloads;
pub mod mac_prefixes;
pub mod rpc;
pub mod protocols;
pub mod service_probes_db;
pub mod os_db;

pub use services::*;
pub use payloads::*;

use std::borrow::Cow;
use std::path::Path;

/// Return the `nmap-service-probes` text to use: the file under `--datadir`
/// when present and readable, otherwise the embedded full v7.99 database.
pub fn load_service_probes(datadir: Option<&Path>) -> Cow<'static, str> {
    if let Some(d) = datadir {
        if let Ok(s) = std::fs::read_to_string(d.join("nmap-service-probes")) {
            return Cow::Owned(s);
        }
    }
    Cow::Borrowed(service_probes_db::FULL)
}

/// Return the `nmap-os-db` text to use: the file under `--datadir` when
/// present and readable, otherwise the embedded full v7.99 database.
pub fn load_os_db(datadir: Option<&Path>) -> Cow<'static, str> {
    if let Some(d) = datadir {
        if let Ok(s) = std::fs::read_to_string(d.join("nmap-os-db")) {
            return Cow::Owned(s);
        }
    }
    Cow::Borrowed(os_db::FULL)
}
