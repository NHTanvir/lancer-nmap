//! Script registry — discovery + lookup.

use crate::categories::{Category, CategoryFilter};
use crate::scripts::Script;
use indexmap::IndexMap;
use std::path::Path;
use tracing::trace;

#[derive(Default)]
pub struct ScriptRegistry {
    pub scripts: IndexMap<String, Script>,
}

impl ScriptRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate the registry with the bundled starter scripts.
    pub fn load_builtin(&mut self) {
        for s in starter_scripts() {
            self.scripts.insert(s.name.clone(), s);
        }
    }

    pub fn discover_in(&mut self, dir: &Path) {
        for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
            if entry.file_type().is_file() {
                if let Some(name) = entry.path().file_name().and_then(|n| n.to_str()) {
                    if name.ends_with(".nse") {
                        let path = entry.path().to_path_buf();
                        let body = std::fs::read_to_string(&path).unwrap_or_default();
                        let parsed = parse_header(&body);
                        let s = Script {
                            name: name.trim_end_matches(".nse").to_string(),
                            path: Some(path),
                            source: Some(body),
                            description: parsed.description,
                            categories: parsed.categories,
                            author: parsed.author,
                            license: parsed.license,
                            dependencies: parsed.dependencies,
                        };
                        self.scripts.insert(s.name.clone(), s);
                    }
                }
            }
        }
        trace!("NSE registry loaded {} scripts", self.scripts.len());
    }

    pub fn filter(&self, f: &CategoryFilter) -> Vec<Script> {
        self.scripts
            .values()
            .filter(|s| f.allows(&s.name, &s.categories))
            .cloned()
            .collect()
    }
}

struct ParsedHeader {
    description: String,
    categories: Vec<Category>,
    author: String,
    license: String,
    dependencies: Vec<String>,
}

fn parse_header(body: &str) -> ParsedHeader {
    let mut out = ParsedHeader {
        description: String::new(),
        categories: Vec::new(),
        author: String::new(),
        license: String::new(),
        dependencies: Vec::new(),
    };
    // Crude scan for description = [[ ... ]], categories = {...}, etc.
    if let Some(start) = body.find("description") {
        let tail = &body[start..];
        if let Some(open) = tail.find("[[") {
            if let Some(close) = tail[open..].find("]]") {
                out.description = tail[open + 2..open + close].trim().to_string();
            }
        }
    }
    if let Some(start) = body.find("categories") {
        let tail = &body[start..];
        if let Some(open) = tail.find('{') {
            if let Some(close) = tail[open..].find('}') {
                let body = &tail[open + 1..open + close];
                for tok in body.split(',') {
                    let tok = tok.trim().trim_matches('"').trim_matches('\'');
                    if let Some(c) = Category::parse(tok) {
                        out.categories.push(c);
                    }
                }
            }
        }
    }
    if let Some(start) = body.find("author") {
        let tail = &body[start..];
        if let Some(open) = tail.find('"') {
            if let Some(close) = tail[open + 1..].find('"') {
                out.author = tail[open + 1..open + 1 + close].to_string();
            }
        }
    }
    if let Some(start) = body.find("license") {
        let tail = &body[start..];
        if let Some(open) = tail.find('"') {
            if let Some(close) = tail[open + 1..].find('"') {
                out.license = tail[open + 1..open + 1 + close].to_string();
            }
        }
    }
    out
}

fn starter_scripts() -> Vec<Script> {
    use Category::*;
    vec![
        Script::builtin(
            "http-title",
            include_str!("../scripts/http-title.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "http-headers",
            include_str!("../scripts/http-headers.nse"),
            &[Discovery, Safe],
        ),
        Script::builtin(
            "http-methods",
            include_str!("../scripts/http-methods.nse"),
            &[Default, Safe],
        ),
        Script::builtin(
            "http-enum",
            include_str!("../scripts/http-enum.nse"),
            &[Discovery, Intrusive],
        ),
        Script::builtin(
            "http-robots-txt",
            include_str!("../scripts/http-robots-txt.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "ssl-cert",
            include_str!("../scripts/ssl-cert.nse"),
            &[Default, Safe, Discovery],
        ),
        Script::builtin(
            "ssl-enum-ciphers",
            include_str!("../scripts/ssl-enum-ciphers.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "ssl-heartbleed",
            include_str!("../scripts/ssl-heartbleed.nse"),
            &[Vuln, Safe],
        ),
        Script::builtin(
            "ftp-anon",
            include_str!("../scripts/ftp-anon.nse"),
            &[Default, Auth, Safe],
        ),
        Script::builtin(
            "ftp-syst",
            include_str!("../scripts/ftp-syst.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "ssh-hostkey",
            include_str!("../scripts/ssh-hostkey.nse"),
            &[Default, Safe, Discovery],
        ),
        Script::builtin(
            "ssh-auth-methods",
            include_str!("../scripts/ssh-auth-methods.nse"),
            &[Auth, Discovery],
        ),
        Script::builtin(
            "ssh-brute",
            include_str!("../scripts/ssh-brute.nse"),
            &[Brute, Intrusive],
        ),
        Script::builtin(
            "smb-os-discovery",
            include_str!("../scripts/smb-os-discovery.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "smb-enum-shares",
            include_str!("../scripts/smb-enum-shares.nse"),
            &[Discovery, Intrusive],
        ),
        Script::builtin(
            "smb-vuln-ms17-010",
            include_str!("../scripts/smb-vuln-ms17-010.nse"),
            &[Vuln, Safe],
        ),
        Script::builtin(
            "smb-vuln-webexec",
            include_str!("../scripts/smb-vuln-webexec.nse"),
            &[Vuln, Safe],
        ),
        Script::builtin(
            "dns-recursion",
            include_str!("../scripts/dns-recursion.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "dns-zone-transfer",
            include_str!("../scripts/dns-zone-transfer.nse"),
            &[Discovery, Intrusive],
        ),
        Script::builtin(
            "smtp-commands",
            include_str!("../scripts/smtp-commands.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "smtp-enum-users",
            include_str!("../scripts/smtp-enum-users.nse"),
            &[Discovery, Intrusive],
        ),
        Script::builtin(
            "snmp-info",
            include_str!("../scripts/snmp-info.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "snmp-sysdescr",
            include_str!("../scripts/snmp-sysdescr.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "mysql-info",
            include_str!("../scripts/mysql-info.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "mysql-empty-password",
            include_str!("../scripts/mysql-empty-password.nse"),
            &[Auth, Intrusive],
        ),
        Script::builtin(
            "mssql-info",
            include_str!("../scripts/mssql-info.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "redis-info",
            include_str!("../scripts/redis-info.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "mongodb-info",
            include_str!("../scripts/mongodb-info.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "rdp-enum-encryption",
            include_str!("../scripts/rdp-enum-encryption.nse"),
            &[Discovery, Safe],
        ),
        Script::builtin(
            "rpcinfo",
            include_str!("../scripts/rpcinfo.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "telnet-encryption",
            include_str!("../scripts/telnet-encryption.nse"),
            &[Discovery, Safe],
        ),
        Script::builtin(
            "vnc-info",
            include_str!("../scripts/vnc-info.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "vnc-title",
            include_str!("../scripts/vnc-title.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "ntp-info",
            include_str!("../scripts/ntp-info.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "ntp-monlist",
            include_str!("../scripts/ntp-monlist.nse"),
            &[Discovery, Intrusive],
        ),
        Script::builtin(
            "memcached-info",
            include_str!("../scripts/memcached-info.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "elasticsearch-info",
            include_str!("../scripts/elasticsearch-info.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "docker-version",
            include_str!("../scripts/docker-version.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "http-vuln-cve2017-5638",
            include_str!("../scripts/http-vuln-cve2017-5638.nse"),
            &[Vuln, Safe],
        ),
        Script::builtin(
            "http-vuln-cve2014-3704",
            include_str!("../scripts/http-vuln-cve2014-3704.nse"),
            &[Vuln, Safe],
        ),
        Script::builtin(
            "http-aws-imds",
            include_str!("../scripts/http-aws-imds.nse"),
            &[Vuln, Discovery],
        ),
        Script::builtin(
            "http-kube-anon-access",
            include_str!("../scripts/http-kube-anon-access.nse"),
            &[Discovery, Vuln],
        ),
        Script::builtin(
            "http-internal-ip-disclosure",
            include_str!("../scripts/http-internal-ip-disclosure.nse"),
            &[Discovery, Vuln],
        ),
        Script::builtin(
            "hostmap-crtsh",
            include_str!("../scripts/hostmap-crtsh.nse"),
            &[Discovery, External, Safe],
        ),
        Script::builtin(
            "mikrotik-routeros-version",
            include_str!("../scripts/mikrotik-routeros-version.nse"),
            &[Discovery, Iot, Safe],
        ),
        Script::builtin(
            "mikrotik-routeros-username-brute",
            include_str!("../scripts/mikrotik-routeros-username-brute.nse"),
            &[Brute, Intrusive, Iot],
        ),
        Script::builtin(
            "modbus-discover",
            include_str!("../scripts/modbus-discover.nse"),
            &[Discovery, Ics, Safe],
        ),
        Script::builtin(
            "s7-info",
            include_str!("../scripts/s7-info.nse"),
            &[Discovery, Ics, Safe],
        ),
        Script::builtin(
            "bacnet-info",
            include_str!("../scripts/bacnet-info.nse"),
            &[Discovery, Ics, Safe],
        ),
        Script::builtin(
            "hartip-info",
            include_str!("../scripts/hartip-info.nse"),
            &[Discovery, Ics, Safe],
        ),
        Script::builtin(
            "tls-alpn",
            include_str!("../scripts/tls-alpn.nse"),
            &[Default, Discovery, Safe],
        ),
        Script::builtin(
            "rsa-vuln-roca",
            include_str!("../scripts/rsa-vuln-roca.nse"),
            &[Vuln, Safe],
        ),
        Script::builtin(
            "openflow-info",
            include_str!("../scripts/openflow-info.nse"),
            &[Discovery, Safe],
        ),
    ]
}
