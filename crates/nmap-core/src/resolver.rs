//! Async DNS — hickory-resolver, plus an `/etc/hosts` pre-lookup so
//! `localhost` returns `127.0.0.1` without going to the network (7.97+ fix).

use crate::error::{Error, Result};
use crate::target::Target;
use hickory_resolver::{
    config::{NameServerConfig, Protocol as DnsProto, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone)]
pub struct Resolver {
    inner: Arc<TokioAsyncResolver>,
    hosts: Arc<HashMap<String, Vec<IpAddr>>>,
    resolve_all: bool,
}

impl Resolver {
    pub fn from_options(
        custom_servers: &[IpAddr],
        system_dns: bool,
        resolve_all: bool,
    ) -> Result<Self> {
        let mut cfg = if system_dns || custom_servers.is_empty() {
            ResolverConfig::cloudflare_https()
        } else {
            ResolverConfig::new()
        };
        for s in custom_servers {
            cfg.add_name_server(NameServerConfig::new(
                SocketAddr::new(*s, 53),
                DnsProto::Udp,
            ));
            cfg.add_name_server(NameServerConfig::new(
                SocketAddr::new(*s, 53),
                DnsProto::Tcp,
            ));
        }
        let mut opts = ResolverOpts::default();
        opts.num_concurrent_reqs = 64;
        opts.timeout = std::time::Duration::from_secs(5);
        let resolver = TokioAsyncResolver::tokio(cfg, opts);
        Ok(Self {
            inner: Arc::new(resolver),
            hosts: Arc::new(load_hosts_file()),
            resolve_all,
        })
    }

    pub async fn lookup(&self, host: &str) -> Result<Vec<Target>> {
        // Localhost is special-cased.
        let key = host.to_ascii_lowercase();
        if key == "localhost" || key == "ip6-localhost" || key == "localhost.localdomain" {
            return Ok(vec![Target::with_hostname(
                IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                host,
            )]);
        }
        if let Some(v) = self.hosts.get(&key) {
            return Ok(v
                .iter()
                .map(|ip| Target::with_hostname(*ip, host))
                .collect());
        }
        let resp = self
            .inner
            .lookup_ip(host)
            .await
            .map_err(|e| Error::Resolution(format!("{host}: {e}")))?;
        let mut out = Vec::new();
        for ip in resp.iter() {
            out.push(Target::with_hostname(ip, host));
            if !self.resolve_all {
                break;
            }
        }
        Ok(out)
    }

    pub async fn reverse(&self, ip: IpAddr) -> Option<String> {
        let r = self.inner.reverse_lookup(ip).await.ok()?;
        let first = r.iter().next()?;
        Some(first.to_string().trim_end_matches('.').to_string())
    }
}

fn load_hosts_file() -> HashMap<String, Vec<IpAddr>> {
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let paths: Vec<PathBuf> = if cfg!(windows) {
        vec![PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")]
    } else {
        vec![PathBuf::from("/etc/hosts")]
    };
    for path in paths {
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                let line = line.split('#').next().unwrap_or("");
                let mut parts = line.split_whitespace();
                let ip = match parts.next().and_then(|t| t.parse::<IpAddr>().ok()) {
                    Some(ip) => ip,
                    None => continue,
                };
                for name in parts {
                    map.entry(name.to_ascii_lowercase())
                        .or_default()
                        .push(ip);
                }
            }
        }
    }
    // Guarantee localhost regardless of hosts-file presence.
    map.entry("localhost".into())
        .or_default()
        .push(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    map
}
