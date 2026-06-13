//! `nmap-rpc`: Sun-RPC program number → name lookup.

use once_cell::sync::Lazy;
use std::collections::HashMap;

/// The complete upstream `nmap-rpc` file, embedded verbatim.
pub const FULL: &str = include_str!("../data/nmap-rpc");

static RPC_MAP: Lazy<HashMap<u32, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    for &(k, v) in RPC_TABLE {
        m.insert(k, v);
    }
    // Overlay the full embedded file: `name  number  aliases  # comment`.
    for line in FULL.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let name = match it.next() {
            Some(n) => n,
            None => continue,
        };
        if let Some(num) = it.next().and_then(|n| n.parse::<u32>().ok()) {
            m.insert(num, name);
        }
    }
    m
});

pub fn lookup(program_no: u32) -> Option<&'static str> {
    RPC_MAP.get(&program_no).copied()
}

const RPC_TABLE: &[(u32, &str)] = &[
    (100000, "portmapper"),
    (100001, "rstatd"),
    (100002, "rusersd"),
    (100003, "nfs"),
    (100004, "ypserv"),
    (100005, "mountd"),
    (100007, "ypbind"),
    (100008, "walld"),
    (100009, "yppasswdd"),
    (100011, "rquotad"),
    (100012, "sprayd"),
    (100017, "rexd"),
    (100021, "nlockmgr"),
    (100024, "status"),
    (100026, "bootparam"),
    (100068, "cmsd"),
    (100078, "kerbd"),
    (100083, "ttdbserverd"),
    (100087, "adm-mountd"),
    (100099, "autofs"),
    (100133, "nsm_addrand"),
    (100134, "ypxfrd"),
    (100150, "mediad"),
    (100166, "snmpXdmid"),
    (100221, "amd"),
    (100227, "nfs_acl"),
    (100229, "metad"),
    (100230, "metamhd"),
    (100232, "sadmind"),
    (100235, "cachefsd"),
    (100236, "kcms_server"),
    (100249, "snmpdx"),
    (100300, "nisd"),
    (100302, "rpc.nispasswd"),
    (100303, "rpc.rusersd"),
    (390113, "Solaris-PC-NetLink-rpc"),
    (390435, "Solaris-PC-NetLink-rpc"),
    (805306368, "Win32-RPC"),
];
