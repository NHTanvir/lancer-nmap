//! `nmap-protocols`: IP protocol number → name.

use once_cell::sync::Lazy;
use std::collections::HashMap;

pub fn name(proto_no: u8) -> Option<&'static str> {
    NAME_MAP.get(&proto_no).copied()
}

/// The complete upstream `nmap-protocols` file, embedded verbatim.
pub const FULL: &str = include_str!("../data/nmap-protocols");

static NAME_MAP: Lazy<HashMap<u8, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    // Hardcoded compact table first (fallback / always-present baseline).
    for &(k, v) in PROTOCOL_TABLE {
        m.insert(k, v);
    }
    // Then overlay the full embedded file: `name  number  aliases  # comment`.
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
        if let Some(num) = it.next().and_then(|n| n.parse::<u8>().ok()) {
            m.insert(num, name);
        }
    }
    m
});

const PROTOCOL_TABLE: &[(u8, &str)] = &[
    (0, "hopopt"),
    (1, "icmp"),
    (2, "igmp"),
    (3, "ggp"),
    (4, "ipv4"),
    (5, "st"),
    (6, "tcp"),
    (7, "cbt"),
    (8, "egp"),
    (9, "igp"),
    (10, "bbn-rcc"),
    (11, "nvp"),
    (12, "pup"),
    (13, "argus"),
    (14, "emcon"),
    (15, "xnet"),
    (16, "chaos"),
    (17, "udp"),
    (18, "mux"),
    (19, "dcn"),
    (20, "hmp"),
    (21, "prm"),
    (22, "xns-idp"),
    (23, "trunk-1"),
    (24, "trunk-2"),
    (25, "leaf-1"),
    (26, "leaf-2"),
    (27, "rdp"),
    (28, "irtp"),
    (29, "iso-tp4"),
    (30, "netblt"),
    (31, "mfe-nsp"),
    (32, "merit-inp"),
    (33, "dccp"),
    (34, "3pc"),
    (35, "idpr"),
    (36, "xtp"),
    (37, "ddp"),
    (38, "idpr-cmtp"),
    (39, "tp++"),
    (40, "il"),
    (41, "ipv6"),
    (42, "sdrp"),
    (43, "ipv6-route"),
    (44, "ipv6-frag"),
    (45, "idrp"),
    (46, "rsvp"),
    (47, "gre"),
    (48, "dsr"),
    (49, "bna"),
    (50, "esp"),
    (51, "ah"),
    (52, "i-nlsp"),
    (53, "swipe"),
    (54, "narp"),
    (55, "mobile"),
    (56, "tlsp"),
    (57, "skip"),
    (58, "ipv6-icmp"),
    (59, "ipv6-nonxt"),
    (60, "ipv6-opts"),
    (88, "eigrp"),
    (89, "ospf"),
    (94, "ipip"),
    (97, "etherip"),
    (98, "encap"),
    (108, "ipcomp"),
    (112, "vrrp"),
    (115, "l2tp"),
    (132, "sctp"),
    (133, "fc"),
    (135, "mobility-header"),
    (136, "udplite"),
    (137, "mpls-in-ip"),
    (138, "manet"),
    (139, "hip"),
    (140, "shim6"),
    (141, "wesp"),
    (142, "rohc"),
];
