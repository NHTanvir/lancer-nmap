//! `nmap-mac-prefixes`: 24-bit MAC OUI → vendor lookup.

use once_cell::sync::Lazy;
use std::collections::HashMap;

static OUI_MAP: Lazy<HashMap<u32, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    for &(k, v) in OUI_TABLE {
        m.insert(k, v);
    }
    m
});

pub fn lookup(mac: &[u8; 6]) -> Option<&'static str> {
    let key = ((mac[0] as u32) << 16) | ((mac[1] as u32) << 8) | (mac[2] as u32);
    OUI_MAP.get(&key).copied()
}

pub fn lookup_str(mac_str: &str) -> Option<&'static str> {
    let mut bytes = [0u8; 6];
    let mut i = 0;
    for part in mac_str.split(|c| c == ':' || c == '-') {
        if i >= 6 {
            return None;
        }
        bytes[i] = u8::from_str_radix(part, 16).ok()?;
        i += 1;
    }
    if i < 3 {
        return None;
    }
    lookup(&bytes)
}

// Compact subset of the upstream nmap-mac-prefixes file. Real builds can
// override via `--datadir`.
const OUI_TABLE: &[(u32, &str)] = &[
    (0x000000, "XEROX"), (0x000001, "XEROX"), (0x000002, "XEROX"), (0x000003, "XEROX"),
    (0x00000C, "Cisco"), (0x000142, "Cisco"), (0x001B63, "Apple"), (0x002241, "Apple"),
    (0x002500, "Apple"), (0x003065, "Apple"), (0x0050C2, "IEEE Registration Authority"),
    (0x005056, "VMware"), (0x000C29, "VMware"), (0x000569, "VMware"), (0x001C14, "VMware"),
    (0x080027, "PCS Computer Systems GmbH (VirtualBox)"), (0x525400, "Realtek (QEMU virtual NIC)"),
    (0x000D3A, "Microsoft"), (0x0017FA, "Microsoft"), (0x002248, "Microsoft"),
    (0x009027, "Intel"), (0x001500, "Intel"), (0x001F3B, "Intel"), (0x0024D7, "Intel"),
    (0x002608, "Apple"), (0x10DDB1, "Apple"), (0x40B395, "Apple"), (0x6CC26B, "Apple"),
    (0x000625, "Linksys"), (0x001310, "Linksys"), (0x001839, "Cisco-Linksys"),
    (0x002129, "Cisco-Linksys"), (0xC03F0E, "Netgear"), (0x002722, "Netgear"),
    (0x44E137, "Netgear"), (0x0024B2, "Netgear"), (0x000FB5, "Netgear"),
    (0x001B11, "D-Link"), (0x00179A, "D-Link"), (0x4C76DB, "D-Link"),
    (0x000000, "Reserved"), (0xB827EB, "Raspberry Pi Foundation"),
    (0xDCA632, "Raspberry Pi Trading"), (0xE45F01, "Raspberry Pi Trading"),
    (0xC83A35, "Tenda Technology"), (0x000874, "Dell"), (0x14B31F, "Dell"),
    (0x00219B, "Dell"), (0x782BCB, "Dell"), (0x9C8E99, "HP"), (0x9457A5, "HP"),
    (0x00904C, "Epigram"), (0x002608, "Apple"), (0x80F6E0, "Espressif"), (0xC44F33, "Espressif"),
    (0x0CB815, "Espressif"), (0x84F3EB, "Espressif"), (0xC8C9A3, "Espressif"),
    (0x001E58, "WistronInfoComm"), (0x000000, "Xerox"),
    (0x00E04C, "Realtek"), (0x52540A, "Realtek"),
    (0x6C40088, "Apple"), (0xCC25EF, "Apple"), (0xF8FFC2, "Apple"), (0xB8E856, "Apple"),
    (0xACDE48, "Apple"), (0xE0F847, "Apple"),
];
