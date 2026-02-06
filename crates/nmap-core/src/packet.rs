//! Packet-builder helpers — small wrappers around `etherparse` plus a
//! lancer-specific (`host_idx`, `port`)-to-source-port + ISN encoder used by
//! the raw-socket scanners to recover (host, port) from probe responses
//! without an in-memory tracking table.

use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};

/// Compact tag carried in TCP source-port + ISN low 24 bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeTag {
    pub host_idx: u16,
    pub port: u16,
    pub nonce: u8,
}

impl ProbeTag {
    /// Encode `host_idx` into the source port and `port` + `nonce` into the
    /// ISN low 24 bits. Source-port range is upstream's [33000-65535).
    pub fn encode(self) -> (u16, u32) {
        let sport = 33000u16.wrapping_add(self.host_idx % (65535 - 33000));
        let isn = ((self.port as u32) << 16) | ((self.nonce as u32) << 8);
        let high = rand::thread_rng().gen::<u8>() as u32;
        (sport, isn | high)
    }

    /// Recover the tag from the source-port-back + ISN echoed in SEQ.
    pub fn decode(sport: u16, isn: u32) -> Self {
        Self {
            host_idx: sport.wrapping_sub(33000),
            port: ((isn >> 16) & 0xffff) as u16,
            nonce: ((isn >> 8) & 0xff) as u8,
        }
    }
}

/// Compute a 16-bit one's-complement checksum (used for IPv4 / TCP / UDP /
/// ICMP). Public so the OS-detect probe builder can reuse it for hand-rolled
/// TCP-option payloads.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum = sum.wrapping_add(u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32);
        i += 2;
    }
    if i < bytes.len() {
        sum = sum.wrapping_add((bytes[i] as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Generic local-source-IP picker; returns a private-class fallback if no
/// route is found.
pub fn local_source_ip(_dst: IpAddr) -> IpAddr {
    // A real impl would call `getsockname` on a UDP-connect-to-dst socket.
    // For unprivileged + GUI use this is plenty.
    use socket2::{Domain, Socket, Type};
    let dst = match _dst {
        IpAddr::V4(_) => "8.8.8.8:80".parse().unwrap(),
        IpAddr::V6(_) => "[2001:4860:4860::8888]:80".parse().unwrap(),
    };
    let sock = match _dst {
        IpAddr::V4(_) => Socket::new(Domain::IPV4, Type::DGRAM, None),
        IpAddr::V6(_) => Socket::new(Domain::IPV6, Type::DGRAM, None),
    };
    if let Ok(s) = sock {
        if s.connect(&socket2::SockAddr::from(dst)).is_ok() {
            if let Ok(addr) = s.local_addr() {
                if let Some(a) = addr.as_socket() {
                    return a.ip();
                }
            }
        }
    }
    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
}
