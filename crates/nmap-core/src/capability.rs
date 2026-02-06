//! Detect raw-socket capability at runtime so we can transparently fall
//! back to `-sT` (TCP connect) when the user is unprivileged.

use std::sync::atomic::{AtomicI8, Ordering};

static CACHED: AtomicI8 = AtomicI8::new(-1); // -1 = unknown, 0 = no, 1 = yes

pub fn detect_raw() -> bool {
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != -1 {
        return cached == 1;
    }
    let allowed = detect_raw_impl();
    CACHED.store(if allowed { 1 } else { 0 }, Ordering::Relaxed);
    allowed
}

#[cfg(unix)]
fn detect_raw_impl() -> bool {
    // Try opening a raw ICMP socket. If we can, we have CAP_NET_RAW (linux)
    // or BPF perms (mac).
    use socket2::{Domain, Protocol, Socket, Type};
    Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok()
}

#[cfg(windows)]
fn detect_raw_impl() -> bool {
    // On Windows, raw sockets are nerfed since XP SP2 — Npcap is required.
    // We check for Npcap by probing the well-known service registry key.
    // This is best-effort; the real test is whether `pcap::Capture::from_device`
    // succeeds, which the raw scanners do at start-up.
    npcap_present()
}

#[cfg(windows)]
fn npcap_present() -> bool {
    use std::path::Path;
    Path::new(r"C:\Windows\System32\Npcap").exists()
        || Path::new(r"C:\Windows\System32\drivers\npcap.sys").exists()
}

#[cfg(not(any(unix, windows)))]
fn detect_raw_impl() -> bool {
    false
}

pub fn cached_message() -> String {
    if detect_raw() {
        "raw-socket capability available".into()
    } else if cfg!(windows) {
        "raw sockets unavailable — install Npcap or run as Administrator".into()
    } else {
        "raw sockets unavailable — needs CAP_NET_RAW + CAP_NET_ADMIN, or root".into()
    }
}
