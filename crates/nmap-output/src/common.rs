use nmap_core::result::{HostResult, PortResult, PortState, ScanResult};

pub fn elapsed_seconds(r: &ScanResult) -> f64 {
    r.elapsed.as_secs_f64()
}

pub fn open_ports(h: &HostResult) -> Vec<&PortResult> {
    h.ports
        .iter()
        .filter(|p| matches!(p.state, PortState::Open | PortState::OpenFiltered))
        .collect()
}
