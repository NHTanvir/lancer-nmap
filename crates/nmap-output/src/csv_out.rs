//! Lancer-extension CSV emitter — port-row per host.

use nmap_core::result::ScanResult;

pub fn emit(r: &ScanResult) -> String {
    let mut wtr = csv::Writer::from_writer(vec![]);
    let _ = wtr.write_record(["host", "hostname", "port", "protocol", "state", "service", "product", "version", "reason"]);
    for h in &r.hosts {
        let hn = h.hostnames.first().cloned().unwrap_or_default();
        for p in &h.ports {
            let _ = wtr.write_record([
                h.address.to_string(),
                hn.clone(),
                p.port.number.to_string(),
                p.port.protocol.short().to_string(),
                p.state.as_str().to_string(),
                p.service.as_ref().and_then(|s| s.name.clone()).unwrap_or_default(),
                p.service.as_ref().and_then(|s| s.product.clone()).unwrap_or_default(),
                p.service.as_ref().and_then(|s| s.version.clone()).unwrap_or_default(),
                p.reason.as_ref().map(|r| r.reason.clone()).unwrap_or_default(),
            ]);
        }
    }
    let data = wtr.into_inner().unwrap_or_default();
    String::from_utf8(data).unwrap_or_default()
}
