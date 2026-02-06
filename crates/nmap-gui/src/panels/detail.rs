use crate::app::App;
use eframe::egui;

pub fn ui(ui: &mut egui::Ui, app: &mut App) {
    ui.heading("Detail");
    let idx = *app.state.selected_host.lock();
    let jobs = app.state.jobs.lock().clone();
    let result = jobs.iter().rev().find_map(|j| j.result.clone());
    let host = match (idx, result.as_ref()) {
        (Some(i), Some(r)) => r.hosts.get(i).cloned(),
        _ => None,
    };
    let Some(h) = host else {
        ui.label("Select a host from the results table to see details.");
        return;
    };
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.label(format!("IP: {}", h.address));
        if !h.hostnames.is_empty() {
            ui.label(format!("Hostnames: {}", h.hostnames.join(", ")));
        }
        if let Some(mac) = &h.mac {
            ui.label(format!("MAC: {mac}"));
        }
        if let Some(v) = &h.vendor {
            ui.label(format!("Vendor: {v}"));
        }
        ui.separator();
        ui.label(format!("State: {:?}", h.state));
        if let Some(r) = &h.state_reason {
            ui.label(format!("Reason: {}", r.reason));
        }
        ui.separator();
        ui.label("Ports:");
        for p in &h.ports {
            ui.collapsing(
                format!(
                    "{}/{} {}",
                    p.port.number,
                    p.port.protocol.short(),
                    p.state.as_str()
                ),
                |ui| {
                    if let Some(r) = &p.reason {
                        ui.label(format!("reason: {}", r.reason));
                    }
                    if let Some(s) = &p.service {
                        if let Some(n) = &s.name {
                            ui.label(format!("service: {n}"));
                        }
                        if let Some(pr) = &s.product {
                            ui.label(format!("product: {pr}"));
                        }
                        if let Some(v) = &s.version {
                            ui.label(format!("version: {v}"));
                        }
                        if let Some(e) = &s.extra_info {
                            ui.label(format!("extra: {e}"));
                        }
                        for c in &s.cpe {
                            ui.label(format!("cpe: {c}"));
                        }
                    }
                    for sc in &p.scripts {
                        ui.label(format!("[{}] {}", sc.id, sc.output));
                    }
                },
            );
        }
        if !h.os_matches.is_empty() {
            ui.separator();
            ui.label("OS matches:");
            for om in &h.os_matches {
                ui.label(format!("{} ({}%)", om.name, om.accuracy));
            }
        }
        if !h.host_scripts.is_empty() {
            ui.separator();
            ui.label("Host scripts:");
            for s in &h.host_scripts {
                ui.label(format!("[{}] {}", s.id, s.output));
            }
        }
        if !h.trace.is_empty() {
            ui.separator();
            ui.label("Trace:");
            for hop in &h.trace {
                ui.label(format!(
                    "  {:>2}  {:>6.1}ms  {}",
                    hop.ttl,
                    hop.rtt_ms,
                    hop.ip.map(|i| i.to_string()).unwrap_or_default()
                ));
            }
        }
    });
}
