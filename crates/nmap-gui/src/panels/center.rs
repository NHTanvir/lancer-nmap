use crate::app::App;
use eframe::egui;
use egui_extras::{Column, TableBuilder};

pub fn ui(ui: &mut egui::Ui, app: &mut App) {
    ui.heading("Results");
    let jobs = app.state.jobs.lock().clone();
    let result = jobs.iter().rev().find_map(|j| j.result.clone());
    let hosts = result
        .as_ref()
        .map(|r| r.hosts.clone())
        .unwrap_or_default();
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(160.0).at_least(120.0).clip(true))
        .column(Column::initial(90.0))
        .column(Column::initial(120.0))
        .column(Column::initial(80.0))
        .column(Column::initial(110.0))
        .column(Column::remainder())
        .header(20.0, |mut header| {
            header.col(|ui| {
                ui.strong("Host");
            });
            header.col(|ui| {
                ui.strong("State");
            });
            header.col(|ui| {
                ui.strong("Open ports");
            });
            header.col(|ui| {
                ui.strong("Vendor");
            });
            header.col(|ui| {
                ui.strong("OS guess");
            });
            header.col(|ui| {
                ui.strong("Top services");
            });
        })
        .body(|mut body| {
            for (i, host) in hosts.iter().enumerate() {
                body.row(20.0, |mut row| {
                    row.col(|ui| {
                        let label = if let Some(name) = host.hostnames.first() {
                            format!("{} ({})", name, host.address)
                        } else {
                            host.address.to_string()
                        };
                        if ui.selectable_label(*app.state.selected_host.lock() == Some(i), label).clicked() {
                            *app.state.selected_host.lock() = Some(i);
                        }
                    });
                    row.col(|ui| {
                        ui.label(format!("{:?}", host.state));
                    });
                    row.col(|ui| {
                        let n = host
                            .ports
                            .iter()
                            .filter(|p| {
                                matches!(
                                    p.state,
                                    nmap_core::result::PortState::Open
                                        | nmap_core::result::PortState::OpenFiltered
                                )
                            })
                            .count();
                        ui.label(format!("{n}/{}", host.ports.len()));
                    });
                    row.col(|ui| {
                        ui.label(host.vendor.clone().unwrap_or_default());
                    });
                    row.col(|ui| {
                        if let Some(om) = host.os_matches.first() {
                            ui.label(format!("{} ({}%)", om.name, om.accuracy));
                        } else {
                            ui.label("-");
                        }
                    });
                    row.col(|ui| {
                        let s: Vec<String> = host
                            .ports
                            .iter()
                            .filter(|p| matches!(p.state, nmap_core::result::PortState::Open))
                            .take(5)
                            .map(|p| {
                                let svc = p
                                    .service
                                    .as_ref()
                                    .and_then(|s| s.name.clone())
                                    .unwrap_or_default();
                                format!("{}/{}/{}", p.port.number, p.port.protocol.short(), svc)
                            })
                            .collect();
                        ui.label(s.join(", "));
                    });
                });
            }
        });
}
