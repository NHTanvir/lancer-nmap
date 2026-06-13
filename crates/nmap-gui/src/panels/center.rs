use crate::app::App;
use crate::state::JobStatus;
use crate::theme;
use eframe::egui::{self, Color32, RichText};
use nmap_core::result::{HostState, PortResult, PortState};

pub fn ui(ui: &mut egui::Ui, app: &mut App) {
    let jobs = app.state.jobs.lock().clone();
    let result = jobs.iter().rev().find_map(|j| j.result.clone());
    let running = jobs
        .iter()
        .any(|j| matches!(j.progress.status, JobStatus::Running));

    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.heading("Results");
        if running {
            ui.add(egui::Spinner::new().size(16.0));
            ui.label(RichText::new("scanning…").color(theme::TEXT_DIM));
        }
    });
    ui.add_space(8.0);

    let Some(r) = result else {
        ui.add_space(60.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("🛰  No results yet").size(18.0).color(theme::TEXT_DIM));
            ui.add_space(4.0);
            ui.label(
                RichText::new("Enter a target on the left and press  ▶ Run Scan")
                    .color(theme::TEXT_DIM),
            );
        });
        return;
    };

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (i, host) in r.hosts.iter().enumerate() {
                host_card(ui, app, i, host);
                ui.add_space(12.0);
            }

            ui.collapsing(
                RichText::new("📄  Raw nmap output (-oN)").color(theme::TEXT_DIM),
                |ui| {
                    let mut text = nmap_output::emit_normal(&r);
                    if ui.button("📋  Copy to clipboard").clicked() {
                        ui.ctx().copy_text(text.clone());
                    }
                    ui.add_space(4.0);
                    ui.add(
                        egui::TextEdit::multiline(&mut text)
                            .code_editor()
                            .desired_width(f32::INFINITY),
                    );
                },
            );
            ui.add_space(8.0);
        });
}

fn host_card(ui: &mut egui::Ui, app: &mut App, i: usize, host: &nmap_core::result::HostResult) {
    let selected = *app.state.selected_host.lock() == Some(i);
    let up = matches!(host.state, HostState::Up);
    egui::Frame::none()
        .fill(theme::BG_CARD)
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::same(14.0))
        .stroke(egui::Stroke::new(
            if selected { 1.6 } else { 1.0 },
            if selected {
                theme::ACCENT
            } else {
                Color32::from_rgb(0x2a, 0x2e, 0x44)
            },
        ))
        .show(ui, |ui| {
            // Header: status dot · host · UP/DOWN badge
            ui.horizontal(|ui| {
                ui.label(RichText::new("●").size(14.0).color(if up {
                    theme::GREEN
                } else {
                    theme::RED
                }));
                let name = host
                    .hostnames
                    .first()
                    .map(|h| format!("{h}  "))
                    .unwrap_or_default();
                let title = format!("{name}{}", host.address);
                if ui
                    .selectable_label(selected, RichText::new(title).size(16.0).strong())
                    .clicked()
                {
                    *app.state.selected_host.lock() = Some(i);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (txt, col) = if up {
                        ("UP", theme::GREEN)
                    } else {
                        ("DOWN", theme::RED)
                    };
                    ui.label(RichText::new(txt).small().strong().color(col).background_color(
                        col.linear_multiply(0.18),
                    ));
                });
            });

            let open = host
                .ports
                .iter()
                .filter(|p| {
                    matches!(p.state, PortState::Open | PortState::OpenFiltered)
                })
                .count();
            let mut meta = format!("{open} open · {} scanned", host.ports.len());
            if let Some(rs) = &host.state_reason {
                meta.push_str(&format!("  ·  {}", rs.reason));
            }
            ui.label(RichText::new(meta).small().color(theme::TEXT_DIM));
            ui.add_space(8.0);

            // Port table
            if host.ports.is_empty() {
                ui.label(RichText::new("no ports scanned").italics().color(theme::TEXT_DIM));
            } else {
                egui::Grid::new(("ports", i))
                    .num_columns(4)
                    .spacing([22.0, 5.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for h in ["PORT", "STATE", "SERVICE", "VERSION"] {
                            ui.label(RichText::new(h).small().strong().color(theme::TEXT_DIM));
                        }
                        ui.end_row();
                        for p in &host.ports {
                            ui.label(
                                RichText::new(format!("{}/{}", p.port.number, p.port.protocol.short()))
                                    .monospace(),
                            );
                            let st = p.state.as_str();
                            ui.label(RichText::new(st).monospace().color(theme::state_color(st)));
                            let svc = p
                                .service
                                .as_ref()
                                .and_then(|s| s.name.clone())
                                .or_else(|| {
                                    nmap_data::services::service_name(
                                        p.port.number,
                                        p.port.protocol.short(),
                                    )
                                    .map(|s| s.to_string())
                                })
                                .unwrap_or_default();
                            ui.label(RichText::new(svc).monospace().color(theme::CYAN));
                            ui.label(RichText::new(version_string(p)).monospace().color(theme::TEXT));
                            ui.end_row();
                        }
                    });

                // NSE script output, indented under the ports.
                for p in &host.ports {
                    for sc in &p.scripts {
                        if sc.output.is_empty() {
                            continue;
                        }
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new(format!("│ {}: {}", sc.id, sc.output))
                                .monospace()
                                .small()
                                .color(theme::GREEN),
                        );
                    }
                }
            }

            if !host.os_matches.is_empty() {
                ui.add_space(6.0);
                for om in host.os_matches.iter().take(3) {
                    ui.label(
                        RichText::new(format!("⊞ OS: {} ({}%)", om.name, om.accuracy))
                            .small()
                            .color(theme::ORANGE),
                    );
                }
            }
        });
}

fn version_string(p: &PortResult) -> String {
    let Some(s) = &p.service else {
        return String::new();
    };
    let mut v = String::new();
    if let Some(x) = &s.product {
        v.push_str(x);
    }
    if let Some(x) = &s.version {
        if !v.is_empty() {
            v.push(' ');
        }
        v.push_str(x);
    }
    if let Some(x) = &s.extra_info {
        if !x.is_empty() {
            v.push_str(&format!(" ({x})"));
        }
    }
    v
}
