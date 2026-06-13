use crate::app::App;
use crate::theme::Theme;
use eframe::egui;

pub fn ui(ctx: &egui::Context, app: &mut App) {
    egui::TopBottomPanel::top("menu").show(ctx, |ui| {
        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Open targets file…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        if let Ok(text) = std::fs::read_to_string(&path) {
                            app.state.form.lock().targets = text;
                        }
                        ui.close_menu();
                    }
                }
                if ui.button("Export results…").clicked() {
                    let _ = rfd::FileDialog::new().save_file();
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("Tools", |ui| {
                // The primary Run action lives under the input form in the
                // sidebar ("Run Scan"), right after the targets/options.
                if ui.button("Compare scans (ndiff)…").clicked() {
                    ui.close_menu();
                }
                if ui.button("Packet crafter (nping)…").clicked() {
                    ui.close_menu();
                }
            });
            ui.menu_button("Settings", |ui| {
                let mut theme = *app.state.theme.lock();
                if ui.radio(theme == Theme::Dark, "Dark").clicked() {
                    theme = Theme::Dark;
                }
                if ui.radio(theme == Theme::Light, "Light").clicked() {
                    theme = Theme::Light;
                }
                if ui.radio(theme == Theme::System, "System").clicked() {
                    theme = Theme::System;
                }
                if theme != *app.state.theme.lock() {
                    *app.state.theme.lock() = theme;
                    ctx.set_visuals(theme.visuals());
                }
            });
            ui.menu_button("Help", |ui| {
                if ui.button("About").clicked() {
                    ui.close_menu();
                }
                if ui.button("Docs").clicked() {
                    ui.close_menu();
                }
            });
        });
    });
}
