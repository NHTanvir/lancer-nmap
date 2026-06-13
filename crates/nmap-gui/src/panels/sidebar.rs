use crate::app::App;
use crate::state::JobStatus;
use eframe::egui;

pub fn ui(ui: &mut egui::Ui, app: &mut App) {
    ui.heading("Inputs");
    let mut form = app.state.form.lock().clone();
    ui.add_space(6.0);
    ui.label("Targets (one per line)");
    ui.add(
        egui::TextEdit::multiline(&mut form.targets)
            .desired_rows(4)
            .hint_text("e.g. scanme.nmap.org 10.0.0.0/24"),
    );
    ui.add_space(6.0);
    ui.label("Ports (`-p`)");
    ui.add(
        egui::TextEdit::singleline(&mut form.ports)
            .hint_text("80,443,1-1024"),
    );
    ui.add_space(8.0);
    egui::Grid::new("toggles").num_columns(2).show(ui, |ui| {
        ui.checkbox(&mut form.fast, "-F fast");
        ui.checkbox(&mut form.udp, "-sU UDP");
        ui.end_row();
        ui.checkbox(&mut form.service_scan, "-sV");
        ui.checkbox(&mut form.os_scan, "-O");
        ui.end_row();
        ui.checkbox(&mut form.aggressive, "-A");
        ui.checkbox(&mut form.traceroute, "--traceroute");
        ui.end_row();
        ui.checkbox(&mut form.default_scripts, "-sC");
        ui.checkbox(&mut form.vpn_passthrough, "VPN");
        ui.end_row();
    });
    ui.add_space(8.0);
    ui.label("--script (NSE selector)");
    ui.add(egui::TextEdit::singleline(&mut form.script_spec).hint_text("default,vuln,!intrusive"));

    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label("Timing");
        for t in 0..=5 {
            let label = format!("T{}", t);
            if ui.selectable_label(form.timing == t, label).clicked() {
                form.timing = t;
            }
        }
    });
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label("Min rate (pps)");
        let mut s = form.min_rate.map(|n| n.to_string()).unwrap_or_default();
        if ui.text_edit_singleline(&mut s).changed() {
            form.min_rate = s.parse().ok();
        }
    });
    ui.horizontal(|ui| {
        ui.label("Max rate (pps)");
        let mut s = form.max_rate.map(|n| n.to_string()).unwrap_or_default();
        if ui.text_edit_singleline(&mut s).changed() {
            form.max_rate = s.parse().ok();
        }
    });
    *app.state.form.lock() = form;

    // Primary action: Run the scan with everything entered above.
    ui.add_space(12.0);
    let has_target = !app
        .state
        .form
        .lock()
        .targets
        .trim()
        .is_empty();
    let run = ui.add_sized(
        [ui.available_width(), 34.0],
        egui::Button::new(egui::RichText::new("▶  Run Scan").size(16.0).strong())
            .fill(egui::Color32::from_rgb(0x1f, 0x7a, 0x33)),
    );
    if !has_target {
        ui.label(
            egui::RichText::new("enter a target above first")
                .small()
                .weak(),
        );
    }
    if run.clicked() && has_target {
        app.run_form(ui.ctx());
    }
    ui.add_space(8.0);

    ui.separator();
    ui.heading("Jobs");
    let jobs = app.state.jobs.lock().clone();
    egui::ScrollArea::vertical().show(ui, |ui| {
        for (i, job) in jobs.iter().enumerate().rev() {
            let label = format!(
                "{} {} ({}/{})",
                match job.progress.status {
                    JobStatus::Queued => "[Q]",
                    JobStatus::Running => "[R]",
                    JobStatus::Completed => "[OK]",
                    JobStatus::Failed => "[X]",
                },
                job.name,
                job.progress.hosts_done,
                job.progress.hosts_total.max(job.progress.hosts_done),
            );
            if ui
                .selectable_label(*app.state.selected_host.lock() == Some(i), label)
                .clicked()
            {
                *app.state.selected_host.lock() = Some(i);
            }
        }
    });
}
