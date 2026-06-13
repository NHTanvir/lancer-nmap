//! The eframe `App` — three-pane layout, top menu, bottom status bar.

use crate::panels::{center, detail, sidebar, top_menu};
use crate::state::{GuiState, Job, JobStatus};
use eframe::egui;

pub struct App {
    pub state: GuiState,
    pub toasts: egui_notify::Toasts,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let state: GuiState = cc
            .storage
            .and_then(|s| eframe::get_value::<crate::theme::Theme>(s, "theme"))
            .map(|t| {
                let st = GuiState::default();
                *st.theme.lock() = t;
                st
            })
            .unwrap_or_default();
        let visuals = state.theme.lock().visuals();
        cc.egui_ctx.set_visuals(visuals);
        Self {
            state,
            toasts: egui_notify::Toasts::default(),
        }
    }

    pub fn run_form(&mut self, ctx: &egui::Context) {
        let form = self.state.form.lock().clone();
        let mut opts = nmap_core::options::ScanOptions::default();
        for tok in form.targets.split_whitespace() {
            if let Ok(s) = nmap_core::target::parse_target(tok) {
                opts.targets.add_spec(s);
            }
        }
        if !form.ports.trim().is_empty() {
            if let Ok(s) =
                nmap_core::port::parse_port_spec(&form.ports, nmap_core::port::Protocol::Tcp)
            {
                opts.port_scan.ports = s;
            }
        }
        if form.fast {
            opts.port_scan.fast = true;
        }
        if form.udp {
            opts.port_scan.scan_types.push(nmap_core::scan::ScanType::Udp);
        }
        opts.port_scan
            .scan_types
            .push(nmap_core::scan::ScanType::TcpConnect);
        opts.service_scan.enabled = form.service_scan || form.aggressive;
        opts.os_scan.enabled = form.os_scan || form.aggressive;
        opts.discovery.traceroute = form.traceroute || form.aggressive;
        opts.nse.default_scripts = form.default_scripts || form.aggressive;
        if !form.script_spec.trim().is_empty() {
            opts.nse.script_spec.push(form.script_spec.clone());
        }
        opts.timing.template =
            nmap_core::options::TimingTemplate::from_n(form.timing);
        opts.timing.min_rate = form.min_rate;
        opts.timing.max_rate = form.max_rate;
        opts.vpn_passthrough = form.vpn_passthrough;
        let job = Job {
            id: uuid::Uuid::new_v4(),
            name: form
                .targets
                .split_whitespace()
                .next()
                .unwrap_or("scan")
                .to_string(),
            created: chrono::Utc::now(),
            started: None,
            progress: Default::default(),
            options: opts.clone(),
            result: None,
        };
        self.state.jobs.lock().push(job.clone());
        spawn_job(self.state.clone(), job.id, opts, ctx.clone());
        self.toasts.success("Scan queued");
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        top_menu::ui(ctx, self);
        egui::SidePanel::left("sidebar")
            .resizable(true)
            .default_width(280.0)
            .min_width(180.0)
            .show(ctx, |ui| {
                sidebar::ui(ui, self);
            });
        egui::SidePanel::right("detail")
            .resizable(true)
            .default_width(340.0)
            .min_width(220.0)
            .show(ctx, |ui| {
                detail::ui(ui, self);
            });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            self.status_bar(ui);
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            center::ui(ui, self);
        });
        self.toasts.show(ctx);
        ctx.request_repaint_after(std::time::Duration::from_millis(250));
        let _ = frame;
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "theme", &*self.state.theme.lock());
    }
}

impl App {
    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let jobs = self.state.jobs.lock();
            let running = jobs.iter().filter(|j| j.progress.status == JobStatus::Running).count();
            let done = jobs.iter().filter(|j| j.progress.status == JobStatus::Completed).count();
            ui.label(format!("Jobs: {} running, {} done", running, done));
            ui.separator();
            if let Some(idx) = *self.state.selected_host.lock() {
                if let Some(job) = jobs
                    .iter()
                    .rev()
                    .find(|j| j.result.is_some())
                {
                    if let Some(host) = job.result.as_ref().and_then(|r| r.hosts.get(idx)) {
                        ui.label(format!("Selected: {}", host.address));
                    }
                }
            }
            drop(jobs); // release the lock before &mut self calls below
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Run").clicked() {
                    self.run_form(ui.ctx());
                }
                if ui.button("Open…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.toasts.info(format!("Loaded {}", path.display()));
                    }
                }
                if ui.button("Export…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().save_file() {
                        let jobs = self.state.jobs.lock();
                        if let Some(r) = jobs.iter().rev().find_map(|j| j.result.as_ref()) {
                            let _ = std::fs::write(&path, nmap_output::emit_json(r));
                            self.toasts.success(format!("Exported to {}", path.display()));
                        }
                    }
                }
            });
        });
    }
}

fn spawn_job(
    state: GuiState,
    job_id: uuid::Uuid,
    opts: nmap_core::options::ScanOptions,
    ctx: egui::Context,
) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => return,
        };
        rt.block_on(async move {
            let scanner = nmap_core::scanner::Scanner::new(opts);
            let mut rx = match scanner.scan_stream().await {
                Ok(rx) => rx,
                Err(_) => return,
            };
            mark_running(&state, job_id);
            ctx.request_repaint();
            let mut hosts = Vec::new();
            while let Some(h) = rx.recv().await {
                update_progress(&state, job_id, &h);
                hosts.push(h);
                ctx.request_repaint();
            }
            finalize(&state, job_id, hosts);
            ctx.request_repaint();
        });
    });
}

fn mark_running(state: &GuiState, job_id: uuid::Uuid) {
    let mut jobs = state.jobs.lock();
    if let Some(j) = jobs.iter_mut().find(|j| j.id == job_id) {
        j.progress.status = JobStatus::Running;
        j.started = Some(std::time::Instant::now());
    }
}

fn update_progress(state: &GuiState, job_id: uuid::Uuid, host: &nmap_core::result::HostResult) {
    let mut jobs = state.jobs.lock();
    if let Some(j) = jobs.iter_mut().find(|j| j.id == job_id) {
        j.progress.hosts_done += 1;
        j.progress.last_host = Some(host.clone());
    }
}

fn finalize(state: &GuiState, job_id: uuid::Uuid, hosts: Vec<nmap_core::result::HostResult>) {
    let mut jobs = state.jobs.lock();
    if let Some(j) = jobs.iter_mut().find(|j| j.id == job_id) {
        j.progress.status = JobStatus::Completed;
        let mut r = nmap_core::result::ScanResult::default();
        r.hosts = hosts;
        r.summary_total = r.hosts.len();
        r.summary_up = r
            .hosts
            .iter()
            .filter(|h| matches!(h.state, nmap_core::result::HostState::Up))
            .count();
        r.summary_down = r.summary_total - r.summary_up;
        j.result = Some(r);
    }
}
