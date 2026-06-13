//! The eframe `App` — three-pane layout, top menu, bottom status bar.

use crate::panels::{center, detail, sidebar, top_menu};
use crate::state::{GuiState, Job, JobStatus};
use eframe::egui;

pub struct App {
    pub state: GuiState,
    pub toasts: egui_notify::Toasts,
    /// Set when launched with `LANCER_GUI_AUTORUN`; triggers a scan on the
    /// first rendered frame so the GUI can be driven headlessly.
    auto_run: bool,
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
        state.theme.lock().apply(&cc.egui_ctx);

        // Optional pre-load from the environment: lets a launcher (or a test)
        // open the GUI with a target already entered, and auto-start the scan.
        let mut auto_run = false;
        if let Ok(t) = std::env::var("LANCER_GUI_TARGET") {
            if !t.trim().is_empty() {
                let mut form = state.form.lock();
                form.targets = t;
                if let Ok(p) = std::env::var("LANCER_GUI_PORTS") {
                    form.ports = p;
                }
                form.service_scan = std::env::var("LANCER_GUI_SV").is_ok();
                form.os_scan = std::env::var("LANCER_GUI_O").is_ok();
                form.default_scripts = std::env::var("LANCER_GUI_SC").is_ok();
                drop(form);
                auto_run = std::env::var("LANCER_GUI_AUTORUN")
                    .map(|v| v != "0")
                    .unwrap_or(false);
            }
        }

        Self {
            state,
            toasts: egui_notify::Toasts::default(),
            auto_run,
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
        // Keep our custom palette even though eframe may follow the OS theme
        // and reset visuals each frame.
        ctx.set_visuals(self.state.theme.lock().visuals());
        if self.auto_run {
            self.auto_run = false;
            self.run_form(ctx);
        }
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
    // Generous stacks: parsing the ~8 MB embedded probe/OS databases during
    // enrichment overflows the small default thread stacks.
    let _ = std::thread::Builder::new()
        .name("lancer-scan".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(64 * 1024 * 1024)
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async move {
                let scanner = nmap_core::scanner::Scanner::new(opts.clone());
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
                    // Show each host as soon as its port scan finishes.
                    set_partial(&state, job_id, hosts.clone());
                    ctx.request_repaint();
                }
                // Enrich with -sV / -O / NSE so the GUI shows the same depth as
                // the CLI (service versions, OS guesses, script output).
                let mut result = nmap_core::result::ScanResult::default();
                result.hosts = hosts;
                nmap_engine::enrich(&mut result, &opts).await;
                finalize(&state, job_id, result.hosts);
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

/// Publish in-progress results (after the port scan, before enrichment) so the
/// table fills in immediately instead of waiting for the full `-sV`/`-O`/NSE pass.
fn set_partial(state: &GuiState, job_id: uuid::Uuid, hosts: Vec<nmap_core::result::HostResult>) {
    use nmap_core::result::{HostState, ScanResult};
    let mut jobs = state.jobs.lock();
    if let Some(j) = jobs.iter_mut().find(|j| j.id == job_id) {
        let mut r = ScanResult::default();
        r.summary_total = hosts.len();
        r.summary_up = hosts
            .iter()
            .filter(|h| matches!(h.state, HostState::Up))
            .count();
        r.summary_down = r.summary_total - r.summary_up;
        r.hosts = hosts;
        j.result = Some(r); // status stays Running
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
