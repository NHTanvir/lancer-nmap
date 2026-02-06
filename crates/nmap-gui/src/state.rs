//! GUI-side state shared between worker thread and UI thread.

use nmap_core::options::ScanOptions;
use nmap_core::result::{HostResult, ScanResult};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone, Default)]
pub struct GuiState {
    pub form: Arc<Mutex<FormState>>,
    pub jobs: Arc<Mutex<Vec<Job>>>,
    pub selected_host: Arc<Mutex<Option<usize>>>,
    pub theme: Arc<Mutex<crate::theme::Theme>>,
}

#[derive(Clone, Debug, Default)]
pub struct FormState {
    pub targets: String,
    pub ports: String,
    pub fast: bool,
    pub aggressive: bool,
    pub service_scan: bool,
    pub os_scan: bool,
    pub traceroute: bool,
    pub udp: bool,
    pub default_scripts: bool,
    pub script_spec: String,
    pub timing: u8,
    pub max_rate: Option<u64>,
    pub min_rate: Option<u64>,
    pub vpn_passthrough: bool,
}

#[derive(Clone)]
pub struct Job {
    pub id: uuid::Uuid,
    pub name: String,
    pub created: chrono::DateTime<chrono::Utc>,
    pub started: Option<Instant>,
    pub progress: JobProgress,
    pub options: ScanOptions,
    pub result: Option<ScanResult>,
}

#[derive(Clone, Default)]
pub struct JobProgress {
    pub status: JobStatus,
    pub hosts_done: usize,
    pub hosts_total: usize,
    pub last_host: Option<HostResult>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum JobStatus {
    #[default]
    Queued,
    Running,
    Completed,
    Failed,
}
