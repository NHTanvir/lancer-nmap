//! Local HTTP control plane — auto-allocated port, written to
//! `%TEMP%/lancer-nmap.port`. Enables sibling tools in the Lancer ecosystem
//! to "Send to lancer-nmap" with a single POST.

use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use nmap_core::result::ScanResult;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Clone, Default)]
pub struct ControlState {
    pub latest: Arc<RwLock<Option<ScanResult>>>,
    pub queued: Arc<RwLock<Vec<String>>>,
}

#[derive(Serialize)]
pub struct StateView {
    pub jobs: Vec<String>,
    pub last_scan_total: usize,
    pub last_scan_up: usize,
}

#[derive(Deserialize)]
pub struct ImportPayload {
    pub targets: Vec<String>,
    pub ports: Option<String>,
}

pub async fn start(state: ControlState) -> Result<u16> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route("/v1/state", get(get_state))
        .route("/v1/import", post(post_import))
        .route("/v1/export", get(get_export))
        .with_state(state.clone());
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error=%e, "control plane crashed");
        }
    });
    write_port_file(port);
    info!(%port, "lancer-nmap control plane listening on 127.0.0.1");
    Ok(port)
}

fn write_port_file(port: u16) {
    let dir = std::env::temp_dir();
    let path = dir.join("lancer-nmap.port");
    let _ = std::fs::write(path, port.to_string());
}

async fn get_state(State(state): State<ControlState>) -> Json<StateView> {
    let latest = state.latest.read();
    let total = latest.as_ref().map(|r| r.summary_total).unwrap_or(0);
    let up = latest.as_ref().map(|r| r.summary_up).unwrap_or(0);
    Json(StateView {
        jobs: state.queued.read().clone(),
        last_scan_total: total,
        last_scan_up: up,
    })
}

async fn post_import(
    State(state): State<ControlState>,
    Json(payload): Json<ImportPayload>,
) -> impl IntoResponse {
    let mut q = state.queued.write();
    for t in payload.targets {
        q.push(t);
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

async fn get_export(
    State(state): State<ControlState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let format = params.get("format").cloned().unwrap_or_else(|| "json".into());
    let latest = state.latest.read().clone();
    let r = match latest {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "no scan yet").into_response(),
    };
    let body = match format.as_str() {
        "xml" => nmap_output::emit_xml(&r),
        "grepable" | "gnmap" => nmap_output::emit_grepable(&r),
        "normal" | "nmap" => nmap_output::emit_normal(&r),
        "sarif" => nmap_output::emit_sarif(&r),
        "csv" => nmap_output::emit_csv(&r),
        "markdown" => to_markdown(&r),
        _ => nmap_output::emit_json(&r),
    };
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        body,
    )
        .into_response()
}

fn to_markdown(r: &ScanResult) -> String {
    let mut s = String::new();
    s.push_str("# lancer-nmap results\n\n");
    s.push_str(&format!("- Hosts scanned: **{}**\n", r.summary_total));
    s.push_str(&format!("- Hosts up: **{}**\n\n", r.summary_up));
    for h in &r.hosts {
        s.push_str(&format!("## {}\n\n", h.address));
        s.push_str("| Port | State | Service | Version |\n|---|---|---|---|\n");
        for p in &h.ports {
            let svc = p
                .service
                .as_ref()
                .and_then(|s| s.name.clone())
                .unwrap_or_default();
            let ver = p
                .service
                .as_ref()
                .and_then(|s| s.version.clone())
                .unwrap_or_default();
            s.push_str(&format!(
                "| {}/{} | {} | {} | {} |\n",
                p.port.number,
                p.port.protocol.short(),
                p.state.as_str(),
                svc,
                ver
            ));
        }
        s.push('\n');
    }
    s
}
