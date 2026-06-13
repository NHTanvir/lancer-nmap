//! `lancer-nmap-cli` — same binary surface as `lancer-nmap --cli`.

use anyhow::Result;

#[path = "../cli.rs"]
mod cli;

#[path = "../runner.rs"]
mod runner;

#[path = "../control_plane.rs"]
mod control_plane;

fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let argv: Vec<String> = std::env::args().collect();
    cli::run(argv)
}
