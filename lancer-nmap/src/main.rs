//! `lancer-nmap` — entry point.
//!
//! Plain invocation opens the eframe / egui GUI window. Passing `--cli`
//! (or running the `lancer-nmap-cli` companion binary) drops into the full
//! CLI surface — every upstream flag mirrored.

use anyhow::Result;
use clap::Parser;

mod cli;
mod control_plane;
mod runner;

#[derive(Parser, Debug)]
#[command(
    name = "lancer-nmap",
    version,
    about = "Rust clone of nmap — part of the Lancer bug bounty toolkit",
    disable_help_flag = true,
    arg_required_else_help = false
)]
struct EntryArgs {
    /// Drop into the CLI instead of opening the GUI.
    #[arg(long = "cli")]
    cli: bool,

    /// Pass-through everything else to the CLI parser.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    rest: Vec<String>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .try_init()
        .ok();

    let entry = EntryArgs::parse();
    if entry.cli || !entry.rest.is_empty() {
        let mut argv = vec!["lancer-nmap".to_string()];
        argv.extend(entry.rest.iter().cloned());
        return cli::run(argv);
    }
    nmap_gui::launch()
}
