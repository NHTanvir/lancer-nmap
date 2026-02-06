//! lancer-nmap
//! Rust clone of nmap. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-nmap", version, about = "Rust clone of nmap")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-nmap - scaffold ready. Implement per plan.md.");
    Ok(())
}
