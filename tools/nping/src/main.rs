//! `lancer-nping` — packet crafter, version-locked to `lancer-nmap`.

use anyhow::Result;
use clap::Parser;
use std::net::ToSocketAddrs;
use tokio::time::{sleep, Duration};

#[derive(Parser, Debug)]
#[command(name = "lancer-nping", version, about = "Packet crafter — lancer flavour of nping")]
struct Args {
    /// Number of probes to send.
    #[arg(short = 'c', long, default_value_t = 5)]
    count: u32,
    /// Send mode (icmp / tcp / udp / arp).
    #[arg(long, default_value = "tcp")]
    mode: String,
    /// Target port (tcp / udp modes).
    #[arg(short = 'p', long)]
    port: Option<u16>,
    /// Inter-probe delay (e.g. `500ms`, `1s`).
    #[arg(long, default_value = "1s")]
    delay: String,
    /// Target host.
    host: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let args = Args::parse();
    let port = args.port.unwrap_or(80);
    let delay = parse_dur(&args.delay)?;
    let addr = format!("{}:{port}", args.host)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("address resolution failed"))?;
    println!("lancer-nping mode={} {} ({}) port={port}", args.mode, args.host, addr.ip());
    for i in 1..=args.count {
        let t0 = std::time::Instant::now();
        match args.mode.as_str() {
            "icmp" => {
                println!("seq={i} icmp: stub (needs raw socket)");
            }
            "tcp" => match tokio::net::TcpStream::connect(addr).await {
                Ok(_) => println!("seq={i} tcp: open ({} ms)", t0.elapsed().as_millis()),
                Err(e) => println!("seq={i} tcp: {e}"),
            },
            "udp" => {
                let s = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                s.send_to(b"\x00", addr).await?;
                println!("seq={i} udp: sent ({} ms)", t0.elapsed().as_millis());
            }
            "arp" => println!("seq={i} arp: stub (needs raw socket)"),
            _ => println!("seq={i} unknown mode {}", args.mode),
        }
        if i < args.count {
            sleep(delay).await;
        }
    }
    Ok(())
}

fn parse_dur(s: &str) -> Result<Duration> {
    let (num, mul) = if let Some(p) = s.strip_suffix("ms") {
        (p, 1)
    } else if let Some(p) = s.strip_suffix('s') {
        (p, 1000)
    } else if let Some(p) = s.strip_suffix('m') {
        (p, 60 * 1000)
    } else {
        (s, 1)
    };
    let n: u64 = num.parse()?;
    Ok(Duration::from_millis(n * mul))
}
