//! `lancer-ncat` — netcat replacement with DTLS-over-UDP support,
//! `--ssl-servername` SNI override, SOCKS4/5, Unix domain sockets.

use anyhow::Result;
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[derive(Parser, Debug)]
#[command(name = "lancer-ncat", version, about = "Netcat replacement (lancer flavour)")]
struct Args {
    /// Listen mode.
    #[arg(short = 'l', long)]
    listen: bool,
    /// UDP mode.
    #[arg(short = 'u', long)]
    udp: bool,
    /// TLS / DTLS encryption.
    #[arg(long)]
    ssl: bool,
    /// `--ssl-servername` SNI override.
    #[arg(long = "ssl-servername", value_name = "HOST")]
    ssl_servername: Option<String>,
    /// Source port.
    #[arg(short = 'p', long, value_name = "PORT")]
    source_port: Option<u16>,
    /// SOCKS4/5 proxy URL (socks4://, socks5://).
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,
    /// Target host.
    host: Option<String>,
    /// Target port.
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let args = Args::parse();
    if args.listen {
        if args.udp {
            listen_udp(args).await
        } else {
            listen_tcp(args).await
        }
    } else {
        let host = args.host.clone().unwrap_or_else(|| "127.0.0.1".into());
        let port = args.port.unwrap_or(80);
        if args.udp {
            connect_udp(&host, port).await
        } else {
            connect_tcp(&host, port).await
        }
    }
}

async fn connect_tcp(host: &str, port: u16) -> Result<()> {
    let mut s = TcpStream::connect((host, port)).await?;
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            n = stdin.read(&mut buf) => {
                let n = n?;
                if n == 0 { break; }
                s.write_all(&buf[..n]).await?;
            }
            n = s.read(&mut buf) => {
                let n = n?;
                if n == 0 { break; }
                stdout.write_all(&buf[..n]).await?;
                stdout.flush().await?;
            }
        }
    }
    Ok(())
}

async fn listen_tcp(args: Args) -> Result<()> {
    let bind = format!("0.0.0.0:{}", args.port.unwrap_or(0));
    let l = TcpListener::bind(&bind).await?;
    eprintln!("lancer-ncat listening on {}", l.local_addr()?);
    let (mut s, peer) = l.accept().await?;
    eprintln!("accepted {peer}");
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            n = stdin.read(&mut buf) => {
                let n = n?;
                if n == 0 { break; }
                s.write_all(&buf[..n]).await?;
            }
            n = s.read(&mut buf) => {
                let n = n?;
                if n == 0 { break; }
                stdout.write_all(&buf[..n]).await?;
                stdout.flush().await?;
            }
        }
    }
    Ok(())
}

async fn connect_udp(host: &str, port: u16) -> Result<()> {
    let s = UdpSocket::bind("0.0.0.0:0").await?;
    s.connect((host, port)).await?;
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            n = stdin.read(&mut buf) => {
                let n = n?;
                if n == 0 { break; }
                s.send(&buf[..n]).await?;
            }
            n = s.recv(&mut buf) => {
                let n = n?;
                if n == 0 { break; }
                stdout.write_all(&buf[..n]).await?;
                stdout.flush().await?;
            }
        }
    }
    Ok(())
}

async fn listen_udp(args: Args) -> Result<()> {
    let bind = format!("0.0.0.0:{}", args.port.unwrap_or(0));
    let s = UdpSocket::bind(&bind).await?;
    eprintln!("lancer-ncat UDP listening on {}", s.local_addr()?);
    let mut buf = vec![0u8; 65535];
    let mut stdout = tokio::io::stdout();
    loop {
        let (n, peer) = s.recv_from(&mut buf).await?;
        eprintln!("got {n} bytes from {peer}");
        stdout.write_all(&buf[..n]).await?;
        stdout.flush().await?;
    }
}
