use serde::{Deserialize, Serialize};

/// One of the upstream scan techniques. Mirrors `-sS`, `-sT`, etc.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ScanType {
    /// `-sS` — SYN stealth (default for root/admin).
    SynStealth,
    /// `-sT` — TCP connect (default unprivileged).
    TcpConnect,
    /// `-sU` — UDP.
    Udp,
    /// `-sN` — TCP NULL (no flags).
    Null,
    /// `-sF` — TCP FIN.
    Fin,
    /// `-sX` — TCP Xmas (FIN|PSH|URG).
    Xmas,
    /// `-sA` — TCP ACK (firewall mapping).
    Ack,
    /// `-sW` — TCP Window (uses Win-size oddities).
    Window,
    /// `-sM` — TCP Maimon (FIN|ACK).
    Maimon,
    /// `-sI zombie:port` — idle/zombie scan via IPID side-channel.
    IdleZombie,
    /// `-sO` — IP protocol scan.
    IpProtocol,
    /// `-sY` — SCTP INIT.
    SctpInit,
    /// `-sZ` — SCTP COOKIE-ECHO.
    SctpCookieEcho,
    /// `-b ftp.example.com` — FTP bounce.
    FtpBounce,
    /// `--scanflags ...` — custom-flag scan.
    Custom,
    /// `-sn` — host-discovery only (no port scan).
    PingOnly,
}

impl ScanType {
    pub fn short(self) -> &'static str {
        match self {
            Self::SynStealth => "syn",
            Self::TcpConnect => "connect",
            Self::Udp => "udp",
            Self::Null => "null",
            Self::Fin => "fin",
            Self::Xmas => "xmas",
            Self::Ack => "ack",
            Self::Window => "window",
            Self::Maimon => "maimon",
            Self::IdleZombie => "idle",
            Self::IpProtocol => "ip-protocol",
            Self::SctpInit => "sctp-init",
            Self::SctpCookieEcho => "sctp-cookie-echo",
            Self::FtpBounce => "ftp-bounce",
            Self::Custom => "custom",
            Self::PingOnly => "ping",
        }
    }

    pub fn family(self) -> ScanFamily {
        match self {
            Self::SynStealth
            | Self::Null
            | Self::Fin
            | Self::Xmas
            | Self::Ack
            | Self::Window
            | Self::Maimon
            | Self::IdleZombie
            | Self::Custom
            | Self::FtpBounce => ScanFamily::RawTcp,
            Self::TcpConnect => ScanFamily::TcpConnect,
            Self::Udp => ScanFamily::Udp,
            Self::IpProtocol => ScanFamily::IpProto,
            Self::SctpInit | Self::SctpCookieEcho => ScanFamily::Sctp,
            Self::PingOnly => ScanFamily::Discovery,
        }
    }

    pub fn needs_raw(self) -> bool {
        !matches!(self, Self::TcpConnect | Self::PingOnly)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ScanFamily {
    RawTcp,
    TcpConnect,
    Udp,
    IpProto,
    Sctp,
    Discovery,
}
