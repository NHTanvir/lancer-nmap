use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid target spec: {0}")]
    InvalidTarget(String),

    #[error("invalid port spec: {0}")]
    InvalidPort(String),

    #[error("name resolution failed: {0}")]
    Resolution(String),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("permission denied — raw sockets require CAP_NET_RAW (linux), admin (windows), or BPF perms (mac)")]
    PermissionDenied,

    #[error("scan aborted")]
    Aborted,

    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),

    #[error("pcap error: {0}")]
    Pcap(String),

    #[error("nse error: {0}")]
    Nse(String),

    #[error("parser error: {0}")]
    Parse(String),

    #[error("unsupported feature: {0}")]
    Unsupported(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("other: {0}")]
    Other(String),
}

impl Error {
    pub fn parse(msg: impl Into<String>) -> Self {
        Self::Parse(msg.into())
    }

    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e.to_string())
    }
}
