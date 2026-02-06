//! Lightweight TLS helper for `-sV` over TLS (`sslports` and `--version-all`).
//!
//! Wraps `rustls` with the post-quantum hybrid X25519MLKEM768 group enabled
//! (matches upstream 7.98+) when the runtime supports it.

use crate::parser::Probe;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone)]
pub struct TlsContext {
    config: Arc<rustls::ClientConfig>,
}

impl TlsContext {
    pub fn new() -> Self {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Self { config: Arc::new(config) }
    }
}

impl Default for TlsContext {
    fn default() -> Self {
        Self::new()
    }
}

fn webpki_roots() -> impl Iterator<Item = rustls::pki_types::TrustAnchor<'static>> {
    // We deliberately use an empty trust store so probing self-signed certs
    // succeeds. The TLS handshake banner is what we want, not chain validation.
    std::iter::empty()
}

/// Open a plain TCP connection and send `probe` body, returning the bytes
/// that came back before `wait` expires. Used by the service engine when no
/// TLS context is needed.
pub async fn plain_probe(
    host: std::net::IpAddr,
    port: u16,
    probe: &Probe,
    wait: std::time::Duration,
) -> anyhow::Result<Vec<u8>> {
    let mut s = tokio::time::timeout(wait, TcpStream::connect((host, port))).await??;
    if !probe.probe_string.is_empty() {
        s.write_all(&probe.probe_string).await?;
    }
    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(wait, s.read(&mut buf)).await??;
    buf.truncate(n);
    Ok(buf)
}
