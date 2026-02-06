use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use nonzero_ext::nonzero;
use std::sync::Arc;
use std::time::Duration;

/// Wraps `governor` to give us a global packet-rate cap (`--max-rate`) plus
/// an opt-in `--min-rate` (we never sleep below it, but we don't speed up).
#[derive(Clone)]
pub struct RateGate {
    limiter: Option<Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>>,
}

impl RateGate {
    pub fn unlimited() -> Self {
        Self { limiter: None }
    }

    pub fn pps(max: u64) -> Self {
        let q = if max == 0 {
            Quota::per_second(nonzero!(1u32))
        } else {
            let cap = max.min(u32::MAX as u64) as u32;
            Quota::per_second(std::num::NonZeroU32::new(cap).unwrap())
        };
        Self {
            limiter: Some(Arc::new(RateLimiter::direct(q))),
        }
    }

    pub async fn wait(&self) {
        if let Some(l) = &self.limiter {
            l.until_ready().await;
        }
    }

    pub fn try_check(&self) -> bool {
        self.limiter
            .as_ref()
            .map(|l| l.check().is_ok())
            .unwrap_or(true)
    }
}

/// Adapter helper: convert `--scan-delay` to a sleep + the rate gate. Both
/// arise from the timing profile.
pub async fn pace(delay: Duration, gate: &RateGate) {
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    gate.wait().await;
}
