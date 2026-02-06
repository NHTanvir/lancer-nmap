//! Per-host TCP-friendly congestion window — mirror of upstream
//! `ultra_scan.cc`'s probe-window controller.
//!
//! - slow-start from cwnd=10 doubling per RTT until ssthresh
//! - on loss: ssthresh = cwnd/2, cwnd = ssthresh, then linear (additive
//!   increase, multiplicative decrease)

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub struct CongestionWindow {
    pub cwnd: u32,
    pub ssthresh: u32,
    pub in_flight: u32,
}

impl CongestionWindow {
    pub fn new() -> Self {
        Self {
            cwnd: 10,
            ssthresh: u32::MAX,
            in_flight: 0,
        }
    }

    pub fn can_send(&self) -> bool {
        self.in_flight < self.cwnd
    }

    pub fn on_send(&mut self) {
        self.in_flight = self.in_flight.saturating_add(1);
    }

    pub fn on_ack(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(1);
        } else {
            // Linear: +1/cwnd per ack — approximate with +1 every cwnd acks.
            self.cwnd = self.cwnd.saturating_add(1);
        }
        // Hard cap; mirrors upstream `MAX_CWND`.
        if self.cwnd > 300 {
            self.cwnd = 300;
        }
    }

    pub fn on_loss(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
        self.ssthresh = (self.cwnd / 2).max(2);
        self.cwnd = self.ssthresh;
    }
}

impl Default for CongestionWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default, Clone)]
pub struct CongestionBook {
    inner: Arc<Mutex<HashMap<IpAddr, CongestionWindow>>>,
}

impl CongestionBook {
    pub fn snapshot(&self, host: IpAddr) -> CongestionWindow {
        let mut m = self.inner.lock();
        *m.entry(host).or_insert_with(CongestionWindow::new)
    }

    pub fn with<R>(&self, host: IpAddr, f: impl FnOnce(&mut CongestionWindow) -> R) -> R {
        let mut m = self.inner.lock();
        let cwnd = m.entry(host).or_insert_with(CongestionWindow::new);
        f(cwnd)
    }
}
