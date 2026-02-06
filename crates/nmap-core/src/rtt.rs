//! Per-host SRTT/RTTVAR tracking, RFC-6298-style.
//!
//! Used by the raw-socket scanners (SYN / UDP / NULL / FIN / Xmas / ACK /
//! Window / Maimon / SCTP) and by OS detection.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct RttSample {
    pub srtt: Duration,
    pub rttvar: Duration,
    pub rto: Duration,
    pub samples: u32,
}

impl RttSample {
    pub fn new(initial: Duration) -> Self {
        Self {
            srtt: initial,
            rttvar: initial / 2,
            rto: initial,
            samples: 0,
        }
    }

    /// RFC 6298, with Karn's adjustment: skip retransmitted samples
    /// (caller's responsibility).
    pub fn observe(&mut self, sample: Duration, min: Duration, max: Duration) {
        if self.samples == 0 {
            self.srtt = sample;
            self.rttvar = sample / 2;
        } else {
            let diff = if sample > self.srtt {
                sample - self.srtt
            } else {
                self.srtt - sample
            };
            self.rttvar = (3 * self.rttvar + diff) / 4;
            self.srtt = (7 * self.srtt + sample) / 8;
        }
        self.samples = self.samples.saturating_add(1);
        let rto = self.srtt + 4 * self.rttvar;
        self.rto = rto.clamp(min, max);
    }
}

#[derive(Default, Clone)]
pub struct RttBook {
    inner: Arc<Mutex<HashMap<IpAddr, RttSample>>>,
    subnet_default: Arc<Mutex<HashMap<IpAddr, RttSample>>>,
}

impl RttBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_init(
        &self,
        host: IpAddr,
        initial: Duration,
        min: Duration,
        max: Duration,
    ) -> RttSample {
        let mut book = self.inner.lock();
        let entry = book
            .entry(host)
            .or_insert_with(|| RttSample::new(initial.clamp(min, max)));
        *entry
    }

    pub fn record(
        &self,
        host: IpAddr,
        sample: Duration,
        min: Duration,
        max: Duration,
    ) -> RttSample {
        let mut book = self.inner.lock();
        let entry = book.entry(host).or_insert_with(|| RttSample::new(sample));
        entry.observe(sample, min, max);
        let copy = *entry;
        self.merge_subnet(host, &copy);
        copy
    }

    fn merge_subnet(&self, host: IpAddr, s: &RttSample) {
        let bucket = subnet_bucket(host);
        let mut map = self.subnet_default.lock();
        let entry = map.entry(bucket).or_insert(*s);
        entry.srtt = (entry.srtt + s.srtt) / 2;
        entry.rttvar = (entry.rttvar + s.rttvar) / 2;
        entry.rto = (entry.rto + s.rto) / 2;
    }

    pub fn subnet_hint(&self, host: IpAddr) -> Option<RttSample> {
        self.subnet_default.lock().get(&subnet_bucket(host)).cloned()
    }
}

fn subnet_bucket(host: IpAddr) -> IpAddr {
    match host {
        IpAddr::V4(v) => {
            let mut o = v.octets();
            o[3] = 0;
            IpAddr::V4(std::net::Ipv4Addr::from(o))
        }
        IpAddr::V6(v) => {
            let mut o = v.octets();
            for i in 8..16 {
                o[i] = 0;
            }
            IpAddr::V6(std::net::Ipv6Addr::from(o))
        }
    }
}
