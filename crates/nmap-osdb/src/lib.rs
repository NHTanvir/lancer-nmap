//! `nmap-osdb` — parses the upstream `nmap-os-db` format and scores
//! observed-feature vectors against fingerprints using `MatchPoints`
//! weights.

pub mod parser;
pub mod scoring;
pub mod features;

pub use parser::{parse_db, Fingerprint, OsClass, OsDb};
pub use features::FeatureVector;
pub use scoring::{score, ScoredMatch};
