//! Weighted-Hamming scorer for the OS DB.
//!
//! Each fingerprint scores against the observed feature vector by walking
//! the `MatchPoints` weight table: for every `(test, key, value)` pair the
//! fingerprint defines, award weight points if it matches the observation;
//! the accuracy is `score / max_possible * 100`.
//!
//! The `value` cell can be:
//!   - a literal: `SP=23` matches exactly `23`
//!   - a list: `SP=23|24|25` matches any of those
//!   - a range: `SP=10-30` matches any value in that range (hex or decimal)
//!   - empty (`OK=`) matches the observation being absent

use crate::parser::OsDb;
use crate::features::FeatureVector;
use nmap_core::result::{OsClass as CoreClass, OsMatch};

#[derive(Clone, Debug)]
pub struct ScoredMatch {
    pub name: String,
    pub line: u32,
    pub accuracy: u8,
    pub classes: Vec<CoreClass>,
}

pub fn score(db: &OsDb, fv: &FeatureVector, top_n: usize) -> Vec<OsMatch> {
    let mut out: Vec<ScoredMatch> = Vec::new();
    for fp in &db.fingerprints {
        let (got, max) = score_one(db, fp, fv);
        let acc = if max == 0 {
            0u8
        } else {
            ((got as f64 / max as f64) * 100.0).round().clamp(0.0, 100.0) as u8
        };
        if acc == 0 {
            continue;
        }
        let classes: Vec<CoreClass> = fp
            .classes
            .iter()
            .map(|c| CoreClass {
                vendor: c.vendor.clone(),
                osfamily: c.osfamily.clone(),
                osgen: c.osgen.clone(),
                kind: c.kind.clone(),
                accuracy: acc,
                cpe: c.cpe.clone(),
            })
            .collect();
        out.push(ScoredMatch {
            name: fp.name.clone(),
            line: fp.line,
            accuracy: acc,
            classes,
        });
    }
    out.sort_by(|a, b| b.accuracy.cmp(&a.accuracy));
    out.truncate(top_n);
    out.into_iter()
        .map(|m| OsMatch {
            name: m.name,
            accuracy: m.accuracy,
            line: m.line,
            cpe: m
                .classes
                .iter()
                .flat_map(|c| c.cpe.clone())
                .collect(),
            os_class: m.classes,
        })
        .collect()
}

fn score_one(db: &OsDb, fp: &crate::parser::Fingerprint, fv: &FeatureVector) -> (u32, u32) {
    let mut got: u32 = 0;
    let mut max: u32 = 0;
    for (test, body) in &fp.tests {
        for (key, expected) in body {
            let weight_key = format!("{test}.{key}");
            let weight = *db.match_points.get(&weight_key).unwrap_or(&1);
            max = max.saturating_add(weight);
            let observed = fv.get(test, key);
            if value_matches(expected, observed) {
                got = got.saturating_add(weight);
            }
        }
    }
    (got, max)
}

fn value_matches(expected: &str, observed: Option<&str>) -> bool {
    if expected.is_empty() {
        return observed.map_or(true, |s| s.is_empty());
    }
    let observed = match observed {
        Some(s) => s,
        None => return false,
    };
    for alt in expected.split('|') {
        if alt == observed {
            return true;
        }
        if let Some((lo, hi)) = alt.split_once('-') {
            if let (Some(o), Some(l), Some(h)) =
                (parse_int(observed), parse_int(lo), parse_int(hi))
            {
                if o >= l && o <= h {
                    return true;
                }
            }
        }
    }
    false
}

fn parse_int(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x") {
        return i64::from_str_radix(rest, 16).ok();
    }
    if let Ok(v) = i64::from_str_radix(s, 16) {
        return Some(v);
    }
    s.parse::<i64>().ok()
}
