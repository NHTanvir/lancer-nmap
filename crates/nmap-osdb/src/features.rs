//! Observation-side feature vector: the data extracted from the 16 OS
//! probes (`SEQ`/`OPS`/`WIN`/`ECN`/`T1`..`T7`/`U1`/`IE`).
//!
//! Each test produces a `(test_name, key)` -> value mapping that is
//! compared field-by-field against fingerprints in `scoring`.

use indexmap::IndexMap;

#[derive(Clone, Debug, Default)]
pub struct FeatureVector {
    /// Map of TEST -> KEY -> observed value (string form, matching the
    /// `nmap-os-db` DSL).
    pub tests: IndexMap<String, IndexMap<String, String>>,
}

impl FeatureVector {
    pub fn set(&mut self, test: &str, key: &str, value: impl Into<String>) {
        self.tests
            .entry(test.to_string())
            .or_default()
            .insert(key.to_string(), value.into());
    }

    pub fn get(&self, test: &str, key: &str) -> Option<&str> {
        self.tests.get(test).and_then(|m| m.get(key).map(|s| s.as_str()))
    }
}
