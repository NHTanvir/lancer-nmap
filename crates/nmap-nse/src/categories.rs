//! NSE category set, including the de-facto ICS + IoT categories surfaced
//! upstream but not yet tagged formally (7.99 era).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Category {
    Auth,
    Broadcast,
    Brute,
    Default,
    Discovery,
    Dos,
    Exploit,
    External,
    Fuzzer,
    Intrusive,
    Malware,
    Safe,
    Version,
    Vuln,
    Ics,
    Iot,
}

impl Category {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "auth" => Self::Auth,
            "broadcast" => Self::Broadcast,
            "brute" => Self::Brute,
            "default" => Self::Default,
            "discovery" => Self::Discovery,
            "dos" => Self::Dos,
            "exploit" => Self::Exploit,
            "external" => Self::External,
            "fuzzer" => Self::Fuzzer,
            "intrusive" => Self::Intrusive,
            "malware" => Self::Malware,
            "safe" => Self::Safe,
            "version" => Self::Version,
            "vuln" => Self::Vuln,
            "ics" => Self::Ics,
            "iot" => Self::Iot,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Broadcast => "broadcast",
            Self::Brute => "brute",
            Self::Default => "default",
            Self::Discovery => "discovery",
            Self::Dos => "dos",
            Self::Exploit => "exploit",
            Self::External => "external",
            Self::Fuzzer => "fuzzer",
            Self::Intrusive => "intrusive",
            Self::Malware => "malware",
            Self::Safe => "safe",
            Self::Version => "version",
            Self::Vuln => "vuln",
            Self::Ics => "ics",
            Self::Iot => "iot",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CategoryFilter {
    pub include: HashSet<Category>,
    pub exclude: HashSet<Category>,
    pub include_names: HashSet<String>,
    pub exclude_names: HashSet<String>,
}

impl CategoryFilter {
    /// Parse the upstream `--script category1,category2,!exclude,filename.nse`
    /// expression.
    pub fn parse(spec: &str) -> Self {
        let mut filter = Self::default();
        for tok in spec.split(',') {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            let (negate, body) = if let Some(rest) = tok.strip_prefix('!') {
                (true, rest)
            } else {
                (false, tok)
            };
            if let Some(c) = Category::parse(body) {
                if negate {
                    filter.exclude.insert(c);
                } else {
                    filter.include.insert(c);
                }
            } else if negate {
                filter.exclude_names.insert(body.to_string());
            } else {
                filter.include_names.insert(body.to_string());
            }
        }
        filter
    }

    pub fn allows(&self, name: &str, cats: &[Category]) -> bool {
        if self.exclude_names.contains(name) {
            return false;
        }
        if cats.iter().any(|c| self.exclude.contains(c)) {
            return false;
        }
        if self.include_names.contains(name) {
            return true;
        }
        if self.include.is_empty() && self.include_names.is_empty() {
            return cats.contains(&Category::Default);
        }
        cats.iter().any(|c| self.include.contains(c))
    }
}
