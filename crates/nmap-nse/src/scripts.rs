//! On-disk + embedded script representation.

use crate::categories::Category;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Script {
    pub name: String,
    pub path: Option<PathBuf>,
    /// Inline source, used by built-in scripts that ship with the binary.
    pub source: Option<String>,
    pub description: String,
    pub categories: Vec<Category>,
    pub author: String,
    pub license: String,
    pub dependencies: Vec<String>,
}

impl Script {
    pub fn builtin(name: &str, source: &'static str, categories: &[Category]) -> Self {
        Self {
            name: name.to_string(),
            path: None,
            source: Some(source.to_string()),
            description: String::new(),
            categories: categories.to_vec(),
            author: "Lancer".into(),
            license: "Same as Nmap".into(),
            dependencies: Vec::new(),
        }
    }
}
