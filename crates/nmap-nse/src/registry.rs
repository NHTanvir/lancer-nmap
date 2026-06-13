//! Script registry — discovery + lookup.
//!
//! The complete upstream NSE corpus (612 `.nse` scripts + 133 `nselib` Lua
//! modules, v7.99) is embedded at build time via `include_dir!`, so every
//! script is registered, category-filterable, and available to `--script` /
//! `--script-help` even on a fresh install with no `--datadir`.

use crate::categories::{Category, CategoryFilter};
use crate::scripts::Script;
use include_dir::{include_dir, Dir};
use indexmap::IndexMap;
use std::path::Path;
use tracing::trace;

/// The complete upstream NSE script corpus (`.nse` files), embedded verbatim.
static EMBEDDED_SCRIPTS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/nse/scripts");

/// The complete upstream `nselib` (Lua helper modules), embedded verbatim and
/// resolved by the engine's `require` searcher.
pub static EMBEDDED_NSELIB: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/nse/nselib");

/// Look up an embedded `nselib` module source by `require` name (e.g.
/// `"stdnse"` → `nselib/stdnse.lua`). Used by the engine's Lua searcher.
pub fn nselib_source(module: &str) -> Option<&'static str> {
    let path = format!("{module}.lua");
    EMBEDDED_NSELIB
        .get_file(&path)
        .and_then(|f| f.contents_utf8())
}

#[derive(Default)]
pub struct ScriptRegistry {
    pub scripts: IndexMap<String, Script>,
}

impl ScriptRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate the registry with the full embedded upstream NSE corpus (all
    /// 612 scripts). Each script's categories/author/license are parsed from
    /// its real header.
    pub fn load_builtin(&mut self) {
        for file in EMBEDDED_SCRIPTS.files() {
            let fname = match file.path().file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if !fname.ends_with(".nse") {
                continue;
            }
            let body = match file.contents_utf8() {
                Some(b) => b,
                None => continue,
            };
            let name = fname.trim_end_matches(".nse").to_string();
            let parsed = parse_header(body);
            let s = Script {
                name: name.clone(),
                path: None,
                source: Some(body.to_string()),
                description: parsed.description,
                categories: parsed.categories,
                author: parsed.author,
                license: parsed.license,
                dependencies: parsed.dependencies,
            };
            self.scripts.insert(name, s);
        }
        trace!("NSE registry loaded {} embedded scripts", self.scripts.len());
    }

    /// Discover scripts in an on-disk directory (e.g. a user `--datadir`'s
    /// `scripts/`), overriding any embedded script of the same name.
    pub fn discover_in(&mut self, dir: &Path) {
        for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
            if entry.file_type().is_file() {
                if let Some(name) = entry.path().file_name().and_then(|n| n.to_str()) {
                    if name.ends_with(".nse") {
                        let path = entry.path().to_path_buf();
                        let body = std::fs::read_to_string(&path).unwrap_or_default();
                        let parsed = parse_header(&body);
                        let s = Script {
                            name: name.trim_end_matches(".nse").to_string(),
                            path: Some(path),
                            source: Some(body),
                            description: parsed.description,
                            categories: parsed.categories,
                            author: parsed.author,
                            license: parsed.license,
                            dependencies: parsed.dependencies,
                        };
                        self.scripts.insert(s.name.clone(), s);
                    }
                }
            }
        }
        trace!("NSE registry now holds {} scripts", self.scripts.len());
    }

    pub fn filter(&self, f: &CategoryFilter) -> Vec<Script> {
        self.scripts
            .values()
            .filter(|s| f.allows(&s.name, &s.categories))
            .cloned()
            .collect()
    }
}

struct ParsedHeader {
    description: String,
    categories: Vec<Category>,
    author: String,
    license: String,
    dependencies: Vec<String>,
}

fn parse_header(body: &str) -> ParsedHeader {
    let mut out = ParsedHeader {
        description: String::new(),
        categories: Vec::new(),
        author: String::new(),
        license: String::new(),
        dependencies: Vec::new(),
    };
    // description = [[ ... ]]
    if let Some(start) = body.find("description") {
        let tail = &body[start..];
        if let Some(open) = tail.find("[[") {
            if let Some(close) = tail[open + 2..].find("]]") {
                out.description = tail[open + 2..open + 2 + close].trim().to_string();
            }
        }
    }
    // categories = { "default", "safe", ... }
    if let Some(block) = find_braced_assignment(body, "categories") {
        for tok in block.split(',') {
            let tok = tok.trim().trim_matches(|c| c == '"' || c == '\'').trim();
            if let Some(c) = Category::parse(tok) {
                out.categories.push(c);
            }
        }
    }
    // dependencies = { "smb-brute", ... }
    if let Some(block) = find_braced_assignment(body, "dependencies") {
        for tok in block.split(',') {
            let tok = tok.trim().trim_matches(|c| c == '"' || c == '\'').trim();
            if !tok.is_empty() {
                out.dependencies.push(tok.to_string());
            }
        }
    }
    out.author = find_string_assignment(body, "author").unwrap_or_default();
    out.license = find_string_assignment(body, "license").unwrap_or_default();
    out
}

/// Find `<key> = { ... }` and return the contents between the braces.
fn find_braced_assignment(body: &str, key: &str) -> Option<String> {
    let mut from = 0;
    while let Some(rel) = body[from..].find(key) {
        let idx = from + rel;
        let after = &body[idx + key.len()..];
        if after.trim_start().starts_with('=') {
            if let Some(open) = after.find('{') {
                if let Some(close) = after[open..].find('}') {
                    return Some(after[open + 1..open + close].to_string());
                }
            }
        }
        from = idx + key.len();
    }
    None
}

/// Find `<key> = "..."` and return the quoted string.
fn find_string_assignment(body: &str, key: &str) -> Option<String> {
    let mut from = 0;
    while let Some(rel) = body[from..].find(key) {
        let idx = from + rel;
        let after = &body[idx + key.len()..];
        let after_trim = after.trim_start();
        if let Some(eq) = after_trim.strip_prefix('=') {
            if let Some(q) = eq.find('"') {
                if let Some(close) = eq[q + 1..].find('"') {
                    return Some(eq[q + 1..q + 1 + close].to_string());
                }
            }
        }
        from = idx + key.len();
    }
    None
}
