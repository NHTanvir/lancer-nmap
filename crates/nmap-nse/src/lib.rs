//! `nmap-nse` — NSE (Nmap Scripting Engine) host.
//!
//! Embeds mlua/Lua 5.4. Provides:
//! - `Engine` — VM + script registry + per-script coroutine runner
//! - `nmap`, `stdnse`, `shortport`, `comm`, `http`, `dns`, `ssl`, `creds`,
//!   `vulns`, `bin`, `match`, `string`, `table`, `tableaux`, `target`,
//!   `unicode`, `oops`, `os_detection`, `service`, `vulns`, `output` libs
//! - Script discovery via `script.db` + `categories`/`portrule`/`hostrule`/`action`
//! - Cooperative timeouts via `tokio::time::timeout`
//! - Cancellation via a `CancellationToken` shared with the orchestrator

pub mod engine;
pub mod libs;
pub mod scripts;
pub mod runtime;
pub mod registry;
pub mod categories;

pub use engine::{Engine, ScriptInvocation, ScriptOutput};
pub use registry::ScriptRegistry;
pub use scripts::Script;
