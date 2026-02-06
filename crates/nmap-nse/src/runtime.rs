//! Per-script runtime context — what NSE scripts see when they run.

use indexmap::IndexMap;
use nmap_core::result::{HostResult, PortResult, ScriptResult};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct ScriptContext {
    pub host: Arc<HostResult>,
    pub port: Option<PortResult>,
    pub args: Arc<IndexMap<String, String>>,
    pub timeout: std::time::Duration,
}

#[derive(Clone, Debug, Default)]
pub struct ScriptResultBuilder {
    pub id: String,
    pub output: String,
    pub elements: IndexMap<String, serde_json::Value>,
}

impl ScriptResultBuilder {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into(), ..Default::default() }
    }
    pub fn build(self) -> ScriptResult {
        ScriptResult {
            id: self.id,
            output: self.output,
            elements: self.elements,
        }
    }
}
