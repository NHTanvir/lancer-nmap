//! NSE host engine — runs one script per (script, host[, port]) invocation
//! in an isolated Lua VM with a cooperative timeout.

use crate::libs;
use crate::registry::ScriptRegistry;
use crate::runtime::{ScriptContext, ScriptResultBuilder};
use crate::scripts::Script;
use mlua::prelude::*;
use nmap_core::result::{HostResult, PortResult, ScriptResult};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::warn;

#[derive(Clone, Debug)]
pub struct ScriptInvocation {
    pub host: Arc<HostResult>,
    pub port: Option<PortResult>,
    pub args: indexmap::IndexMap<String, String>,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ScriptOutput {
    pub script: String,
    pub host: std::net::IpAddr,
    pub port: Option<u16>,
    pub result: ScriptResult,
}

pub struct Engine {
    pub registry: ScriptRegistry,
}

impl Engine {
    pub fn new() -> Self {
        let mut r = ScriptRegistry::new();
        r.load_builtin();
        Self { registry: r }
    }

    pub async fn run_script(
        &self,
        script: &Script,
        inv: ScriptInvocation,
    ) -> ScriptOutput {
        let host = inv.host.clone();
        let port = inv.port.clone();
        let port_no = inv.port.as_ref().map(|p| p.port.number);
        let ctx = ScriptContext {
            host: host.clone(),
            port: port.clone(),
            args: Arc::new(inv.args.clone()),
            timeout: inv.timeout,
        };
        let name = script.name.clone();
        let source = script.source.clone().unwrap_or_default();
        let fut = tokio::task::spawn_blocking(move || run_in_lua(name, source, ctx));
        let result = match timeout(inv.timeout, fut).await {
            Ok(Ok(Ok(r))) => r,
            Ok(Ok(Err(e))) => {
                warn!(error=%e, "NSE script failure");
                ScriptResultBuilder::new(script.name.clone()).build()
            }
            Ok(Err(e)) => {
                warn!(error=%e, "NSE join failure");
                ScriptResultBuilder::new(script.name.clone()).build()
            }
            Err(_) => {
                let mut b = ScriptResultBuilder::new(script.name.clone());
                b.output = "[timeout]".into();
                b.build()
            }
        };
        ScriptOutput {
            script: script.name.clone(),
            host: host.address,
            port: port_no,
            result,
        }
    }

    pub async fn run_default_scripts(&self, host: HostResult) -> Vec<ScriptOutput> {
        let host_arc = Arc::new(host);
        let mut outs = Vec::new();
        for script in self.registry.scripts.values() {
            if !script
                .categories
                .iter()
                .any(|c| matches!(c, crate::categories::Category::Default))
            {
                continue;
            }
            let inv = ScriptInvocation {
                host: host_arc.clone(),
                port: None,
                args: Default::default(),
                timeout: Duration::from_secs(60),
            };
            outs.push(self.run_script(script, inv).await);
        }
        outs
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

fn run_in_lua(
    script_name: String,
    source: String,
    ctx: ScriptContext,
) -> Result<ScriptResult, mlua::Error> {
    let lua = Lua::new();
    libs::install_all(&lua, &ctx)?;
    let chunk = lua.load(&source).set_name(script_name.clone());
    let _ = chunk.exec();
    // Built-in starter scripts populate `_lancer_output` as the convention.
    let out: String = lua
        .globals()
        .get("_lancer_output")
        .unwrap_or_default();
    let mut b = ScriptResultBuilder::new(script_name);
    b.output = out;
    Ok(b.build())
}
