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

    // Execute the script body to define its globals (description, categories,
    // portrule / hostrule, action, ...). Leniently ignore load errors caused
    // by nselib `require`s we don't yet fully support — the script simply
    // produces no output in that case.
    if let Err(e) = lua.load(&source).set_name(script_name.clone()).exec() {
        tracing::debug!(target: "nse", script = %script_name, "load: {e}");
    }
    let globals = lua.globals();

    // Build the `host` and `port` argument tables NSE `action`/`portrule`
    // functions expect.
    let host_tbl = lua.create_table()?;
    host_tbl.set("ip", ctx.host.address.to_string())?;
    if let Some(h) = ctx.host.hostnames.first() {
        host_tbl.set("name", h.clone())?;
        host_tbl.set("targetname", h.clone())?;
    }
    let port_tbl = lua.create_table()?;
    let has_port = ctx.port.is_some();
    if let Some(p) = &ctx.port {
        port_tbl.set("number", p.port.number)?;
        port_tbl.set("protocol", p.port.protocol.short())?;
        port_tbl.set("state", p.state.as_str())?;
        let svc = lua.create_table()?;
        if let Some(s) = &p.service {
            if let Some(n) = &s.name {
                svc.set("name", n.clone())?;
            }
            if let Some(v) = &s.version {
                svc.set("version", v.clone())?;
            }
            if let Some(pr) = &s.product {
                svc.set("product", pr.clone())?;
            }
        }
        port_tbl.set("service", svc)?;
    }

    // Decide whether to run: evaluate portrule (per-port scripts) or hostrule
    // (host scripts). A missing rule defaults to running for port scripts.
    let rule_name = if has_port { "portrule" } else { "hostrule" };
    let should_run = match globals.get::<mlua::Value>(rule_name) {
        Ok(mlua::Value::Function(f)) => f
            .call::<bool>((host_tbl.clone(), port_tbl.clone()))
            .unwrap_or(false),
        _ => has_port,
    };

    let mut output = String::new();
    if should_run {
        if let Ok(mlua::Value::Function(action)) = globals.get::<mlua::Value>("action") {
            match action.call::<mlua::Value>((host_tbl, port_tbl)) {
                Ok(v) => output = lua_value_to_output(&v),
                Err(e) => tracing::debug!(target: "nse", script = %script_name, "action: {e}"),
            }
        }
    }
    // Back-compat with scripts using the `_lancer_output` convention.
    if output.is_empty() {
        output = globals.get("_lancer_output").unwrap_or_default();
    }

    let mut b = ScriptResultBuilder::new(script_name);
    b.output = output;
    Ok(b.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::categories::Category;
    use crate::scripts::Script;
    use nmap_core::port::{Port, Protocol};
    use nmap_core::result::{HostResult, PortResult, PortState};

    #[tokio::test]
    async fn action_runs_with_host_and_port() {
        // A script that returns from action() using the host/port tables and a
        // portrule — exercises the real NSE execution path.
        let src = r#"
            portrule = function(host, port) return port.number == 80 end
            action = function(host, port)
                return "banner " .. host.ip .. ":" .. port.number .. "/" .. port.protocol
            end
        "#;
        let script = Script::builtin("t", "", &[Category::Default]);
        let script = Script { source: Some(src.to_string()), ..script };
        let engine = Engine { registry: ScriptRegistry::new() };
        let mut host = HostResult::new("127.0.0.1".parse().unwrap());
        let port = PortResult::new(Port { number: 80, protocol: Protocol::Tcp }, PortState::Open);
        host.ports.push(port.clone());
        let inv = ScriptInvocation {
            host: Arc::new(host),
            port: Some(port),
            args: Default::default(),
            timeout: Duration::from_secs(5),
        };
        let out = engine.run_script(&script, inv).await;
        assert_eq!(out.result.output, "banner 127.0.0.1:80/tcp");
    }

    #[tokio::test]
    async fn portrule_false_skips_action() {
        let src = r#"
            portrule = function(host, port) return false end
            action = function(host, port) return "should not run" end
        "#;
        let script = Script {
            source: Some(src.to_string()),
            ..Script::builtin("t", "", &[Category::Default])
        };
        let engine = Engine { registry: ScriptRegistry::new() };
        let mut host = HostResult::new("127.0.0.1".parse().unwrap());
        let port = PortResult::new(Port { number: 80, protocol: Protocol::Tcp }, PortState::Open);
        host.ports.push(port.clone());
        let inv = ScriptInvocation {
            host: Arc::new(host),
            port: Some(port),
            args: Default::default(),
            timeout: Duration::from_secs(5),
        };
        let out = engine.run_script(&script, inv).await;
        assert_eq!(out.result.output, "");
    }
}

/// Flatten an NSE `action` return value (string | number | bool | table) into
/// printable script output.
fn lua_value_to_output(v: &mlua::Value) -> String {
    match v {
        mlua::Value::String(s) => s.to_str().map(|s| s.to_string()).unwrap_or_default(),
        mlua::Value::Integer(i) => i.to_string(),
        mlua::Value::Number(n) => n.to_string(),
        mlua::Value::Boolean(b) => b.to_string(),
        mlua::Value::Table(t) => {
            let mut out = String::new();
            for pair in t.clone().pairs::<mlua::Value, mlua::Value>() {
                let Ok((k, val)) = pair else { continue };
                let vs = lua_value_to_output(&val);
                if vs.is_empty() {
                    continue;
                }
                match k {
                    mlua::Value::String(ks) => {
                        let key = ks.to_str().map(|s| s.to_string()).unwrap_or_default();
                        out.push_str(&format!("{key}: {vs}\n"));
                    }
                    _ => {
                        out.push_str(&vs);
                        out.push('\n');
                    }
                }
            }
            out.trim_end().to_string()
        }
        _ => String::new(),
    }
}
