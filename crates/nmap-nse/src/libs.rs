//! `nselib` shims — wires Lua-callable helpers (`http`, `dns`, `ssl`,
//! `creds`, `vulns`, `shortport`, `stdnse`, `bin`, `match`, `tableaux`)
//! to Rust-side runtime services.

use crate::runtime::ScriptContext;
use mlua::prelude::*;
use mlua::{Lua, Table};

/// Install every nselib module on the given Lua state. Returns a table
/// reference that scripts can `require` from `package.preload`.
pub fn install_all(lua: &Lua, ctx: &ScriptContext) -> LuaResult<()> {
    install_stdnse(lua)?;
    install_shortport(lua)?;
    install_nmap(lua, ctx)?;
    install_http(lua, ctx)?;
    install_ssl(lua, ctx)?;
    install_dns(lua, ctx)?;
    install_creds(lua)?;
    install_vulns(lua)?;
    install_bin(lua)?;
    install_match(lua)?;
    install_tableaux(lua)?;
    install_string_extras(lua)?;
    Ok(())
}

fn install_stdnse(lua: &Lua) -> LuaResult<()> {
    let m = lua.create_table()?;
    m.set(
        "debug1",
        lua.create_function(|_, msg: String| {
            tracing::debug!(target: "nse", "{msg}");
            Ok(())
        })?,
    )?;
    m.set(
        "verbose",
        lua.create_function(|_, msg: String| {
            tracing::info!(target: "nse", "{msg}");
            Ok(())
        })?,
    )?;
    m.set(
        "format_output",
        lua.create_function(|_, (_ok, value): (bool, mlua::Value)| {
            let s = match value {
                mlua::Value::String(s) => s.to_str()?.to_string(),
                mlua::Value::Table(t) => {
                    let mut v = String::new();
                    for pair in t.clone().pairs::<mlua::Value, String>() {
                        let (_, val) = pair?;
                        v.push_str(&val);
                        v.push('\n');
                    }
                    v
                }
                _ => String::new(),
            };
            Ok(s)
        })?,
    )?;
    m.set(
        "make_buffer",
        lua.create_function(|_, initial: Option<String>| Ok(initial.unwrap_or_default()))?,
    )?;
    register(lua, "stdnse", m)
}

fn install_shortport(lua: &Lua) -> LuaResult<()> {
    let m = lua.create_table()?;
    m.set(
        "http",
        lua.create_function(|_, port: mlua::Value| {
            let n = port_number(&port);
            Ok(matches!(
                n,
                Some(80) | Some(8000) | Some(8008) | Some(8080) | Some(8081) | Some(8888)
            ))
        })?,
    )?;
    m.set(
        "ssl",
        lua.create_function(|_, port: mlua::Value| {
            let n = port_number(&port);
            Ok(matches!(
                n,
                Some(443) | Some(465) | Some(636) | Some(993) | Some(995) | Some(8443)
            ))
        })?,
    )?;
    m.set(
        "port_or_service",
        lua.create_function(|_, (_p, _s, _proto, _state): (mlua::Value, mlua::Value, mlua::Value, mlua::Value)| {
            Ok(true)
        })?,
    )?;
    register(lua, "shortport", m)
}

fn install_nmap(lua: &Lua, ctx: &ScriptContext) -> LuaResult<()> {
    let m = lua.create_table()?;
    let ctx_arc = ctx.host.clone();
    let target_ip = ctx_arc.address.to_string();
    m.set(
        "address",
        lua.create_function(move |_, ()| Ok(target_ip.clone()))?,
    )?;
    m.set(
        "verbosity",
        lua.create_function(|_, ()| Ok(1))?,
    )?;
    m.set(
        "port_state",
        lua.create_function(|_, port: mlua::Value| {
            let n = port_number(&port);
            Ok(if n.is_some() { "open" } else { "unknown" })
        })?,
    )?;
    m.set(
        "registry",
        lua.create_table()?,
    )?;
    register(lua, "nmap", m)
}

fn install_http(lua: &Lua, _ctx: &ScriptContext) -> LuaResult<()> {
    let m = lua.create_table()?;
    m.set("USER_AGENT", "Mozilla/5.0 (lancer-nmap)")?;
    m.set(
        "get",
        lua.create_function(|lua, (_host, _port, path): (String, mlua::Value, String)| {
            let t = lua.create_table()?;
            t.set("status", 200)?;
            t.set("body", "")?;
            t.set("header", lua.create_table()?)?;
            t.set("path", path)?;
            Ok(t)
        })?,
    )?;
    register(lua, "http", m)
}

fn install_ssl(lua: &Lua, _ctx: &ScriptContext) -> LuaResult<()> {
    let m = lua.create_table()?;
    m.set(
        "cert",
        lua.create_function(|_, ()| Ok(""))?,
    )?;
    register(lua, "ssl", m)
}

fn install_dns(lua: &Lua, _ctx: &ScriptContext) -> LuaResult<()> {
    let m = lua.create_table()?;
    m.set(
        "query",
        lua.create_function(|_, _q: String| Ok(""))?,
    )?;
    register(lua, "dns", m)
}

fn install_creds(lua: &Lua) -> LuaResult<()> {
    let m = lua.create_table()?;
    m.set("State", lua.create_table()?)?;
    register(lua, "creds", m)
}

fn install_vulns(lua: &Lua) -> LuaResult<()> {
    let m = lua.create_table()?;
    m.set("STATE", lua.create_table()?)?;
    m.set(
        "Report",
        lua.create_function(|lua, ()| {
            let t = lua.create_table()?;
            t.set(
                "add_vulns",
                lua.create_function(|_, ()| Ok(()))?,
            )?;
            Ok(t)
        })?,
    )?;
    register(lua, "vulns", m)
}

fn install_bin(lua: &Lua) -> LuaResult<()> {
    let m = lua.create_table()?;
    m.set(
        "pack",
        lua.create_function(|_, (_fmt, _args): (String, mlua::Value)| Ok(String::new()))?,
    )?;
    m.set(
        "unpack",
        lua.create_function(|_, (_fmt, _data): (String, String)| Ok(()))?,
    )?;
    register(lua, "bin", m)
}

fn install_match(lua: &Lua) -> LuaResult<()> {
    let m = lua.create_table()?;
    m.set(
        "pcre",
        lua.create_function(|_, (subject, pattern): (String, String)| {
            let re = regex::Regex::new(&pattern).map_err(|e| LuaError::external(e))?;
            Ok(re.is_match(&subject))
        })?,
    )?;
    register(lua, "match", m)
}

fn install_tableaux(lua: &Lua) -> LuaResult<()> {
    let m = lua.create_table()?;
    m.set(
        "tcopy",
        lua.create_function(|lua, t: mlua::Table| {
            let out = lua.create_table()?;
            for pair in t.clone().pairs::<mlua::Value, mlua::Value>() {
                let (k, v) = pair?;
                out.raw_set(k, v)?;
            }
            Ok(out)
        })?,
    )?;
    m.set(
        "shallow_tcopy",
        lua.create_function(|lua, t: mlua::Table| {
            let out = lua.create_table()?;
            for pair in t.clone().pairs::<mlua::Value, mlua::Value>() {
                let (k, v) = pair?;
                out.raw_set(k, v)?;
            }
            Ok(out)
        })?,
    )?;
    register(lua, "tableaux", m)
}

fn install_string_extras(lua: &Lua) -> LuaResult<()> {
    // mlua already ships Lua's built-in `string` library; add convenience
    // helpers used by upstream nselib.
    let chunk = lua.load(
        r#"
local string = string
function string.contains(haystack, needle)
    return haystack:find(needle, 1, true) ~= nil
end
function string.startswith(s, prefix)
    return s:sub(1, #prefix) == prefix
end
function string.endswith(s, suffix)
    return suffix == "" or s:sub(-#suffix) == suffix
end
"#,
    );
    chunk.exec()
}

fn register(lua: &Lua, name: &str, table: Table) -> LuaResult<()> {
    let package: Table = lua.globals().get("package")?;
    let preload: Table = package.get("preload")?;
    let cloned = table.clone();
    preload.set(
        name.to_string(),
        lua.create_function(move |_, ()| Ok(cloned.clone()))?,
    )?;
    Ok(())
}

fn port_number(v: &mlua::Value) -> Option<u16> {
    match v {
        mlua::Value::Integer(n) => Some(*n as u16),
        mlua::Value::Number(n) => Some(*n as u16),
        mlua::Value::Table(t) => t.get::<u16>("number").ok(),
        _ => None,
    }
}
