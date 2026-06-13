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
    install_nselib_modules(lua)?;
    Ok(())
}

/// Preload every embedded upstream `nselib` Lua module (133 modules) into
/// `package.preload` so scripts can `require` them. The Rust-backed primitive
/// stubs installed above (nmap/http/ssl/dns/stdnse/...) take precedence — we
/// never overwrite an already-registered module.
fn install_nselib_modules(lua: &Lua) -> LuaResult<()> {
    let package: Table = lua.globals().get("package")?;
    let preload: Table = package.get("preload")?;
    for file in crate::registry::EMBEDDED_NSELIB.files() {
        let name = match file.path().file_stem().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let existing: mlua::Value = preload.get(name.clone())?;
        if !existing.is_nil() {
            continue; // keep the Rust-backed stub
        }
        let src = match file.contents_utf8() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let modname = name.clone();
        preload.set(
            name,
            lua.create_function(move |lua, ()| {
                lua.load(&src).set_name(modname.clone()).eval::<mlua::Value>()
            })?,
        )?;
    }
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
    // `stdnse.get_script_args(...)` — scripts use `... or default`, so nil is
    // a safe baseline until per-script-arg wiring lands.
    m.set(
        "get_script_args",
        lua.create_function(|_, _names: mlua::MultiValue| Ok(mlua::Value::Nil))?,
    )?;
    // `stdnse.output_table()` — returns a plain table scripts fill with k/v
    // pairs and return from `action`; our action-return flattener prints it.
    m.set(
        "output_table",
        lua.create_function(|lua, ()| lua.create_table())?,
    )?;
    for name in ["debug2", "debug3", "print_debug", "print_verbose"] {
        m.set(
            name,
            lua.create_function(|_, _: mlua::MultiValue| Ok(()))?,
        )?;
    }
    register(lua, "stdnse", m)
}

fn install_shortport(lua: &Lua) -> LuaResult<()> {
    let m = lua.create_table()?;
    // `shortport.http` / `shortport.ssl` are themselves portrule functions,
    // used as `portrule = shortport.http` — so they take (host, port).
    m.set(
        "http",
        lua.create_function(|_, (_host, port): (mlua::Value, mlua::Value)| {
            let n = port_number(&port);
            Ok(matches!(
                n,
                Some(80) | Some(280) | Some(443) | Some(591) | Some(593) | Some(8000)
                    | Some(8008) | Some(8080) | Some(8081) | Some(8443) | Some(8888)
            ))
        })?,
    )?;
    m.set(
        "ssl",
        lua.create_function(|_, (_host, port): (mlua::Value, mlua::Value)| {
            let n = port_number(&port);
            Ok(matches!(
                n,
                Some(443) | Some(465) | Some(636) | Some(993) | Some(995) | Some(989)
                    | Some(990) | Some(992) | Some(5061) | Some(8443)
            ))
        })?,
    )?;
    // `shortport.port_or_service(ports, services, ...)` returns a portrule
    // function that matches the given port numbers / service names.
    m.set(
        "port_or_service",
        lua.create_function(|lua, args: mlua::MultiValue| {
            let mut it = args.into_iter();
            let ports = value_to_u16_set(it.next().as_ref());
            let services = value_to_string_set(it.next().as_ref());
            let rule = lua.create_function(move |_, (_host, port): (mlua::Value, mlua::Value)| {
                let num = port_number(&port);
                let svc = port_service_name(&port);
                let by_port = num.map(|n| ports.contains(&n)).unwrap_or(false);
                let by_svc = svc
                    .as_ref()
                    .map(|s| services.iter().any(|x| x == s))
                    .unwrap_or(false);
                Ok(by_port || by_svc)
            })?;
            Ok(rule)
        })?,
    )?;
    // `shortport.portnumber(ports, protos)` → portrule matching the numbers.
    m.set(
        "portnumber",
        lua.create_function(|lua, args: mlua::MultiValue| {
            let ports = value_to_u16_set(args.into_iter().next().as_ref());
            let rule = lua.create_function(move |_, (_host, port): (mlua::Value, mlua::Value)| {
                Ok(port_number(&port).map(|n| ports.contains(&n)).unwrap_or(false))
            })?;
            Ok(rule)
        })?,
    )?;
    register(lua, "shortport", m)
}

fn value_to_u16_set(v: Option<&mlua::Value>) -> std::collections::HashSet<u16> {
    let mut set = std::collections::HashSet::new();
    match v {
        Some(mlua::Value::Integer(n)) => {
            set.insert(*n as u16);
        }
        Some(mlua::Value::Number(n)) => {
            set.insert(*n as u16);
        }
        Some(mlua::Value::Table(t)) => {
            for pair in t.clone().pairs::<mlua::Value, mlua::Value>() {
                if let Ok((_, val)) = pair {
                    if let Some(n) = port_number(&val) {
                        set.insert(n);
                    }
                }
            }
        }
        _ => {}
    }
    set
}

fn value_to_string_set(v: Option<&mlua::Value>) -> Vec<String> {
    let mut out = Vec::new();
    match v {
        Some(mlua::Value::String(s)) => {
            if let Ok(s) = s.to_str() {
                out.push(s.to_string());
            }
        }
        Some(mlua::Value::Table(t)) => {
            for pair in t.clone().pairs::<mlua::Value, mlua::Value>() {
                if let Ok((_, mlua::Value::String(s))) = pair {
                    if let Ok(s) = s.to_str() {
                        out.push(s.to_string());
                    }
                }
            }
        }
        _ => {}
    }
    out
}

fn port_service_name(port: &mlua::Value) -> Option<String> {
    if let mlua::Value::Table(t) = port {
        if let Ok(mlua::Value::Table(svc)) = t.get::<mlua::Value>("service") {
            if let Ok(mlua::Value::String(n)) = svc.get::<mlua::Value>("name") {
                return n.to_str().ok().map(|s| s.to_string());
            }
        }
    }
    None
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
    // Real blocking-TCP socket factory — `nmap.new_socket()` returns a socket
    // object scripts drive with :connect/:send/:receive/:close. We run inside
    // a blocking task, so synchronous std::net I/O is correct here.
    m.set(
        "new_socket",
        lua.create_function(|_, _proto: mlua::Value| Ok(NseSocket::new()))?,
    )?;
    register(lua, "nmap", m)
}

/// A blocking TCP socket exposed to NSE scripts as `nmap.new_socket()`.
struct NseSocket {
    stream: Option<std::net::TcpStream>,
    timeout: std::time::Duration,
}

impl NseSocket {
    fn new() -> Self {
        Self {
            stream: None,
            timeout: std::time::Duration::from_secs(5),
        }
    }
}

impl mlua::UserData for NseSocket {
    fn add_methods<M: mlua::UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method_mut("set_timeout", |_, this, ms: u64| {
            this.timeout = std::time::Duration::from_millis(ms.max(1));
            Ok(())
        });
        methods.add_method_mut(
            "connect",
            |_, this, (host, port, _proto): (String, mlua::Value, Option<String>)| {
                use std::net::ToSocketAddrs;
                let port = port_number(&port).unwrap_or(0);
                let to = this.timeout;
                let addrs = match (host.as_str(), port).to_socket_addrs() {
                    Ok(a) => a,
                    Err(e) => return Ok((false, e.to_string())),
                };
                for addr in addrs {
                    if let Ok(s) = std::net::TcpStream::connect_timeout(&addr, to) {
                        let _ = s.set_read_timeout(Some(to));
                        let _ = s.set_write_timeout(Some(to));
                        this.stream = Some(s);
                        return Ok((true, String::new()));
                    }
                }
                Ok((false, "connect failed".to_string()))
            },
        );
        methods.add_method_mut("send", |_, this, data: mlua::String| {
            use std::io::Write;
            match &mut this.stream {
                Some(s) => match s.write_all(&data.as_bytes()) {
                    Ok(_) => Ok((true, String::new())),
                    Err(e) => Ok((false, e.to_string())),
                },
                None => Ok((false, "not connected".to_string())),
            }
        });
        methods.add_method_mut("receive", |lua, this, ()| {
            use std::io::Read;
            match &mut this.stream {
                Some(s) => {
                    let mut buf = [0u8; 8192];
                    match s.read(&mut buf) {
                        Ok(0) => Ok((false, lua.create_string("EOF")?)),
                        Ok(n) => Ok((true, lua.create_string(&buf[..n])?)),
                        Err(e) => Ok((false, lua.create_string(e.to_string())?)),
                    }
                }
                None => Ok((false, lua.create_string("not connected")?)),
            }
        });
        methods.add_method_mut("receive_bytes", |lua, this, n: usize| {
            use std::io::Read;
            match &mut this.stream {
                Some(s) => {
                    let mut buf = vec![0u8; n.clamp(1, 65536)];
                    match s.read(&mut buf) {
                        Ok(got) => Ok((true, lua.create_string(&buf[..got])?)),
                        Err(e) => Ok((false, lua.create_string(e.to_string())?)),
                    }
                }
                None => Ok((false, lua.create_string("not connected")?)),
            }
        });
        // Approximate receive_lines with a single read of available data.
        methods.add_method_mut("receive_lines", |lua, this, _n: usize| {
            use std::io::Read;
            match &mut this.stream {
                Some(s) => {
                    let mut buf = [0u8; 8192];
                    match s.read(&mut buf) {
                        Ok(0) => Ok((false, lua.create_string("EOF")?)),
                        Ok(got) => Ok((true, lua.create_string(&buf[..got])?)),
                        Err(e) => Ok((false, lua.create_string(e.to_string())?)),
                    }
                }
                None => Ok((false, lua.create_string("not connected")?)),
            }
        });
        methods.add_method_mut("close", |_, this, ()| {
            this.stream = None;
            Ok(true)
        });
        methods.add_method_mut("get_info", |_, this, ()| match &this.stream {
            Some(s) => {
                let local = s.local_addr().map(|a| a.ip().to_string()).unwrap_or_default();
                let lport = s.local_addr().map(|a| a.port()).unwrap_or(0);
                let peer = s.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
                let pport = s.peer_addr().map(|a| a.port()).unwrap_or(0);
                Ok((true, local, lport, peer, pport))
            }
            None => Ok((false, String::new(), 0u16, String::new(), 0u16)),
        });
    }
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
