//! `-oX` XML output. Matches the `nmap.dtd` schema closely so any existing
//! parser (`nmaprun`, libnmap, etc.) handles us transparently.

use nmap_core::result::{HostState, PortState, ScanResult};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use std::io::Cursor;

pub fn emit(r: &ScanResult) -> String {
    let mut w = Writer::new_with_indent(Cursor::new(Vec::new()), b' ', 2);
    let _ = w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)));
    let mut run = BytesStart::new("nmaprun");
    run.push_attribute(("scanner", r.scanner.as_str()));
    run.push_attribute(("version", r.version.as_str()));
    let start = r.start.timestamp().to_string();
    run.push_attribute(("start", start.as_str()));
    let args = r.args.clone();
    run.push_attribute(("args", args.as_str()));
    let xmlns = "https://nmap.org/xsl/nmap.xsl";
    run.push_attribute(("xmlversion", "1.05"));
    run.push_attribute(("xmlns", xmlns));
    let _ = w.write_event(Event::Start(run.to_owned()));

    for h in &r.hosts {
        let mut host = BytesStart::new("host");
        host.push_attribute(("starttime", h.start.timestamp().to_string().as_str()));
        host.push_attribute(("endtime", h.end.timestamp().to_string().as_str()));
        let _ = w.write_event(Event::Start(host.to_owned()));

        // status
        let mut status = BytesStart::new("status");
        status.push_attribute((
            "state",
            match h.state {
                HostState::Up => "up",
                HostState::Down => "down",
                _ => "unknown",
            },
        ));
        if let Some(r) = &h.state_reason {
            status.push_attribute(("reason", r.reason.as_str()));
            if let Some(ttl) = r.ttl {
                let ttl_s = ttl.to_string();
                status.push_attribute(("reason_ttl", ttl_s.as_str()));
            }
        }
        let _ = w.write_event(Event::Empty(status.to_owned()));

        // addresses
        let mut addr = BytesStart::new("address");
        let address = h.address.to_string();
        addr.push_attribute(("addr", address.as_str()));
        addr.push_attribute((
            "addrtype",
            if h.address.is_ipv4() { "ipv4" } else { "ipv6" },
        ));
        let _ = w.write_event(Event::Empty(addr.to_owned()));

        if !h.hostnames.is_empty() {
            let _ = w.write_event(Event::Start(BytesStart::new("hostnames").to_owned()));
            for name in &h.hostnames {
                let mut hn = BytesStart::new("hostname");
                hn.push_attribute(("name", name.as_str()));
                hn.push_attribute(("type", "user"));
                let _ = w.write_event(Event::Empty(hn.to_owned()));
            }
            let _ = w.write_event(Event::End(BytesEnd::new("hostnames")));
        }

        // ports
        if !h.ports.is_empty() {
            let _ = w.write_event(Event::Start(BytesStart::new("ports").to_owned()));
            for p in &h.ports {
                let mut port = BytesStart::new("port");
                port.push_attribute(("protocol", p.port.protocol.short()));
                let num_s = p.port.number.to_string();
                port.push_attribute(("portid", num_s.as_str()));
                let _ = w.write_event(Event::Start(port.to_owned()));

                let mut st = BytesStart::new("state");
                let state_s = p.state.as_str();
                st.push_attribute(("state", state_s));
                if let Some(r) = &p.reason {
                    st.push_attribute(("reason", r.reason.as_str()));
                    if let Some(t) = r.ttl {
                        let t_s = t.to_string();
                        st.push_attribute(("reason_ttl", t_s.as_str()));
                    }
                }
                let _ = w.write_event(Event::Empty(st.to_owned()));

                if let Some(svc) = &p.service {
                    let mut s_el = BytesStart::new("service");
                    if let Some(n) = &svc.name {
                        s_el.push_attribute(("name", n.as_str()));
                    }
                    if let Some(p) = &svc.product {
                        s_el.push_attribute(("product", p.as_str()));
                    }
                    if let Some(v) = &svc.version {
                        s_el.push_attribute(("version", v.as_str()));
                    }
                    if let Some(e) = &svc.extra_info {
                        s_el.push_attribute(("extrainfo", e.as_str()));
                    }
                    if let Some(m) = &svc.method {
                        s_el.push_attribute(("method", m.as_str()));
                    }
                    let conf_s = svc.conf.to_string();
                    s_el.push_attribute(("conf", conf_s.as_str()));
                    if svc.cpe.is_empty() {
                        let _ = w.write_event(Event::Empty(s_el.to_owned()));
                    } else {
                        let _ = w.write_event(Event::Start(s_el.to_owned()));
                        for c in &svc.cpe {
                            let _ = w.write_event(Event::Start(BytesStart::new("cpe").to_owned()));
                            let _ = w.write_event(Event::Text(BytesText::new(c)));
                            let _ = w.write_event(Event::End(BytesEnd::new("cpe")));
                        }
                        let _ = w.write_event(Event::End(BytesEnd::new("service")));
                    }
                }

                for s in &p.scripts {
                    let mut sc = BytesStart::new("script");
                    sc.push_attribute(("id", s.id.as_str()));
                    sc.push_attribute(("output", s.output.as_str()));
                    let _ = w.write_event(Event::Empty(sc.to_owned()));
                }
                let _ = w.write_event(Event::End(BytesEnd::new("port")));
            }
            let _ = w.write_event(Event::End(BytesEnd::new("ports")));
        }

        if !h.os_matches.is_empty() {
            let _ = w.write_event(Event::Start(BytesStart::new("os").to_owned()));
            for om in &h.os_matches {
                let mut m = BytesStart::new("osmatch");
                m.push_attribute(("name", om.name.as_str()));
                let acc = om.accuracy.to_string();
                m.push_attribute(("accuracy", acc.as_str()));
                let line = om.line.to_string();
                m.push_attribute(("line", line.as_str()));
                let _ = w.write_event(Event::Empty(m.to_owned()));
            }
            let _ = w.write_event(Event::End(BytesEnd::new("os")));
        }

        for s in &h.host_scripts {
            let mut sc = BytesStart::new("hostscript");
            sc.push_attribute(("id", s.id.as_str()));
            sc.push_attribute(("output", s.output.as_str()));
            let _ = w.write_event(Event::Empty(sc.to_owned()));
        }

        let _ = w.write_event(Event::End(BytesEnd::new("host")));
    }

    let mut runstats = BytesStart::new("runstats");
    let _ = w.write_event(Event::Start(runstats.to_owned()));
    let mut finished = BytesStart::new("finished");
    let end_ts = r.end.timestamp().to_string();
    finished.push_attribute(("time", end_ts.as_str()));
    let elapsed = format!("{:.2}", r.elapsed.as_secs_f64());
    finished.push_attribute(("elapsed", elapsed.as_str()));
    finished.push_attribute(("exit", "success"));
    let _ = w.write_event(Event::Empty(finished.to_owned()));
    let mut hosts = BytesStart::new("hosts");
    let up = r.summary_up.to_string();
    hosts.push_attribute(("up", up.as_str()));
    let down = r.summary_down.to_string();
    hosts.push_attribute(("down", down.as_str()));
    let total = r.summary_total.to_string();
    hosts.push_attribute(("total", total.as_str()));
    let _ = w.write_event(Event::Empty(hosts.to_owned()));
    let _ = w.write_event(Event::End(BytesEnd::new("runstats")));

    let _ = w.write_event(Event::End(BytesEnd::new("nmaprun")));
    String::from_utf8(w.into_inner().into_inner()).unwrap_or_default()
}
