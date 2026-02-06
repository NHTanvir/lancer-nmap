//! Lancer-extension SARIF v2.1.0 emitter — one result per open port +
//! one result per NSE script hit.

use nmap_core::result::{PortState, ScanResult};
use serde_json::{json, Value};

pub fn emit(r: &ScanResult) -> String {
    let mut results: Vec<Value> = Vec::new();
    let mut rules: Vec<Value> = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();
    for h in &r.hosts {
        for p in &h.ports {
            if !matches!(p.state, PortState::Open | PortState::OpenFiltered) {
                continue;
            }
            let rule_id = format!("port-open/{}", p.port.protocol.short());
            if seen_rules.insert(rule_id.clone()) {
                rules.push(json!({
                    "id": rule_id,
                    "shortDescription": {"text": "Open port"},
                    "helpUri": "https://nmap.org/book/port-scanning.html",
                }));
            }
            let service = p.service.as_ref().and_then(|s| s.name.clone()).unwrap_or_default();
            let version = p.service.as_ref().and_then(|s| s.version.clone()).unwrap_or_default();
            results.push(json!({
                "ruleId": rule_id,
                "level": "note",
                "message": {"text": format!("{} {} {}", p.port.number, service, version)},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": format!("network://{}/{}", h.address, p.port.number)},
                    }
                }],
                "properties": {
                    "host": h.address.to_string(),
                    "port": p.port.number,
                    "protocol": p.port.protocol.short(),
                    "service": service,
                    "version": version,
                }
            }));
            for s in &p.scripts {
                let nse_rule = format!("nse/{}", s.id);
                if seen_rules.insert(nse_rule.clone()) {
                    rules.push(json!({
                        "id": nse_rule,
                        "shortDescription": {"text": format!("NSE script {}", s.id)},
                    }));
                }
                results.push(json!({
                    "ruleId": nse_rule,
                    "level": "note",
                    "message": {"text": s.output},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": format!("network://{}/{}", h.address, p.port.number)},
                        }
                    }],
                }));
            }
        }
    }
    let doc = json!({
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": r.scanner,
                    "version": r.version,
                    "informationUri": "https://github.com/NHTanvir/lancer-nmap",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}
