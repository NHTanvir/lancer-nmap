//! Parser for the `nmap-os-db` text format. The format is line-oriented:
//!
//! ```text
//! MatchPoints
//! SEQ.GCD=200
//! ...
//!
//! Fingerprint Linux 6.0 - 6.7
//! Class Linux | Linux | 6.X | general purpose
//! CPE cpe:/o:linux:linux_kernel:6
//! SEQ(SP=100-110%GCD=1-6%ISR=104-114%TI=Z%CI=I%TS=8)
//! OPS(O1=M5B4ST11NW7%...)
//! ...
//! ```

use indexmap::IndexMap;

#[derive(Clone, Debug, Default)]
pub struct OsClass {
    pub vendor: String,
    pub osfamily: String,
    pub osgen: Option<String>,
    pub kind: Option<String>,
    pub cpe: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Fingerprint {
    pub name: String,
    pub line: u32,
    pub classes: Vec<OsClass>,
    pub tests: IndexMap<String, IndexMap<String, String>>,
}

#[derive(Clone, Debug, Default)]
pub struct OsDb {
    pub match_points: IndexMap<String, u32>,
    pub fingerprints: Vec<Fingerprint>,
}

pub fn parse_db(text: &str) -> OsDb {
    let mut db = OsDb::default();
    let mut in_match_points = false;
    let mut cur: Option<Fingerprint> = None;
    let mut line_no: u32 = 0;
    for raw in text.lines() {
        line_no += 1;
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "MatchPoints" {
            in_match_points = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("Fingerprint ") {
            in_match_points = false;
            if let Some(p) = cur.take() {
                db.fingerprints.push(p);
            }
            cur = Some(Fingerprint {
                name: rest.to_string(),
                line: line_no,
                ..Default::default()
            });
            continue;
        }
        if in_match_points {
            if let Some((key, val)) = line.split_once('=') {
                if let Ok(n) = val.trim().parse::<u32>() {
                    db.match_points.insert(key.trim().to_string(), n);
                }
            }
            continue;
        }
        let Some(fp) = cur.as_mut() else {
            continue;
        };
        if let Some(rest) = line.strip_prefix("Class ") {
            let parts: Vec<&str> = rest.split('|').map(str::trim).collect();
            let mut c = OsClass::default();
            if let Some(v) = parts.first() {
                c.vendor = v.to_string();
            }
            if let Some(v) = parts.get(1) {
                c.osfamily = v.to_string();
            }
            if let Some(v) = parts.get(2) {
                c.osgen = Some(v.to_string());
            }
            if let Some(v) = parts.get(3) {
                c.kind = Some(v.to_string());
            }
            fp.classes.push(c);
            continue;
        }
        if let Some(rest) = line.strip_prefix("CPE ") {
            if let Some(c) = fp.classes.last_mut() {
                c.cpe.push(rest.to_string());
            }
            continue;
        }
        if let Some((test_name, body)) = parse_test_line(line) {
            fp.tests.insert(test_name, body);
        }
    }
    if let Some(fp) = cur.take() {
        db.fingerprints.push(fp);
    }
    db
}

fn parse_test_line(line: &str) -> Option<(String, IndexMap<String, String>)> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    let name = line[..open].trim().to_string();
    let body = &line[open + 1..close];
    let mut fields: IndexMap<String, String> = IndexMap::new();
    for pair in body.split('%') {
        if let Some((k, v)) = pair.split_once('=') {
            fields.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Some((name, fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_builtin() {
        let db = parse_db(nmap_data::os_db::BUILTIN);
        assert!(!db.fingerprints.is_empty());
        assert!(db.match_points.contains_key("SEQ.GCD"));
    }
}
