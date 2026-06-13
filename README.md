# lancer-nmap

Rust clone of [`nmap`](https://nmap.org) (tracking upstream **7.99**). Part of
the **Lancer** ecosystem — a 2026 AI-era bug bounty toolkit.

`lancer-nmap` ships as a **native GUI application** by default; the full CLI
surface is reachable via `lancer-nmap --cli ...` or the dedicated
`lancer-nmap-cli` binary. It bundles nmap's real reference databases and the
complete NSE script corpus, and accepts nmap-style flags verbatim
(`-sV -Pn -PS22,80 -oA out`).

## What's bundled (the real nmap data, embedded in the binary)

| Database | Source | Size | Parsed entries |
|----------|--------|------|----------------|
| `nmap-service-probes` | upstream 7.99 | 2.6 MB | 187 probes / ~8 000 match lines (`-sV`) |
| `nmap-os-db`          | upstream 7.99 | 5.5 MB | 6 108 OS fingerprints (`-O`) |
| `nmap-services`       | upstream 7.99 | 1.0 MB | 8 387 TCP / 19 022 UDP frequency-ranked (`--top-ports`) |
| `nmap-protocols`, `nmap-rpc`, `nmap-mac-prefixes` | upstream 7.99 | — | IP-proto / RPC / OUI lookups |
| NSE scripts | upstream 7.99 | — | **612 `.nse` scripts** + 133 `nselib` modules + `script.db` |

All are embedded via `include_str!` / `include_dir!` (no external files
needed) and overridable with `--datadir <dir>`. Verify on your machine with
`lancer-nmap --cli --healthcheck`.

## Workspace layout

```
lancer-nmap/                 binary — GUI + CLI entrypoints
crates/nmap-core/            scanner engine, target/port/result types
crates/nmap-probes/          nmap-service-probes parser + service detection
crates/nmap-osdb/            nmap-os-db parser + weighted scoring
crates/nmap-nse/             Lua VM (mlua 0.10) + full 612-script corpus
crates/nmap-data/            embedded data tables (probes/os-db/services/...)
crates/nmap-engine/          shared -sV / -O / NSE enrichment (CLI + GUI)
crates/nmap-output/          Normal / XML / Grepable / SK / JSON / SARIF / CSV
crates/nmap-gui/             eframe + egui 3-pane Lancer-standard layout
tools/ndiff/                 scan-diff comparator (`lancer-ndiff`)
tools/ncat/                  netcat replacement (`lancer-ncat`)
tools/nping/                 packet crafter (`lancer-nping`)
```

## Build

```bash
cargo build --release --workspace      # all binaries into target/release
```

Or use the bundled scripts: `build.bat` (Windows) / `./build-linux.sh`
(Linux/macOS). Requirements:

- [Rust toolchain](https://rustup.rs) (≥ 1.75)
- Windows: Visual C++ Build Tools (2019/2022); **Npcap 1.87+** for raw-socket
  scans (connect scan works without it)
- Linux: `libpcap-dev` for the raw-socket receive path
- macOS: BPF device group membership for raw send/receive

## Usage — GUI

Run `lancer-nmap` with no arguments. Three-pane layout: inputs / jobs on the
left, results table in the centre, host detail on the right. Scans run on a
background thread and are enriched with `-sV` / `-O` / NSE (same depth as the
CLI). Theme toggle persists across sessions.

## Usage — CLI

Accepts nmap's native single-dash flags:

```bash
lancer-nmap --cli -sV -Pn --top-ports 1000 -T4 --open -oA recon scanme.nmap.org
lancer-nmap --cli -p- -sV -sC -O --reason -oX result.xml acme.com
lancer-nmap --cli -sn 10.0.0.0/24
lancer-nmap --cli -sL 192.168.1.0/24            # list targets, don't scan
lancer-nmap --cli --healthcheck                 # show embedded DB sizes
```

Run `lancer-nmap --cli --help` for the full flag matrix (200+ flags grouped by
target / discovery / scan / port / service / script / OS / timing / evasion /
output).

## Feature status

| Area | State |
|------|-------|
| Target spec (IP / CIDR / octet-range / `-iL` / `-iR` / `--exclude`) | ✅ working |
| `-sT` TCP connect scan | ✅ working (default unprivileged path) |
| `-sV` service/version detection (full probe DB) | ✅ working — extracts product/version/extrainfo (verified vs scanme.nmap.org) |
| `-O` OS detection (full os-db, feature-scored) | ✅ working (TTL-class features; full 16-probe stack is roadmap) |
| `--top-ports` / `-F` / `-p` (incl. `T:`/`U:`/`S:` tags) | ✅ working |
| Output: Normal / XML (nmap.dtd) / Grepable / SK / JSON / SARIF / CSV | ✅ working |
| `-oA` / `-oN` / `-oX` / `-oG` / `-oS` / `--open` / `--reason` | ✅ working |
| NSE: 612 scripts registered; scripts execute (portrule + `action` + real `nmap.new_socket` TCP); `-sC` / `--script` / `--script-help` | ✅ engine works; socket-based scripts run, heavy-`nselib` fidelity ongoing |
| GUI (3-pane, run scans, enriched results, export, themes) | ✅ working |
| Host discovery: `-Pn` / `-sn` / TCP-connect ping | ✅ working |
| `-sS/-sU/-sN/-sF/-sX/-sA/-sW/-sM` raw scans | ⏳ fall back to connect until the pnet/pcap raw TX+RX path lands (needs Npcap/root) |
| `-sI` idle, `-sO` IP-proto, `-sY/-sZ` SCTP, `-b` FTP-bounce | ⏳ roadmap (raw sockets) |
| Evasion (`-D`/`-f`/`--mtu`/`--spoof-mac`/`--badsum`/`--ttl`) | ⏳ parsed; applied once raw TX lands |
| Full NSE execution fidelity (all 612 produce upstream output) | ⏳ ongoing — nselib + `nmap` socket bindings expanding |

✅ = implemented & verified · ⏳ = scaffolded / roadmap (see `plan.md`).

## Cross-tool integration

Each Lancer clone exposes a control-plane HTTP server on
`127.0.0.1:<port>` (written to `%TEMP%/lancer-nmap.port`):
`GET /v1/state`, `POST /v1/import`, `GET /v1/export?format=json|csv|sarif|xml|gnmap|normal`.

## Data & licensing

The bundled `nmap-service-probes`, `nmap-os-db`, `nmap-services`,
`nmap-protocols`, `nmap-rpc`, and `nmap-mac-prefixes` data files are
redistributable per the upstream Nmap project. The NSE `.nse` scripts and
`nselib` modules are © the Nmap Project under the **NPSL**. This Rust engine
is a clean-room reimplementation (no upstream C/C++ copied); the data and
scripts are the upstream artifacts. Nmap is a trademark of the Nmap Project.
