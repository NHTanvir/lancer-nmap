# lancer-nmap

Rust clone of [`nmap`](https://nmap.org). Part of the **Lancer** ecosystem —
a complete 2026 AI-era bug bounty toolkit.

`lancer-nmap` ships as a **native GUI application** by default; the CLI
surface is reachable via `lancer-nmap --cli ...` or the dedicated
`lancer-nmap-cli` binary. Every upstream `nmap` flag, every output format,
every probe / detector / scan technique is mirrored.

## Workspace layout

```
lancer-nmap/                 binary — GUI + CLI entrypoints
crates/nmap-core/            scanner engine, target/port/result types
crates/nmap-probes/          nmap-service-probes parser + service detection
crates/nmap-osdb/            nmap-os-db parser + weighted scoring
crates/nmap-nse/             Lua VM (mlua 0.10) + 50 starter scripts
crates/nmap-data/            embedded data tables
crates/nmap-output/          Normal / XML / Grepable / SK / JSON / SARIF / CSV
crates/nmap-gui/             eframe + egui 3-pane Lancer-standard layout
tools/ndiff/                 scan-diff comparator (`lancer-ndiff`)
tools/ncat/                  netcat replacement (`lancer-ncat`)
tools/nping/                 packet crafter (`lancer-nping`)
```

## Build

### Windows
Double-click `build.bat` or, from `cmd`:
```cmd
build.bat
```
Outputs to `build\`:
- `lancer-nmap.exe`      GUI entrypoint (also handles `--cli`)
- `lancer-nmap-cli.exe`  pure CLI binary
- `lancer-ndiff.exe`     scan diff
- `lancer-ncat.exe`      netcat replacement
- `lancer-nping.exe`     packet crafter

Packaged distribution:
```cmd
build-windows.bat
```
Output: `dist\lancer-nmap-windows-x86_64\bin\*.exe`.

### Linux / macOS
```bash
./build-linux.sh
```
Output: `build/`.

### Requirements
- [Rust toolchain](https://rustup.rs) (≥ 1.75 for `edition = "2021"` + workspace deps)
- Linux: `libpcap-dev` for the raw-socket receive path (`AF_PACKET` is the
  fallback on Linux ≥ 2.6.32)
- macOS: BPF device group membership for raw send / receive
- Windows: Visual C++ Build Tools (2019 / 2022); **Npcap 1.87+** for raw
  send (the GUI auto-detects and falls back to `-sT` if missing)

## Usage — GUI

Run `lancer-nmap` with no arguments. Three-pane layout (matches the rest
of the Lancer ecosystem): inputs / jobs on the left, results table in the
centre, host detail on the right. Top menu has File / Tools / Settings
(theme toggle persists across sessions) / Help.

## Usage — CLI

```bash
lancer-nmap --cli -sV --top-ports 1000 -T4 --open -oA recon scanme.nmap.org
lancer-nmap --cli -sn -PR -PE -PS22,80,443 10.0.0.0/24
lancer-nmap --cli -A --script "vuln,!intrusive" -oA full target.com
lancer-nmap --cli -p- -sV -sC -O --reason -oJ result.json acme.com
```

Run `lancer-nmap --cli --help` for the full flag matrix.

## Cross-tool integration

Every Lancer clone exposes a local control-plane HTTP server on a
auto-allocated `127.0.0.1:<port>` (written to `%TEMP%/lancer-nmap.port`).
Endpoints:
- `GET  /v1/state`        current job list / last summary
- `POST /v1/import`       enqueue targets from another Lancer tool
- `GET  /v1/export?format=json|csv|sarif|markdown|xml|gnmap|normal`

## Status

Heavy in development — implementation tracking the local `plan.md`. Full
feature parity is ongoing; see `plan.md` for the granular roadmap.
