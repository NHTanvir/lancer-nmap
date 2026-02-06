# RESEARCH DOSSIER: Nmap

> Part of the Lancer ecosystem. A Rust clone of Fyodor's Nmap — the canonical network mapper and security scanner. Build with Claude Code.
> Upstream: github.com/nmap/nmap (C/C++ + Lua + NSE, **7.95** stable Apr 2024, ~250k stars across mirrors). **NPSL license** (Nmap Public Source License — derivative of GPLv2, with restrictions against integration in commercial products without paid OEM licensing).

## Why both Nmap and naabu

naabu already lives in `19/naabu/` as the **fast port discoverer** — packet-rate optimized, smart-scan, top-N port presets, CDN-aware. That covers the "what's open" half of recon. Nmap is the **deep service profiler** — it adds the three things naabu deliberately doesn't ship: (1) full **service version detection** with the canonical nmap-service-probes database (8000+ signatures), (2) **OS fingerprinting** via the nmap-os-db (5000+ TCP/IP stack signatures), and (3) the **NSE (Nmap Scripting Engine)** ecosystem — 600+ Lua scripts spanning auth bypass, brute force, vuln probing, version-extras, default-cred checks, exploit triggers, malware detection, discovery, fuzzing, and DoS. **Pentest workflow uses naabu for "which ports are open" then Nmap on just the hits for "what's actually running and is it vulnerable."** Same way the field uses RustScan or masscan as the front-runner and Nmap as the deep-dive. Keep both. They are complements, not competitors.

## Feature Parity Mandate

**`lancer-nmap` MUST ship with 100% feature parity to the upstream `nmap` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `nmap --help` (and the long-form man page / docs) must work in `lancer-nmap --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-nmap` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-nmap --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

Nmap is the canonical Internet-era network reconnaissance tool. Given one or many targets (IP, CIDR, hostname, list file), it performs in sequence:

1. **Target enumeration** — expand CIDR/range, resolve hostnames, drop exclusions
2. **Host discovery** (a.k.a. ping scan) — figure out which hosts are alive via ICMP echo, ICMP timestamp, ICMP address-mask, TCP-SYN-to-N-ports, TCP-ACK-to-N-ports, UDP probe, ARP (on local LAN), SCTP-INIT
3. **Port scanning** — figure out the TCP/UDP/SCTP port state (`open`, `closed`, `filtered`, `unfiltered`, `open|filtered`, `closed|filtered`) via 13+ scan techniques: SYN stealth (`-sS`), TCP connect (`-sT`), UDP (`-sU`), TCP NULL (`-sN`), FIN (`-sF`), Xmas (`-sX`), ACK (`-sA`), Window (`-sW`), Maimon (`-sM`), Idle/zombie (`-sI`), IP-protocol (`-sO`), SCTP-INIT (`-sY`), SCTP COOKIE-ECHO (`-sZ`), FTP-bounce (`-b`), custom-flag (`--scanflags`)
4. **Service/version detection** (`-sV`) — for each open port, send probes from `nmap-service-probes`, regex-match the responses against thousands of `match`/`softmatch` lines to derive `service`, `product`, `version`, `extrainfo`, `hostname`, `ostype`, `devicetype`, `cpe:`
5. **OS detection** (`-O`) — send 16 carefully crafted TCP/UDP/ICMP probes (SEQ generation, TCP options ordering, ICMP type-13/15/17, ECN, T2-T7, UDP-to-closed, IE1/IE2), measure ~50 response features, match against `nmap-os-db`
6. **NSE script scanning** (`-sC`, `--script`) — for each port, run matching Lua scripts; categories `default`, `discovery`, `safe`, `version`, `auth`, `vuln`, `intrusive`, `exploit`, `dos`, `brute`, `malware`, `external`, `fuzzer`, `broadcast`; scripts can chain probes, parse banners, attempt logins, fingerprint web tech
7. **Traceroute** (`--traceroute`) — adaptive: reuses the chosen scan technique for hop probes (faster than vanilla traceroute on filtered networks)
8. **Output** — interactive (`-oN`), XML (`-oX` → `nmap-scan.xsl` for HTML), grepable (`-oG`), script-kiddie (`-oS`), all-formats (`-oA basename`)

The `nmap-service-probes` file alone is the most valuable asset in network security — it's the de-facto database of how every service in existence advertises itself.

## Internal architecture

**Workspace** (`Cargo.toml`):
```
[workspace]
members = ["lancer-nmap", "nmap-core", "nmap-nse", "nmap-probes", "nmap-osdb", "tools/*"]
```

- **`lancer-nmap`** — CLI binary (clap 4.5). Parses 200+ flags grouped (target/discovery/scan/port/service/script/os/timing/output/misc/firewall-evasion). Picks XML/grepable/interactive output. Delegates to `nmap-core`.
- **`nmap-core`** — orchestration + packet engine. Sub-modules:
  - `targets.rs` — IP/CIDR/range/hostname/file expansion (mirrors upstream `TargetGroup.cc`)
  - `discovery.rs` — host-alive prelude (ICMP/TCP/UDP/SCTP/ARP/ND)
  - `scan.rs` — main scan dispatcher, per-technique state machine
  - `syn_scan.rs`, `connect_scan.rs`, `udp_scan.rs`, `null_scan.rs`, `fin_scan.rs`, `xmas_scan.rs`, `ack_scan.rs`, `window_scan.rs`, `maimon_scan.rs`, `idle_scan.rs`, `ipprotocol_scan.rs`, `sctp_scan.rs`, `ftp_bounce.rs`
  - `timing.rs` — T0..T5 templates; congestion control (TCP-friendly, mirrors `ultra_scan.cc`)
  - `evasion.rs` — `-D` decoys, `-f` fragmentation, `--mtu`, `--data-length`, `--spoof-mac`, `--source-port`, `--badsum`
  - `pcap_rx.rs` — libpcap receive worker
  - `raw_tx.rs` — raw socket / WinPcap send worker
  - `output/` — XML emitter (full schema), grepable, normal, JSON (Lancer extension), SARIF
- **`nmap-nse`** — Lua VM embedding (`mlua` 0.10 against Lua 5.4). Loads `scripts/*.nse`, exposes the `nmap`, `stdnse`, `shortport`, `comm`, `http`, `ssl`, `creds`, `vulns`, `bin`, `match` libraries
- **`nmap-probes`** — `nmap-service-probes` parser + matching engine
- **`nmap-osdb`** — `nmap-os-db` parser + similarity scorer
- **`tools/`** — `ndiff` (compare scans), `ncat` (netcat-replacement, separate binary upstream), `nping` (packet crafter)

**Key modules (file-level, master as of Apr 2024):**

- **`nsock/`** — Nmap's async socket library (predates libuv); custom event loop, epoll/kqueue/IOCP, IOD (I/O descriptor) abstractions. ~10k LOC C.
- **`libnetutil/`** — packet building helpers (`pcap_open`, `eth_t`, IPv4/IPv6/TCP/UDP/SCTP/ICMP headers)
- **`libdnet-stripped/`** — vendored libdnet for cross-platform raw send
- **`libpcap/`** — vendored libpcap (on Windows uses Npcap)
- **`liblua/`** — vendored Lua 5.4 + `liblinear` (for some NSE scripts)
- **`zenmap/`** — Python+GTK GUI (separate, optional)
- **`scripts/`** — 600+ `.nse` files
- **`nselib/`** — Lua library shipped with NSE: `http.lua`, `dns.lua`, `smb.lua`, `ssl.lua`, `creds.lua`, `vulns.lua`, `shortport.lua`, `match.lua`, `nsedebug.lua`, `stdnse.lua`, ~70 modules
- **`nmap.cc`** — main C++ orchestrator (~5k LOC) — option parsing, target expansion, scan loop
- **`ultra_scan.cc`** — the heart of port scanning (~6k LOC) — ultra-scan algorithm with adaptive RTT, congestion control, simultaneous probes per host
- **`service_scan.cc`** — `-sV` engine
- **`osscan2.cc`** — `-O` OS fingerprinter
- **`nse_main.cc`** + `nse_*.cc` — NSE host process
- **`tcpip.cc`** — packet send/recv primitives
- **`output.cc`** — listing emission
- **`portreasons.cc`** — `--reason` annotations
- **`scan_engine.cc`** — coordinates host scan groups, hostgroup batching
- **`Target.{cc,h}`**, **`portlist.{cc,h}`**, **`scan_lists.{cc,h}`** — model types
- **`nmap-service-probes`** — 2.8MB ASCII DSL, ~8000 match lines
- **`nmap-os-db`** — 5300+ OS fingerprints (~6MB)
- **`nmap-services`** — port-to-service-name frequency table (rare port ranking)
- **`nmap-protocols`** — IP-protocol number-to-name
- **`nmap-rpc`** — Sun-RPC program-number table
- **`nmap-mac-prefixes`** — OUI vendor lookup
- **`nmap-payloads`** — UDP probe payloads for common services

Total upstream LOC: ~250k C/C++ + ~80k Lua. Cloning the **port scanner + -sV engine + a subset of NSE + basic OS detection** is realistic for a solo dev in 16 weeks. Full NSE parity is multi-year.

## Granular feature catalog

### Target spec
- Single host: `scanme.nmap.org`
- CIDR: `10.0.0.0/24`, `2001:db8::/64`
- Octet range: `192.168.1.1-100`, `10.1-3.0-255.50`
- File: `-iL targets.txt`
- Random: `-iR 1000` (pick N random Internet hosts)
- Exclude: `--exclude host1,host2` / `--excludefile excludes.txt`

### Host discovery
- `-sn` — ping scan only (no port scan)
- `-Pn` — skip host discovery (assume alive)
- `-PS22,80,443` — TCP SYN ping
- `-PA80,443` — TCP ACK ping
- `-PU53,161` — UDP ping
- `-PY80` — SCTP INIT ping
- `-PE` — ICMP echo
- `-PP` — ICMP timestamp
- `-PM` — ICMP address-mask
- `-PO1,2,4` — IP protocol ping
- `-PR` — ARP ping (auto-on for local subnets)
- `-n` / `-R` — disable / always-do reverse DNS
- `--dns-servers x.x.x.x` — custom resolvers
- `--system-dns` — use OS resolver
- `--traceroute` — adaptive traceroute after scan
- `--resolve-all` — resolve and scan every IP that a hostname returns (7.95+, was implicit via `-A` before)
- `--unique` — deduplicate target IPs across hostname expansions so each IP is scanned only once (7.96+)
- `--discovery-ignore-rst` — ignore TCP RST during host discovery (helps against firewalls that fake RSTs) (7.97+)

### Scan techniques
- `-sS` — TCP SYN stealth (default for root/admin)
- `-sT` — TCP connect (default unprivileged)
- `-sU` — UDP
- `-sN` — TCP NULL (no flags)
- `-sF` — TCP FIN
- `-sX` — TCP Xmas (FIN+PSH+URG)
- `-sA` — TCP ACK (firewall mapping)
- `-sW` — TCP Window (uses Win-size oddities)
- `-sM` — TCP Maimon (FIN+ACK)
- `-sI zombie:port` — idle/zombie scan (IPID side-channel)
- `-sO` — IP protocol scan
- `-sY` — SCTP INIT
- `-sZ` — SCTP COOKIE-ECHO
- `-sV` — service/version
- `-sC` — default script set (alias for `--script=default`)
- `-A` — aggressive (`-sV -O -sC --traceroute`)
- `-b ftp.example.com` — FTP bounce
- `--scanflags URGACKPSHRSTSYNFIN` — custom flag combo

### Port spec
- `-p 80,443,1-1024`
- `-p T:80,U:53,S:5432` — protocol-tagged
- `-p-` — all 65535
- `-p [80-443]` — only common services in range
- `--top-ports 100` — top-N by frequency
- `-F` — fast (top-100)
- `--port-ratio 0.5` — by services-file frequency
- `--exclude-ports 22,3389`

### Service/version detection
- `-sV` — enable
- `--version-intensity 0-9` — probe selectivity (default 7; 0=no extra probes, 9=all probes)
- `--version-light` — alias for intensity 2
- `--version-all` — intensity 9
- `--version-trace` — debug
- `--allports` — version-scan even normally-skipped ports (9100 printer)
- **Probe coverage 7.95+ (1,246 protocols total):** new probes for `gRPC` (HTTP/2 framed), `MySQLx` (X Protocol, port 33060), `RemoteMouse`, `Tuya` (IoT), `WinBox` (MikroTik), modern Redis ACL banners, etcd v3, and ClickHouse native protocol.
- **DTLS service scanning** (7.96+) — `-sV` now negotiates DTLS handshakes against UDP ports to fingerprint UDP+SSL services (DTLS-SRTP, OpenVPN-DTLS, COAPS, WebRTC).

### OS detection
- `-O` — enable
- `--osscan-limit` — only attempt when 1 open + 1 closed port found
- `--osscan-guess` — accept softer matches
- `--max-os-tries 5` — retries

### NSE
- `-sC` — default scripts
- `--script "category1,category2,!exclude"` — category/glob/file
- `--script-args "key=val,user=admin"` — args
- `--script-args-file scripts.args`
- `--script-help <name>` — show help
- `--script-trace` — debug
- `--script-updatedb` — rebuild script DB

### NSE categories (and counts as of 7.95)
- **`auth`** (~40) — auth-bypass, default-cred, anon-access checks
- **`broadcast`** (~50) — discover hosts via broadcast traffic (mDNS, NBNS, DHCP, UPnP, WSD, Pim, EIGRP)
- **`brute`** (~70) — credential brute force (FTP, SSH, MySQL, MSSQL, Postgres, MongoDB, Redis, HTTP-form, HTTP-basic, RDP, SMB, SMTP, POP3, IMAP, VNC, telnet)
- **`default`** (~80) — sane defaults run on `-sC`
- **`discovery`** (~120) — host/service enumeration (DNS zone-transfer, SMB-shares, HTTP-title, SSL-cert, SNMP-walk, NFS-showmount, finger, rpcinfo)
- **`dos`** (~10) — denial-of-service triggers (don't ship in default)
- **`exploit`** (~15) — actually pop a shell or execute code
- **`external`** (~25) — query third-party services (geoip via MaxMind, whois, asn-query)
- **`fuzzer`** (~10) — protocol fuzzing
- **`intrusive`** — annotation, attached to scripts that send aggressive traffic
- **`malware`** (~15) — backdoor/IRC bot/conficker detection
- **`safe`** (~430) — annotation, no harm to target
- **`version`** (~30) — extra fingerprinting beyond `-sV`
- **`vuln`** (~110) — CVE-specific checkers (Heartbleed, ShellShock, ms17-010 EternalBlue, ms08-067, sambar, sslv2-drown, ftp-vsftpd-backdoor, http-shellshock, http-vuln-cve*, smb-vuln-*)
- **`ics`** (de facto category, 7.95+) — Industrial Control System probes: `hartip-info`, `iec61850-mms`, `profinet-cm-lookup`, `multicast-profinet-discovery`, `modbus-discover`, `s7-info`, `bacnet-info`, `enip-info`, `omron-info`, `fox-info` (Tridium Niagara)

### New / notable NSE scripts added 7.95 → 7.99
- `mikrotik-routeros-version` — query WinBox admin service for RouterOS version (7.95)
- `mikrotik-routeros-username-brute` — brute WinBox usernames via CVE-2024-54772 (7.95)
- `targets-ipv6-eui64` — generate IPv6 targets from MAC file via EUI-64 (7.95)
- `hartip-info`, `iec61850-mms`, `profinet-cm-lookup`, `multicast-profinet-discovery` — ICS family (7.95)
- `rsa-vuln-roca` — Return Of Coppersmith's Attack (CVE-2017-15361) on RSA keys (7.96)
- `smb-vuln-webexec` — Cisco WebEx ActiveX RCE check (7.96)
- `nbns-interfaces` — enumerate NetBIOS interfaces (7.96)
- `openflow-info` — OpenFlow controller fingerprint (7.96)
- `ssh-auth-methods` updated to print pre-auth banner (needs libssh2 1.11.0+)

### Timing
- `-T0` (paranoid) — 5min between probes
- `-T1` (sneaky) — 15s
- `-T2` (polite) — slow, reduce bandwidth/load
- `-T3` (normal) — default
- `-T4` (aggressive) — assume fast & reliable network
- `-T5` (insane) — assume extraordinarily fast network
- `--min-hostgroup` / `--max-hostgroup` — parallelism
- `--min-parallelism` / `--max-parallelism` — probe parallelism
- `--min-rtt-timeout` / `--max-rtt-timeout` / `--initial-rtt-timeout`
- `--max-retries N`
- `--host-timeout 30m`
- `--scan-delay 1s` / `--max-scan-delay 10s`
- `--min-rate 100` / `--max-rate 1000` — pps cap

### IDS/firewall evasion
- `-f` — fragment packets (8-byte fragments)
- `--mtu 24` — custom MTU
- `-D RND:10` or `-D decoy1,decoy2,ME,decoy3` — decoy scanning
- `-S spoofed.src.ip` — source IP spoof
- `-e eth0` — interface bind
- `--source-port 53` — fixed source port (DNS-like)
- `--data <hex>` / `--data-string <text>` / `--data-length N` — packet payload padding
- `--ip-options "L 1.2.3.4 5.6.7.8"` — IP options
- `--ttl N` — TTL spoof
- `--spoof-mac AA:BB:CC:DD:EE:FF` / `Cisco` / `0` (random)
- `--badsum` — bad TCP/UDP checksum (some firewalls let through)
- `--randomize-hosts` — shuffle target order

### Output
- `-oN file.nmap` — normal interactive log
- `-oX file.xml` — XML (the canonical machine format)
- `-oG file.gnmap` — grepable
- `-oS file.txt` — script kiddie (1337 speak)
- `-oA basename` — all four formats with one filename stem
- `-v` / `-vv` / `-vvv` — verbosity
- `-d` / `-dd` — debug
- `--reason` — annotate port state with explanation (RST, no-response, ICMP-unreach)
- `--open` — only show open
- `--packet-trace` — print every packet
- `--iflist` — show interfaces
- `--append-output` — append vs overwrite
- `--resume file.nmap` — resume aborted scan
- `--stylesheet URL` / `--webxml` — embed XSL link in XML output
- `--no-stylesheet`

### Misc
- `-6` — IPv6 mode
- `-V` — version
- `-h` — help
- `--datadir /path/to/nmap-data` — override data files
- `--privileged` / `--unprivileged` — force capability assumption

### Hidden / power features
- `--reason` is the most underused — explains *why* a port is `filtered` (no-response vs ICMP-admin-prohibited)
- **`--max-rate` for paranoia** — limits to N pps for stealth
- `--script-args-file` for credential bundles
- **`nmap -sV --version-trace`** debugs what probe matched what — invaluable for `unknown` services
- **IPv6 idle scan** is broken on most modern kernels (random IPID); reverted to PRNG
- **Idle scan zombie** finding: `--script ipidseq` scans a /24 for hosts with predictable IPIDs

## Engineering hard parts

1. **Raw-socket privilege handling.** Linux needs `CAP_NET_RAW` + `CAP_NET_ADMIN`; macOS needs BPF device perms; Windows needs admin + Npcap. Unprivileged users must transparently fall back to `-sT` (TCP connect). Detection must happen at scan-time per-technique, not at startup.
2. **`IP_HDRINCL` cross-platform.** Linux `setsockopt(IP_HDRINCL)` lets you craft full IPv4 headers. macOS BSD-style sockets disagree on header byte order (host vs network). Windows raw sockets are nerfed since XP SP2 — must use Npcap or WinDivert.
3. **Libpcap integration and the pcap loss problem.** At 50k+ pps, libpcap's userspace ring buffer drops responses. Must `setsockopt(SO_RCVBUF, 8MB)`, use `pcap_set_immediate_mode`, optionally AF_PACKET PACKET_MMAP on Linux for ring-buffer receive. Windows Npcap has its own API quirks.
4. **NSE Lua VM embedding.** Each script runs in a coroutine; the engine multiplexes thousands of in-flight scripts against the same `nsock` event loop. Bridge to async Rust via `mlua` 0.10 + dedicated tokio thread per script, OR coroutine-style with `mlua`'s thread API and our own scheduler.
5. **OS fingerprint DB matching.** ~5300 OS fingerprints with weighted feature scoring. Each fingerprint has 50+ fields (SEQ.GCD, SEQ.SP, SEQ.ISR, SEQ.TI, OPS.O1..O6, WIN.W1..W6, ECN, T1..T7, IE.R). The match algorithm is *not* exact match — it's similarity scoring with per-feature weights from `nmap-os-db`'s `MatchPoints` line. Implementing this correctly is several hundred LOC.
6. **Service-probe DB matching.** `nmap-service-probes` is a custom DSL:
   ```
   Probe TCP GenericLines q|\r\n\r\n|
   rarity 1
   ports 21,23,25,79,80,110,143,...
   match http m|^HTTP/1\.([01]) \d\d\d| p/HTTP/v/$1/
   softmatch unknown m|^.+| p/unknown/
   fallback GetRequest
   ```
   Parser must handle `m|...|s`-style delimited regex with optional `s` (case-insensitive), `i` flag, and the `p/.../v/.../i/.../o/.../d/.../h/.../cpe:/...` field substitutions. Naabu's parser is ~400 LOC and "mostly works." Full parity needs ~800 LOC.
7. **Retransmit timing and congestion control.** Nmap's `ultra_scan` implements its own TCP-friendly congestion control: window sized by detected RTT, slow-start, AIMD on probe loss. Mirrors TCP's NewReno. Naive "send N probes then wait" is 10× slower on lossy networks.
8. **Adaptive RTT estimation.** SRTT/RTTVAR like RFC 6298 but per-host. New hosts inherit a "subnet average" until enough samples accumulate. Without this, scans of /24 take individual hosts' worst-case timeouts.
9. **Probe-response correlation.** SYN scan sends thousands of SYNs and must correlate each SYN-ACK back to `(host, port)`. Strategies: encode (host, port) in TCP source port + sequence number; or maintain a tracking table keyed by 4-tuple. Both need careful rollover handling for >65k in-flight probes.
10. **NSE script timeout coordination.** A script's `nmap.connect()` shares the global timeout budget; a misbehaving script can stall the whole scan. Must enforce per-script max-time with cooperative cancellation.
11. **OS DB drift.** `nmap-os-db` updates monthly upstream; out-of-date DB returns garbage matches on modern Linux kernels (5.x has different IPID behavior than 4.x).
12. **NPSL license.** Distinct from GPL — derivative works can't be incorporated into "proprietary security products" without buying a commercial OEM license. **A clean-room Rust clone is fine** (no upstream code, just protocol/algorithm understanding), but copying the `nmap-service-probes` and `nmap-os-db` files verbatim has implications: data files are LGPL/freely redistributable per upstream README, but document carefully.

## Rust library mapping

| Original Nmap component | Recommended Rust crate | Version | Notes |
| --- | --- | --- | --- |
| C++ option parsing | `clap` (derive) | 4.5 | 200+ flags via `next_help_heading` groups |
| `nsock` (custom async I/O) | `tokio` + `tokio::net` | 1.40 | Replace with idiomatic Rust async |
| Raw socket TX | `pnet` (`pnet_transport`, `pnet_packet`) | 0.35 | Cross-platform raw IPv4/IPv6/TCP/UDP |
| L2 send (ARP, custom MAC) | `pnet::datalink::channel` | 0.35 | Wraps AF_PACKET / BPF / Npcap |
| libpcap receive | `pcap` | 2.x | Bind to libpcap on Linux/mac, Npcap on Windows. Or AF_PACKET PACKET_MMAP for native |
| IPv6 + ND | `pnet::packet::ipv6` + custom NDP | 0.35 | NDP not in pnet by default — hand-roll |
| ICMP echo | `pnet::transport::transport_channel(IcmpTypes::EchoRequest)` | 0.35 | Multi-worker for high-rate |
| TCP connect scan | `tokio::net::TcpStream::connect` + `timeout` | 1.40 | For unprivileged fallback |
| Packet assembly | `etherparse` | 0.15 | Ergonomic builder; alternative to manual pnet layers |
| nmap-service-probes parser | hand-roll `nom` or `winnow` | 0.7 | ~800 LOC parser → `Vec<Probe { string, ports, rarity, total_wait, fallback, matches: Vec<MatchRule> }>` |
| nmap-os-db parser | hand-roll `nom` | 0.7 | Each Fingerprint block: SEQ/OPS/WIN/ECN/T1-T7/U1/IE tests |
| OS match scoring | hand-roll weighted Hamming | — | Use `MatchPoints` line weights |
| NSE Lua VM | `mlua` | 0.10 | Lua 5.4 features; coroutines for parallel scripts |
| NSE per-script async | `tokio::task::JoinSet` with cancel token | 1.40 | One task per script per host |
| Lua `http` lib | wire `mlua` to `reqwest` | 1.10 | Native Rust HTTP |
| Lua `ssl` lib | wire to `rustls` or `native-tls` | 0.23 | Cert details exposed to scripts |
| Lua `dns` lib | wire to `hickory-resolver` | 0.24 | |
| Lua `smb` lib | port `nselib/smb.lua` algorithmically | — | ~3k LOC of Lua; large but doable |
| Regex (probe matches) | `regex` + `regex-syntax` | 1.10 | Nmap uses PCRE — `fancy-regex` if look-around needed |
| CIDR iteration | `ipnet` | 2.10 | `Ipv4Net::hosts()` |
| Hostname resolution | `hickory-resolver` | 0.24 | DoH/DoT/UDP/TCP |
| Rate limiting | `governor` | 0.7 | Global + per-host token buckets |
| XML output | `quick-xml` | 0.36 | Match Nmap's XML schema exactly |
| Output templating | `askama` | 0.14 | For HTML XSLT alternative |
| Timing/RTT | hand-roll SRTT/RTTVAR | — | Mirror RFC 6298 + Nmap's congestion control |
| Resume state | `serde_json` checkpoints | 1.0 | Per-host completion tracking |
| MAC OUI lookup | `mac_oui` or embed `nmap-mac-prefixes` | — | Trivial |
| RPC program-num lookup | embed `nmap-rpc` | — | |
| Logging | `tracing` + `tracing-subscriber` | 0.1 / 0.3 | |

## Bug bounty workflows

**A — initial recon on a single host:** `lancer-nmap -sV --top-ports 1000 -T4 --open -oA recon scanme.acme.com`. Fast top-1000 with service version; `--open` filters noise; `-oA` produces .nmap/.xml/.gnmap.

**B — full audit after naabu found opens:** `naabu -host acme.com -top-ports full -silent | awk -F: '{print $1}' | sort -u | xargs -I{} lancer-nmap -p- -sV -sC -O --reason -oA full-{} {}`. naabu finds opens in seconds; Nmap deep-dives those hosts.

**C — specific service deep dive (TLS):** `lancer-nmap -p 443,8443 --script "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-dh-params,ssl-known-key" -oN tls.txt acme.com`. Cert chain, cipher inventory, Heartbleed (CVE-2014-0160), POODLE, weak DH primes, known-compromised keys.

**D — vuln scan:** `lancer-nmap -sV --script "vuln,exploit" --script-args=unsafe=1 -oA vulnscan target`. Runs all `vuln`/`exploit` scripts; `unsafe=1` allows intrusive ones (Heartbleed actually triggers, ms17-010 actually probes).

**E — web tech discovery:** `lancer-nmap -p 80,443,8080,8443,8000-8090 --script "http-title,http-headers,http-methods,http-enum,http-robots.txt,http-shellshock,http-vuln-*" -oN web.txt acme.com`.

**F — internal subnet sweep:** `lancer-nmap -sn -PR -PE -PS22,80,443 -PA80 -PU161 10.0.0.0/16 -oA alive`. ARP + ICMP + TCP SYN + ACK + UDP-to-SNMP.

**G — IDS-evasive scan:** `lancer-nmap -sS -T1 -f --data-length 25 --source-port 53 -D RND:10 --spoof-mac Apple -p 22,80,443 acme.com`. SYN + T1 + frag + padding + DNS-like source port + 10 decoys + spoofed MAC OUI.

**H — credential brute (with care):** `lancer-nmap -p 22 --script ssh-brute --script-args "userdb=users.txt,passdb=passwords.txt,brute.threads=4" target`.

**What hunters actually find:** default Tomcat creds on `:8080/manager`, anon FTP with leaks, MongoDB/Redis/Elasticsearch wide-open, Jenkins `:8080` anon read, Confluence OGNL (CVE-2023-22515 etc.) via `http-vuln-*`, outdated WordPress via `http-enum`, Heartbleed on forgotten internal hosts, SMB null sessions (`smb-enum-shares`), SNMP `public` (`snmp-info`, `snmp-win32-users`).

## 2024-2026 state

- **Nmap 7.94 → 7.95** (Apr 2024) — adds 7 new NSE scripts (notably `tls-alpn`, `http-fileupload-exploiter` improvements, `ssl-cert-intaddr`); updates 4 (`http-headers`, `http-vuln-cve2017-5638` better Struts coverage, `ssl-enum-ciphers` TLS 1.3 awareness, `smb-os-discovery` SMB3-only handshake fix); adds 1500+ MAC prefixes; updates `nmap-payloads` with new UDP probes for protocols seen on shadow servers; new `--resolve-all` flag (replaces `-A` shortcut to also do all-DNS-name resolution); fixes scan-rate calculation bugs with `--min-rate`.
- **libssh2 update.** Service-version probing for SSH now correctly reports OpenSSH 9.x feature flags (post-quantum cipher negotiation).
- **Npcap on Windows.** Since 7.93, Npcap 1.78+ is bundled in the Windows installer (replaces WinPcap which has been EOL since 2018). The installer asks user to accept Npcap's license (which is more restrictive than Nmap's — note for distros).
- **NSE script DB.** Now ~613 scripts as of master. Active areas: K8s API exposure (`http-kube-*` experimental), Helm chart leakage, OCI registry default-cred checks, modern web app fingerprints (Next.js, SvelteKit, Astro), AWS metadata service abuse from SSRF (script `http-aws-imds`).
- **OS DB.** Frequent additions for Linux 6.x, FreeBSD 14, macOS 14 Sonoma, Windows 11 23H2, iOS 17, modern routers (UniFi Cloud Gateway, MikroTik RouterOS 7), IoT (ESP32, Raspberry Pi 5 default Bookworm).
- **Performance work.** `nsock` has had ongoing perf passes; max practical rate on a single host on a modest workstation is ~30k pps SYN.
- **Active forks worth knowing:**
  - **RustScan** — Rust, ~14k stars, very fast connect scan, then *shells out to nmap* for `-sV`/`-sC`. The "fast first-pass" tool that admits nmap is still king of deep probing.
  - **masscan** — C, packet-rate king (>1M pps), tiny feature set (no `-sV`, no NSE, no OS det).
  - **zmap** / **xmap** — academic Internet-wide scanners; tuned for /0 sweeps.
  - **naabu** — Go (PD); the project we wrap with Lancer. Now ships native `-sV` (May 2026).
- **Community sentiment.** Hunters still chain: `rustscan -a host | nmap -sV -sC` OR `naabu -host x -top-ports 1000 -silent | nmap -sV -sC -iL -`. Nmap is dual-irreplaceable: NSE coverage + OS fingerprint DB are decades of curated work no clone has come close to.
- **NPSL license tension.** Continues to deter some commercial integrations; clean-room rewrites in Rust (this clone) are the increasingly common workaround.

### Research note — 2026-05-30 (upstream catch-up)

Direct check against `nmap.org/changelog.html` + `github.com/nmap/nmap` README. Upstream has moved well beyond 7.95 since the original plan was drafted. The release train now reads **7.95 (Apr 2024) → 7.96 (late 2024) → 7.97 (early 2025) → 7.98 (Aug 2025) → 7.99 (Mar 2026)**. Deltas the clone must cover:

- **DNS engine.** Parallel forward DNS lookups now match the long-standing parallel reverse engine. Resolving 1M hostnames to A + AAAA dropped from ~49h to ~1h. Our `hickory-resolver` worker pool must mirror this throughput. New flags `--unique` (dedupe target IPs post-resolution) and `--resolve-all` (scan every IP a hostname returns) must be wired in `lancer-nmap --cli` and as GUI toggles.
- **Host discovery.** `--discovery-ignore-rst` is now a first-class flag (firewalls that fake RST to fool ping scans). Must surface alongside `-Pn`.
- **OS DB.** Over **6,000 IPv4 fingerprints** (up from ~5,300 at 7.94). New TCP-Options CIDR-range syntax in fingerprint expressions — our `nmap-os-db` parser must accept compressed option ranges. Coverage now extends to iOS 15-16, macOS Ventura/Monterey/Sonoma, Linux 6.1+, OpenBSD 7.1.
- **Service probes.** Total recognized protocols climbed from ~1,100 to **1,246**. New probes for `gRPC`, `MySQLx`, `RemoteMouse`, `Tuya`, WinBox, OpenFlow. **DTLS** (UDP-over-SSL) probing is now built into `-sV`.
- **NSE catalog.** ~613 scripts at 7.95 → ~625+ at 7.99. New ICS family (`hartip-info`, `iec61850-mms`, `profinet-cm-lookup`, `multicast-profinet-discovery`) — we should treat ICS as a de-facto category. New vuln scripts: `rsa-vuln-roca`, `smb-vuln-webexec`. New MikroTik family (`mikrotik-routeros-version`, `mikrotik-routeros-username-brute` via CVE-2024-54772). New target generator `targets-ipv6-eui64`. `ssh-auth-methods` now prints pre-auth banner (needs libssh2 1.11.0+).
- **Performance.** OS scan CPU dropped ~50% via string-op rewrites. Host timeout clock now starts at first probe (not hostgroup start) — material for our `host-timeout` semantics. 7.98 had a reverse-DNS regression that 7.99 fixed; pin our test cases against this corner.
- **Windows.** Npcap bumped 1.75 → **1.87**, now supports ARM64. Visual Studio 2019 baseline. CVE-2025-43715 (NSIS installer race) patched — if we ship an NSIS Windows installer we inherit that mitigation.
- **Ncat.** DTLS for UDP+SSL, `--ssl-servername` for SNI override, half-closed TCP removal, SOCKS4/5 improvements, Unix domain socket support. Our `tools/ncat` clone must catch up to this surface.
- **Nping.** Version-synced with Nmap (no more `0.7.95 alpha` mismatch).
- **Zenmap.** Fully Python 3, universal wheel distribution, dark mode. Our `eframe` GUI already covers dark mode and is single-binary — note as parity-achieved.
- **Memory safety.** 7.97-7.99 fixed several OOB read/write issues in service probes + a SOCKS uninitialized-data bug. Rust eliminates the class — but our `nmap-service-probes` parser still needs `proptest`/fuzz coverage as a regression check.

Plan diff applied above: extended Host-discovery, Service/version, and NSE-categories sections with new flags, the ICS category, and the new-scripts roster. Phases 5, 6, 7 (service probes, OS DB, NSE) and Phase 10 (perf/Npcap) are the ones whose deliverable bar moved most; their week budgets stay accurate but the embedded data-file snapshots must be re-pulled from 7.99 — not 7.95 — at first build.

Sources: `nmap.org/changelog.html`, `github.com/nmap/nmap`, `linuxsecurity.com/news/security-projects/nmap-7-95`, `cybersecuritynews.com/nmap-7-95-released/`, `nmap.org/nsedoc/scripts/`.

### Research note — 2026-05-31 (additional gaps from second-pass deep dive)

Second pass against `nmap.org/changelog.html` + `blog.desdelinux.net/en/nmap-7.99-release-new-features-vpn-zenmap-nse/`. Items missed in the 2026-05-30 pass:

- **VPN-tunnel scanning (Nmap 7.99 headline).** Native scan support over Windows VPN adapters (OpenVPN TAP, WireGuard tun, IKEv2 NDIS) without exiting the tunnel. Our `pnet`/`pcap` capture path must accept TAP-Windows6 + WireGuard-NT virtual adapters as scan interfaces. Add `--vpn-passthrough` Lancer flag that auto-detects and binds to a VPN interface. Add CI integration test using a loopback OpenVPN setup so we never regress this.
- **Multi-target on CLI + `-iL` simultaneously (7.96).** Previously mutually exclusive. Now combinable. Our argparse must accept positional targets AND `-iL` files in the same invocation; merge into one target list, dedupe via the new `--unique` semantics.
- **Forward DNS `/etc/hosts` + localhost handling (7.97).** Forward resolver now consults `/etc/hosts` before going to network DNS, and properly returns `127.0.0.1` for `localhost`. Our `hickory` wrapper currently skips hosts file — must add `hostsfile` crate or equivalent pre-lookup.
- **SSH keyboard-interactive auth (7.98).** `ssh-brute`/`ssh-auth-methods`/`ssh-publickey-acceptance` now support the keyboard-interactive method (RFC 4256), required for many banking/cloud SSH gateways. Our `russh` wrapper must expose the `auth_keyboard_interactive` callback to NSE-equivalent Lua.
- **TLS post-quantum cipher library (7.98 — separate from libssh2 OpenSSH update).** Nmap's bundled OpenSSL 3.0.19 with hybrid X25519MLKEM768 KEM. Service probes that perform TLS handshakes (`ssl-enum-ciphers`, `tls-alpn`, `ssl-cert`, etc.) must enumerate post-quantum hybrid groups. Our `rustls` build must enable the `aws-lc-rs` provider with PQ KEMs.
- **`http-internal-ip-disclosure` IPv6/HTTPS (7.99).** Now probes IPv6 hosts and HTTPS endpoints (was IPv4+HTTP only). Our NSE port must mirror the v6/HTTPS code paths.
- **`hostmap-crtsh` lax-mode filter (7.99).** Lax substring filter was hardened to verify subdomain relationships before adding to the hostmap (previously polluted output with name-collision domains). Port the verification step.
- **`tableaux.tcopy` / `tableaux.shallow_tcopy` raw-copy semantics (7.99).** These NSE library helpers now copy table values **without** invoking `__index` metamethods (used to silently call user metamethods, which broke certain scripts). Our `mlua` NSE-library port must implement raw_copy semantics.
- **`stdnse.make_buffer` preloading (7.99).** Now accepts an initial-content parameter so scripts can prime a parsing buffer with already-known bytes. Our nselib `stdnse.make_buffer` shim must accept the same signature.
- **FTP banner RFC 959 strict parsing (7.99).** `ftp-anon`/`ftp-bounce`/`ftp-vsftpd-backdoor` now reject banners that don't conform to RFC 959 multi-line continuation rules. Was permissive before. Port the strict-mode flag (default ON, opt-out via `--script-args=ftp.lax-banner=1`).
- **`ipOps.expand_ip` IPv6 crash fix (7.99).** Malformed IPv6 with embedded IPv4 (`::ffff:1.2.3.4.5`) previously panicked the Lua VM. Fix is silent-error; we must do the same.
- **OS DB CIDR-range syntax for TCP Options.** The OS fingerprint DSL gained `[Min-Max]` ranges inside TCP Options expressions. Our `nmap-os-db` parser pass must extend the option-byte expression grammar — single-value, list, AND now contiguous range.
- **Service probe **softmatch** override list.** When `-sV --version-all` runs and a softmatch fires, 7.97+ records the softmatched service even if no hardmatch follows. Previously dropped silently. Our service-probe engine must persist softmatches in the result graph.
- **Reverse-DNS performance regression (7.98 → 7.99).** 7.98 had a regression slowing rDNS by ~3x. 7.99 fixed. Pin regression test that resolves 10k IPs with `-R --dns-servers 8.8.8.8` and asserts wall-clock budget.
- **Nping at parity version.** Previously frozen at `0.7.95` alpha while Nmap went to 7.99. Now version-locked. Our `tools/nping` binary should ship at the same `lancer-nmap` version (single workspace version string).
- **NSE category drift.** Two informal sub-categories have emerged in the upstream `script.db` but aren't tagged as formal categories yet: **ICS** (industrial control) and **IoT** (consumer devices, MikroTik routers, Tuya, RemoteMouse). Adopt them as Lancer-formal categories `ics` + `iot` and back-tag the relevant scripts on first build.

Sources: `nmap.org/changelog.html`, `blog.desdelinux.net/en/nmap-7.99-release-new-features-vpn-zenmap-nse/`, `nmap.org/dist/sigs/`, `github.com/nmap/nmap/blob/master/CHANGELOG`.

## AI augmentation ideas

1. **Auto-summarize scan results.** Given the XML output for a 100-host scan, an LLM produces a "what matters" exec summary: highest-risk hosts first, novel ports, services with known CVEs, lateral-movement seeds. Replaces auditor staring at 5000 lines of `gnmap` output.
2. **NSE script suggestion engine.** Given a `service:product:version` triple from `-sV`, AI suggests which NSE scripts to run next ("you found `mysql 8.0.28` on `:3306` — run `mysql-empty-password`, `mysql-enum`, `mysql-vuln-cve2012-2122`, `mysql-info`"). Plus emerging CVEs not yet in NSE.
3. **Service banner translator.** `-sV` returns `unknown` for ~5% of services. AI receives the banner bytes and proposes `(service, product, version)` plus a candidate `match` line to contribute upstream.
4. **Attack-chain hypothesizer.** Given an open-port matrix across many hosts (`host_A: 22, 3306` / `host_B: 22, 8080` / `host_C: 80, 9200`), AI proposes plausible attack chains ("ssh-pivot from A → mysql on A → MySQL dump may have creds for Jenkins on B → Jenkins script-console RCE → access Elasticsearch on C → grep for `aws_secret`").
5. **Adaptive timing recommender.** Watch initial scan response patterns; if many `filtered` and slow RTT, recommend `-T2 --max-retries 2 --max-rate 100`. If clean 10ms RTT subnet, recommend `-T4 --min-rate 5000`.
6. **OS fingerprint enrichment.** When `-O` returns ambiguous match ("Linux 4.X|5.X|6.X — 50%"), AI cross-references TCP features + banner data + open-port profile to narrow to a specific kernel + distro likelihood.
7. **Diff explanation.** Comparing today's scan to last week's: AI describes what changed in plain English ("3 new SSH hosts; port 8080 closed on 4 hosts; new SQL Server on .42 — likely production push").
8. **Custom NSE script scaffolding.** "Write me an NSE script that checks if a host responds to `Cisco SMI` on TCP/4786" — LLM emits a complete `.nse` file using `nselib` correctly. Compile/test loop in the agent.
9. **CVE-aware port prioritization.** "There's an active 0-day on Confluence (`:8090`)" → bump port to front of every queue this week.
10. **Heatmap of unusual ports.** Across N scans, surface the long-tail of weird-port hits (port `:31337`, `:8834`, `:9001`, `:7547`, `:6443`) as anomalies for the analyst to triage.

## Implementation phases

16-week roadmap. Heavy because of raw sockets + NSE + OS DB. Skip OS DB and NSE → MVP in 8 weeks but it's not Nmap anymore.

### Phase 0 — Skeleton + connect scan (Week 1)
Workspace: `lancer-nmap` (bin) + `nmap-core` + `nmap-nse` + `nmap-probes` + `nmap-osdb`. `clap` derive with 200+ flags in `next_help_heading` groups. Target expander (CIDR/range/file/hostname). Port spec (list/range/all/top-N, embed `nmap-services` for frequency). TCP connect scan via `tokio::task::JoinSet` + `governor::Keyed` rate cap. Normal + grepable output. Deliverable: `lancer-nmap -sT --top-ports 100 scanme.nmap.org` returns expected open ports.

### Phase 1 — Host discovery (Week 2)
ICMP echo via `pnet::transport::transport_channel`. TCP SYN/ACK ping. UDP ping (ICMP port-unreachable = alive). ARP ping via `pnet::datalink::channel`. IPv6 ND ping. `-sn`/`-Pn` flags. Capability check (`CAP_NET_RAW`/admin/BPF) with transparent `-sT` fallback. Deliverable: `lancer-nmap -sn -PR -PE -PS22,80,443 10.0.0.0/24` lists alive hosts.

### Phase 2 — SYN stealth scan (Weeks 3-4)
pcap receive in dedicated thread → `mpsc` to async fan-out. Raw socket TX via `pnet` (Linux/macOS) or Npcap raw write (Windows). SYN-ACK correlation: encode (host_idx, port) in source port + ISN low bits. TCP sequencer. Per-host SRTT/RTTVAR + retransmit timer. TCP-friendly congestion control window (mirrors `ultra_scan.cc` start-size 10, AIMD). Deliverable: `lancer-nmap -sS -p 1-65535 scanme.nmap.org` completes in <30s.

### Phase 3 — UDP, NULL, FIN, Xmas, ACK, Window, Maimon, Idle (Week 5)
Each technique is a probe-construction + response-interpretation variant on the scan-engine. UDP needs `nmap-payloads` for service-specific payloads. ACK: RST = unfiltered, no-resp = filtered. Window: inspect TCP window value. Maimon (FIN+ACK): BSD quirk. Idle/zombie (`-sI`): two-step IPID probe. Deliverable: parity with Nmap's port state classification on a known target matrix.

### Phase 4 — Timing templates + congestion control (Week 6)
T0-T5 templates implementing exact upstream knob values (probe-delay, parallelism cap, host-timeout, RTT timer bounds). `--min-rate`/`--max-rate` pps caps. Hostgroup batching (`--min-hostgroup`/`--max-hostgroup`). Adaptive backoff on ICMP rate-limiting bursts. Deliverable: `-T4` ~3× faster than `-T3` on a /24, `-T0` honors 5-minute delays.

### Phase 5 — Service/version detection (-sV) (Weeks 7-8)
Parse `nmap-service-probes` (embed via `include_bytes!`). Build `Vec<Probe>` + `MatchRule { service, regex, fields, cpe }`. Probe-selection algorithm: NULL → port-hinted → rarity sweep → fallback chain. Back-reference substitution (`$1`, `$2`...) in `p/.../v/.../i/.../o/.../d/.../h/.../cpe:/...`. Flags: `--version-intensity 0-9`, `--version-light`, `--version-all`, `--version-trace`, `--allports`. Deliverable: matches Nmap's output for a benchmark of 50 services.

### Phase 6 — OS detection (-O) (Weeks 9-10)
Send 16 OSDET probes (6 SEQ, ECN, T2-T7, IE1+IE2, U1). Measure ~50 features (GCD, SP, ISR, TI/CI/II, TS, OPS, WIN, ECN, T1-T7, IE, U1). Parse `nmap-os-db`. Weighted Hamming match scoring using `MatchPoints` weights; top-N with confidence percentages. `--osscan-limit`, `--osscan-guess`, `--max-os-tries`. Deliverable: plausible OS class with confidence on `scanme.nmap.org`.

### Phase 7 — NSE Lua VM + 50 starter scripts (Weeks 11-13)
Embed `mlua` 0.10 (Lua 5.4). Implement `nmap` lib (`new_socket`, `connect`, `send`, `receive_buf`, `registry`, `port_state`), `stdnse`, `shortport`, plus subset of `http`/`dns`/`ssl`/`creds`/`vulns` (~30 nselib modules) wired to `reqwest`/`rustls`/`hickory`. Script discovery via `script.db` + `categories`/`portrule`/`hostrule`/`action`. Per-script coroutine + timeout + cancel. Port 50 highest-impact scripts: `default` set + `ssl-heartbleed` + `ftp-anon` + `http-title` + `ssh-brute`. Flags: `--script`, `--script-args`, `--script-args-file`, `--script-help`, `--script-trace`, `--script-updatedb`. Deliverable: `lancer-nmap -sV --script default scanme.nmap.org` emits structured output.

### Phase 8 — XML output + resume + Lancer integration (Week 14)
Full XML emitter (`quick-xml`) matching `nmap.dtd` schema exactly. `-oA` writes `.nmap`/`.xml`/`.gnmap` simultaneously. `-oS` script-kiddie. `--resume scan.nmap` skips completed hosts. Library API `Scanner::new(opts).scan(targets).await -> impl Stream<Item=HostResult>` for Lancer §37 Bulk Probe + §35/§36 batch-10 wiring. SARIF emitter (Lancer extension). Deliverable: `-A -oA full target` produces files indistinguishable from upstream Nmap's.

### Phase 9 — IDS/firewall evasion (Week 15)
`-D` decoys (`RND:N` + explicit). `-f` / `--mtu` fragmentation (split TCP across IP frags ourselves — kernel won't). `--data-length`, `--source-port`, `-S`, `--spoof-mac`, `--badsum`, `--ip-options`, `--ttl`, `--randomize-hosts`. Deliverable: `-f -D RND:10 --source-port 53` scans complete and look distinct on the wire.

### Phase 10 — Perf + polish + cross-platform (Week 16)
AF_PACKET PACKET_MMAP receive on Linux (bypass libpcap for >100k pps). Npcap detection on Windows. macOS BPF group guidance. `--iflist`, `--packet-trace`, `--reason`, `--open`, verbosity. Release for musl Linux, glibc Linux, macOS arm64+x86_64, Windows. Healthcheck (`--healthcheck`): capability check, libpcap detection, OS DB age, NSE script count, route table. Deliverable: `cargo install lancer-nmap` works on all four platforms; release zip bundles `nmap-service-probes`, `nmap-os-db`, `nmap-services`, `nmap-payloads`, `nmap-mac-prefixes`, `nmap-rpc`, default `scripts/`.

## CLAUDE.md to seed in the clone repo
```
This project = an Nmap clone in Rust ("lancer-nmap").
- Workspace: lancer-nmap (bin) + nmap-core + nmap-nse + nmap-probes + nmap-osdb.
- Embed nmap-service-probes, nmap-os-db, nmap-services, nmap-payloads, nmap-mac-prefixes, nmap-rpc as data files (verbatim from upstream — they're freely redistributable, the NPSL restriction is on code).
- Raw socket TX via pnet. Receive via pcap (default) or AF_PACKET PACKET_MMAP (Linux fast path).
- pcap receive in dedicated thread → tokio mpsc → result fan-out.
- Per-host SRTT/RTTVAR + TCP-friendly congestion control window (mirror ultra_scan.cc).
- Probe-response correlation: encode (host_idx, port) in TCP source port + ISN low bits.
- NSE via mlua 0.10 (Lua 5.4). One coroutine per script per host, cancellable.
- nmap/stdnse/shortport/http/dns/ssl/creds/vulns Lua libs hand-ported, wired to reqwest/rustls/hickory.
- Default to -sT unprivileged; -sS only if CAP_NET_RAW / admin / BPF.
- T0-T5 timing templates exactly mirror upstream knob values.
- XML output matches nmap.dtd schema exactly so existing parsers work.
- Library API in lib.rs (Scanner::scan returns Stream); Lancer §37 Bulk Probe + §35 Passive Secret Scanner + §36 Auth Bypass import this.
- NPSL is not GPL — keep the code clean-room (no upstream src copying). Data files are fine.
- NEVER block on a slow target — per-port + per-host timeouts + global ctx cancel.
```

---

## GUI (Lancer-standard pattern)

`lancer-nmap` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-nmap-cli` companion binary), but the **plain `lancer-nmap` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-nmap/`, `%APPDATA%\lancer-nmap\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-nmap-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-nmap.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-nmap.exe` (double-click opens the GUI window).
- Linux: `build/lancer-nmap` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-nmap` (bundled into `lancer-nmap.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-nmap/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-nmap.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-nmap-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-nmap
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-nmap.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-nmap-windows-x86_64\bin\lancer-nmap.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-nmap`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates), Npcap SDK (for raw send)
- Linux: `libpcap-dev` (or use the native AF_PACKET path)
- macOS: BPF device group membership

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
