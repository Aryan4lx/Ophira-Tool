# Ophira

**One PowerShell script** (5.1+, zero dependencies) for Windows incident response: collect evidence on an endpoint, push it across a fleet, analyze the results, and fetch companion tools.

**Read-only by design** — never kills processes, never deletes files, never modifies the system. Only reads and copies.

## One script, five modes

```powershell
# COLLECT (default) - triage the machine this runs on:
.\Ophira.ps1                                        # interactive: flash triage + module menu
.\Ophira.ps1 -NoMenu -Preset Standard -CaseID INC-2026-042
.\Ophira.ps1 -NoMenu -Preset Quick -SharePath \\IR-SRV\collections$
.\Ophira.ps1 -SimpleUI                              # owner-friendly guided run (what the .bat uses)

# DEPLOY - push the kit to remote hosts over WinRM (parallel, 8 by default):
.\Ophira.ps1 -Mode Deploy -ComputerName SRV01,SRV02 -Preset Quick -Credential (Get-Credential)
.\Ophira.ps1 -Mode Deploy -TargetsFile hosts.txt -MaxThreads 16
.\Ophira.ps1 -Mode Deploy -TargetsFile hosts.txt -PushTools   # Kansa-style: push hayabusa, run, remove after

# DELTA - re-run later and see only what CHANGED (pseudo-monitoring without an agent):
.\Ophira.ps1 -NoMenu -Preset Standard           # auto-diffs against the newest previous OPHIRA_*.zip
.\Ophira.ps1 -NoMenu -Preset Quick -DeltaPath .\old-case.zip

# ANALYZE - merge any number of OPHIRA_*.zip into one fleet view (+ Sigma timeline):
.\Ophira.ps1 -Mode Analyze -AnalyzePath .\collections

# SETUP / LINKS / UPDATERULES:
.\Ophira.ps1 -Mode Setup -SetupTools hayabusa,AmcacheParser,RBCmd
.\Ophira.ps1 -Mode Links
.\Ophira.ps1 -Mode UpdateRules       # refresh hayabusa Sigma rules
```

**Owner handoff:** send the whole folder. They double-click `RUN-OPHIRA.bat`, accept UAC, wait 3-5 minutes. A folder window opens with the result file selected and its path is copied to the clipboard — they paste it into an email. If you pre-fill `ophira.config.txt` (SHARE=/CASE=/ANALYST=), results upload to your share automatically and there's literally nothing to send.

## Interactive launcher (role gate + task menu)

Running `.\Ophira.ps1` bare (no flags) first asks **who is using the tool**:

- `[1] Security / IR team` → **task menu**: collect this PC · push & run on remote PCs · analyze collected results · setup tools · update rules · tool links. Deploy and Analyze are guided wizards (targets, credentials, depth, share — plain questions with `[defaults]`, confirm summary, then the existing parallel engine runs). Deploy has an **advanced options** prompt (Full depth, log analysis window, host parallelism). After each task you return to the menu.
- `[2] The security team asked me to run this` → the guided automatic owner flow (same as the .bat).

Flags always win: `-SimpleUI`, `-NoMenu`, or any explicit `-Mode` skips the gate entirely, so automation and `RUN-OPHIRA.bat` behave exactly as before. Non-interactive sessions never see the gate.

`ophira.config.txt` keys:

| Key | Effect |
|---|---|
| `SHARE=` / `CASE=` / `ANALYST=` | collect-mode defaults (as before) |
| `ROLE=responder\|owner` | pre-selects the gate — never asked |
| `TARGETS=` | deploy wizard default (host list or `hosts.txt`) |
| `PRESET=Quick\|Standard` | deploy wizard depth default |
| `PUSHTOOLS=yes\|no` | deploy wizard hayabusa push default |
| `DEPLOYSHARE=` | deploy wizard upload share default |
| `THREADS=` | deploy parallelism default |

Wizard answers are remembered only when you answer **y** to "Remember these answers?" at the end of a deploy — they become the `[defaults]` shown next time.

## Collect mode

1. **Flash triage (auto, ~15s)** — process anomalies with **correlation scoring** (LOW/MEDIUM/HIGH verdicts), public IP connections, DNS/ARP, SMB + saved credentials, Defender last detection, **IOC matching**
2. **Deep modules** (menu or presets `Flash|Quick|Standard|Full`):
   - VOLATILE — processes, full hashing, connections, DNS+ARP, sessions, drivers
   - PERSISTENCE — Run keys, startup folders, services, scheduled tasks, WMI subscriptions, **ASEP deep sweep** (IFEO debuggers incl. sticky-keys, AppInit_DLLs, Winlogon Shell/Userinit/Notify, HKCU COM hijack suspects, netsh helpers, LSA packages, StartupApproved stamps → `asep_sweep.csv` with flags)
   - NETWORK MAP — interfaces, reachable subnets, SMB, saved creds, Kerberos, proxy/WPAD, opt-in active probes, **firewall profiles + `pfirewall.log` copy**
   - LOGS — Security (4625 brute-force candidates), PowerShell 4104, Sysmon (auto-detected), RDP, System 7045, raw evtx export, **detection pack** (hayabusa Sigma timeline with MITRE ATT&CK tags + HTML + logon summary), **YARA scan of flagged/user-path binaries** (bundled rule pack, drop your own `*.yar` into `tools\yara\rules\`), **C2 beaconing analysis** (periodicity/jitter/regularity on Sysmon network events → `beacon_candidates.csv`, feeds verdict + report)
   - ARTIFACTS — Prefetch (copied **+ parsed run counts via PECmd**), registry hives (SYSTEM/SOFTWARE/SAM/SECURITY, Amcache.hve), UserAssist, SRUM, **chainsaw execution timeline + SRUM + evtx gap detection**, **NTFS forensics** (live `$MFT` filtered executable inventory + **USN journal ransomware-burst detection** with suspicious-extension matching via MFTECmd, **all fixed NTFS drives**)
   - CONTEXT — **attacker activity** (PowerShell console history, RDP client targets, recycle bin), **LNK + Jump Lists** (raw save + parse via LECmd/JLECmd), **ShellBags** (folder-browsing history via SBECmd), **browser artifacts** (Chrome/Edge raw save **+ SQLECmd parse**: history/downloads/searches + **IOC domain cross-check**), **certificate store inventory** (T1553: recent/self-signed root CAs flagged), **security posture audit** (LSA protection, SMBv1, RDP+NLA, PowerShell logging, UAC, Defender exclusions, BitLocker, WinRM → `posture.csv`), **user registry saves** (NTUSER.DAT/UsrClass.dat all profiles), **coverage & context** (Sysmon config, task XML, BITS jobs, domain info), **EZ parsers** (AmcacheParser execution inventory with SHA1×IOC cross-check, RBCmd)
   - DEFENDER — detections, exclusions, status, operational log
   - MEMORY — optional RAM capture (winpmem), optional Volatility 3 quick pass (pslist/cmdline/svcscan + **malfind** → verdict signal + netscan on hits)
3. **Packaging** — SHA256 manifest (per file + package + script self-hash + tool inventory), `case.json`, **compromise verdict** (`verdict.json`: 5-level verdict + coverage-weighted confidence + signals + caveats), `report.html`, **supertimeline.csv** (all events merged chronologically), **delta_new.csv** (new findings vs previous collection), **siem_export.ndjson** (Splunk/Elastic-ready records incl. verdict/beacon/mass-modification), **attack_layer.json** (MITRE ATT&CK Navigator layer — load at navigator.mitre.org), **logging_gaps.csv** (log cleared/stopped + evtx gap tamper check), ZIP

## Compromise verdict (v2.6)

Every collection ends with `Get-CompromiseVerdict` correlating all findings into one call:

- **5 levels**: `COMPROMISED` → `LIKELY COMPROMISED` → `SUSPICIOUS` → `NO EVIDENCE OF COMPROMISE` → `INCONCLUSIVE`
- **Signal floors** — amcache IOC hit or high/critical YARA hit forces COMPROMISED; live IOC hit, critical Sigma, **C2 beaconing (high)** or **USN ransomware-style mass file modification** force ≥ LIKELY COMPROMISED; critical Sigma / HIGH process verdict / Defender history / log-tamper events / **uncommon persistence (IFEO/AppInit/Winlogon/netsh/LSA)** / **memory malfind** / **IOC domain in browser history** force ≥ SUSPICIOUS; two independent strong signals escalate to LIKELY COMPROMISED
- **Confidence %** = weighted coverage of evidence sources actually collected (volatile, persistence, evtx, Sigma, amcache, prefetch, USN journal, MFT timeline, YARA, Sysmon, RAM; −15 if not elevated)
- **Caveats** state what could *not* be ruled out (no Sysmon, short log window, no RAM capture...) — i.e., what would change the verdict
- Surfaced in: console summary, `verdict.json`, `case.json`, and a plain-language RESULT line on the owner screen

Verdicts are correlation heuristics over collected evidence — verify against raw CSV/evtx before acting.

## Delta collection (pseudo-monitoring)

Run Ophira again on the same box days later: it auto-finds the previous case, compares flagged processes / tasks / services / autoruns / Sigma alerts, and reports **only what's NEW** — in the console, the report ("NEW since previous collection"), the SIEM export, and the SimpleUI owner screen. Point-in-time triage becomes a lightweight watch without installing anything.

## FP/TP decision support

- **Correlation score** — evidence stacks per binary: user-path (+1), unsigned (+2), binary deleted (+3), public connection (+2), persistence refs (+2 each), IOC hash hit (+4) → verdict
- **Trusted publishers** — validly-signed binaries from known publishers (or your `tools\trusted.txt`) cap at LOW; IOC hits always override
- **Amcache SHA1 × IOC** — historical execution matched against your IOC list = near-certain TP with a timestamp
- **report.html** — **compromise assessment report v2**: verdict banner with confidence bar + contributing signals + "what would change this verdict" caveats, evidence coverage table, **MITRE ATT&CK grid** (tactic chips + technique table from hayabusa tags, with cannot-rule-out telemetry notes), findings grouped by tactic, defanged copy-ready IOC list, YARA findings, logon/account analysis, persistence inventory, **file-system evidence section** (USN mass-modification windows + ransomware extensions, most-run prefetch, MFT user-path executables), **C2 beaconing candidates**, **host snapshot** (AV state + detections, stored credentials, outbound RDP, BITS, malfind, browser IOCs, **security posture audit**), recommendations incl. **hardening actions from BAD posture findings**, **evidence index** (every CSV with row counts + what to look for — the map into all collected artifacts), VT deep links
- **Raw evidence** — every flag is backed by raw CSV/evtx/hive so any verdict can be verified

## Analyze mode

Merges N case zips → `fleet_report.csv` + **`fleet_report.html`** (**per-host verdicts inherited from each case's `verdict.json`**: verdict chips, worst-first host matrix, ATTENTION FIRST list, **fleet ATT&CK roll-up** with `attack_layer_fleet.json`) + **`fleet_hosts.csv`** (host/verdict/confidence for SIEM), high-priority findings, cross-host indicator + hash dedup, top fleet Sigma detections, **baselining proposals** + one merged hayabusa timeline. Accepts legacy `IRCASE_*` packages too (shown as "no verdict").

**Fleet baselining:** publishers present on ≥60% of hosts with zero HIGH verdicts are written to `proposed_trusted.txt` — review once, merge into `tools\trusted.txt`, and your false-positive rate drops with every host you scan.

## Companion tools

Bundled in `tools\` in this repo (self-contained kit). Refresh via `-Mode Setup` or each project's releases:

| Tool | Enables | Download |
|---|---|---|
| winpmem | RAM capture (7.1) | https://github.com/Velocidex/winpmem/releases |
| hayabusa | Sigma timeline (4.6) + fleet + `-Mode UpdateRules` | https://github.com/Yamato-Security/hayabusa/releases |
| Volatility 3 | offline memory analysis + optional on-host pass | https://github.com/volatilityfoundation/volatility3/releases |
| chainsaw | execution timeline, SRUM, evtx gaps (5.4) + offline Sigma | https://github.com/WithSecureOpenSource/chainsaw/releases |
| AmcacheParser (EZ) | execution inventory + SHA1×IOC (8.4) | https://github.com/EricZimmerman/AmcacheParser/releases |
| RBCmd (EZ) | recycle bin parse (8.4) | https://github.com/EricZimmerman/RBCmd/releases |
| MFTECmd (EZ) | live $MFT + USN journal forensics, all NTFS drives (5.5) | https://download.ericzimmermanstools.com/MFTECmd.zip |
| PECmd (EZ) | prefetch run counts (5.1) | https://download.ericzimmermanstools.com/PECmd.zip |
| LECmd / JLECmd (EZ) | LNK + Jump List parse (8.5) | https://download.ericzimmermanstools.com/LECmd.zip |
| SBECmd (EZ) | ShellBags folder-browsing history (8.8) | https://download.ericzimmermanstools.com/SBECmd.zip |
| SQLECmd (EZ, .NET 9) | browser History/Downloads SQLite parse (8.7) | https://download.ericzimmermanstools.com/net9/SQLECmd.zip |
| yara-x | YARA scan of flagged binaries (4.7), MIT rule pack bundled | https://github.com/VirusTotal/yara-x/releases |

Analyst-side quick wins on a collected case:
```
vol.exe -f memory\physmem.raw windows.pslist.PsList
chainsaw hunt raw\evtx -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

## Design rules

- Read-only; degrades gracefully without admin (logs what failed)
- PowerShell 5.1 baseline (Win 2008 R2+ with updates), no dependencies. Hosts with PowerShell < 5.0 get a clear fail-fast message with remote-collection alternatives instead of cryptic errors
- Fallbacks for 2008-era boxes (netstat/arp/ipconfig parsing when cmdlets missing)
- Per-module failure isolation; speed/precision via presets (Flash 15s → Quick 1-2 min → Standard 3-5 min)
- **Phased parallel collection** — volatile first (order of volatility), then independent categories in parallel runspaces, then heavy analytics (hayabusa/chainsaw/EZ) in parallel; `-Sequential` forces the old serial behavior
- **hayabusa time-boxing** — scans only the configured log range (`--time-offset`) with eid-filter (`-E`); per-module timings recorded in `case.json` (`ModuleTimings`)
- Native tools launched console-less (`.NET CreateNoWindow`) — avoids console handshake stalls and runspace pipe overhead

## Roadmap

- [x] YARA scan of flagged binaries (module 4.7 + bundled `ophira-pack.yar`)
- [x] C2 beaconing detection (module 4.8, v2.9)
- [x] NTFS forensics: $MFT + USN ransomware bursts + prefetch/LNK parsing (v2.10)
- [x] Persistence sweep + quick wins: ASEP, cert store, firewall log, browser copy (v2.11)
- [x] Report completeness: evidence index + snapshots; ATT&CK Navigator layers; SIEM verdict/beacon/USN records (v2.12)
- [x] Research-driven Phase F: posture audit w/ hardening recs, ShellBags, browser parse + IOC xref, ransomware extensions, multi-drive NTFS, malfind quick-pass (v2.13)
- [ ] Real-host pilot run (validate hayabusa timing + MFTECmd on live volume)
- [ ] Role-based presets (WebServer / DC / Workstation)

## License

MIT
