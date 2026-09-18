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

# ANALYZE - merge any number of OPHIRA_*.zip into one fleet view (+ Sigma timeline):
.\Ophira.ps1 -Mode Analyze -AnalyzePath .\collections

# SETUP / LINKS / UPDATERULES:
.\Ophira.ps1 -Mode Setup -SetupTools hayabusa,AmcacheParser,RBCmd
.\Ophira.ps1 -Mode Links
.\Ophira.ps1 -Mode UpdateRules       # refresh hayabusa Sigma rules
```

**Owner handoff:** send the whole folder. They double-click `RUN-OPHIRA.bat`, accept UAC, wait 3-5 minutes. A folder window opens with the result file selected and its path is copied to the clipboard — they paste it into an email. If you pre-fill `ophira.config.txt` (SHARE=/CASE=/ANALYST=), results upload to your share automatically and there's literally nothing to send.

## Collect mode

1. **Flash triage (auto, ~15s)** — process anomalies with **correlation scoring** (LOW/MEDIUM/HIGH verdicts), public IP connections, DNS/ARP, SMB + saved credentials, Defender last detection, **IOC matching**
2. **Deep modules** (menu or presets `Flash|Quick|Standard|Full`):
   - VOLATILE — processes, full hashing, connections, DNS+ARP, sessions, drivers
   - PERSISTENCE — Run keys, startup folders, services, scheduled tasks, WMI subscriptions
   - NETWORK MAP — interfaces, reachable subnets, SMB, saved creds, Kerberos, proxy/WPAD, opt-in active probes
   - LOGS — Security (4625 brute-force candidates), PowerShell 4104, Sysmon (auto-detected), RDP, System 7045, raw evtx export, **detection pack** (hayabusa Sigma timeline + HTML + logon summary)
   - ARTIFACTS — Prefetch, registry hives (SYSTEM/SOFTWARE/SAM/SECURITY, Amcache.hve), UserAssist, SRUM, **chainsaw execution timeline + SRUM + evtx gap detection**
   - CONTEXT — **attacker activity** (PowerShell console history, RDP client targets, recycle bin), **user registry saves** (NTUSER.DAT/UsrClass.dat all profiles), **coverage & context** (Sysmon config, task XML, BITS jobs, domain info), **EZ parsers** (AmcacheParser execution inventory with SHA1×IOC cross-check, RBCmd)
   - DEFENDER — detections, exclusions, status, operational log
   - MEMORY — optional RAM capture (winpmem), optional Volatility 3 quick pass
3. **Packaging** — SHA256 manifest (per file + package + script self-hash + tool inventory), `case.json`, **report.html**, **supertimeline.csv** (all events merged chronologically), ZIP

## FP/TP decision support

- **Correlation score** — evidence stacks per binary: user-path (+1), unsigned (+2), binary deleted (+3), public connection (+2), persistence refs (+2 each), IOC hash hit (+4) → verdict
- **Trusted publishers** — validly-signed binaries from known publishers (or your `tools\trusted.txt`) cap at LOW; IOC hits always override
- **Amcache SHA1 × IOC** — historical execution matched against your IOC list = near-certain TP with a timestamp
- **report.html** — verdict cards, IOC hits, severity-colored Sigma detections, execution highlights, brute-force, VT deep links
- **Raw evidence** — every flag is backed by raw CSV/evtx/hive so any verdict can be verified

## Analyze mode

Merges N case zips → `fleet_report.csv` + **`fleet_report.html`** (host matrix, high-priority findings, cross-host indicator + hash dedup, top fleet Sigma detections) + one merged hayabusa timeline. Accepts legacy `IRCASE_*` packages too.

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

Analyst-side quick wins on a collected case:
```
vol.exe -f memory\physmem.raw windows.pslist.PsList
chainsaw hunt raw\evtx -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

## Design rules

- Read-only; degrades gracefully without admin (logs what failed)
- PowerShell 5.1 baseline (Win 2008 R2+ with updates), no dependencies
- Fallbacks for 2008-era boxes (netstat/arp/ipconfig parsing when cmdlets missing)
- Per-module failure isolation; speed/precision via presets (Flash 15s → Quick 1-2 min → Standard 3-5 min)

## Roadmap

- [ ] Delta collection (re-run shows only NEW findings — pseudo-monitoring without an agent)
- [ ] Fleet baselining auto-allowlist (binary on 40/50 hosts = proposed trusted entry)
- [ ] SIEM export (JSON/CEF) + logging-continuity check
- [ ] YARA scan of flagged binaries
- [ ] Role-based presets (WebServer / DC / Workstation)

## License

MIT
