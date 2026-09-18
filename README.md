# IR-Triage

**One PowerShell script** (5.1+, zero dependencies) for Windows incident response: collect evidence on an endpoint, push it across a fleet, analyze the results, and fetch companion tools.

**Read-only by design** — never kills processes, never deletes files, never modifies the system. Only reads and copies.

## One script, five modes

```powershell
# COLLECT (default) - triage the machine this runs on:
.\IR-Triage.ps1                                        # interactive: flash triage + module menu
.\IR-Triage.ps1 -NoMenu -Preset Standard -CaseID INC-2026-042
.\IR-Triage.ps1 -NoMenu -Preset Quick -SharePath \\IR-SRV\collections$

# DEPLOY - push the kit to remote hosts over WinRM, pull zips back (or use -SharePath):
.\IR-Triage.ps1 -Mode Deploy -ComputerName SRV01,SRV02 -Preset Quick -Credential (Get-Credential)

# ANALYZE - merge any number of IRCASE_*.zip into one fleet view (+ optional Sigma timeline):
.\IR-Triage.ps1 -Mode Analyze -AnalyzePath .\collections

# SETUP - download companion tools straight into tools\ :
.\IR-Triage.ps1 -Mode Setup                    # prompts for each
.\IR-Triage.ps1 -Mode Setup -SetupTools hayabusa,winpmem

# LINKS - print download links for all companion tools:
.\IR-Triage.ps1 -Mode Links
```

Owner handoff: send the whole folder, they double-click `RUN-TRIAGE.bat`, accept UAC, send back the zip. No PowerShell knowledge needed.

## Collect mode

1. **Flash triage (auto, ~15s)** — process anomalies with **correlation scoring** (LOW/MEDIUM/HIGH verdicts), public IP connections, DNS/ARP, SMB + saved credentials, Defender last detection, **IOC matching**
2. **Deep modules** (menu or presets `Flash|Quick|Standard|Full`):
   - VOLATILE — processes, full hashing, connections, DNS+ARP, sessions, drivers
   - PERSISTENCE — Run keys, startup folders, services, scheduled tasks, WMI subscriptions
   - NETWORK MAP — interfaces, reachable subnets, SMB, saved creds, Kerberos, proxy/WPAD, opt-in active probes
   - LOGS — Security (4625 brute-force candidates), PowerShell 4104, Sysmon (auto-detected), RDP, System 7045, **raw evtx export**, **detection pack** (hayabusa Sigma timeline + HTML report + logon summary)
   - ARTIFACTS — Prefetch, registry hives (SYSTEM/SOFTWARE/SAM/SECURITY, Amcache.hve), UserAssist, SRUM, **execution history** (chainsaw shimcache+amcache timeline, SRUM analysis, evtx gap/tamper detection)
   - DEFENDER — detections, exclusions, status, operational log
   - MEMORY — optional RAM capture (winpmem), optional Volatility 3 quick pass
3. **Packaging** — SHA256 manifest per file + package hash, `case.json` metadata, **report.html** (verdict cards, IOC hits, top Sigma detections, execution timeline, VT links), ZIP (memory dump excluded, hashed separately)

## FP/TP decision support

- **Correlation score** — evidence stacks per binary: user-path (+1), unsigned (+2), binary deleted (+3), public connection (+2), persistence refs (+2 each), IOC hash hit (+4) → verdict. A lone Electron app in AppData = LOW; process+task+service+connection+IOC = HIGH
- **Trusted publishers** — validly-signed binaries from known publishers (or your own list in `tools\trusted.txt`, see sample) get capped at LOW — kills updater/Electron false positives; an IOC hit always overrides
- **report.html** — one page per case: verdict cards with evidence chips, IOC hits, severity-colored Sigma detections, execution-timeline highlights, brute-force candidates — every hash/IP/domain gets a VirusTotal deep link
- **IOC matching** — hashes/IPs/domains in `tools\iocs.txt` (see `tools/iocs.txt.sample`); hits print red and land in `flash_ioc_hits.csv`
- **Raw evidence** — every flag is backed by raw CSV/evtx/hive so any verdict can be verified

## Companion tools

| Tool | Enables | Download |
|---|---|---|
| winpmem | RAM capture (module 7.1) | https://github.com/Velocidex/winpmem/releases |
| hayabusa | Sigma timeline on-host (module 4.6) + fleet-wide (Analyze mode) | https://github.com/Yamato-Security/hayabusa/releases |
| Volatility 3 | offline memory analysis (`pslist`, `netscan`, `malfind`) + optional on-host quick pass | https://github.com/volatilityfoundation/volatility3/releases |
| chainsaw | offline Sigma hunt + shimcache/amcache execution timeline | https://github.com/WithSecureOpenSource/chainsaw/releases |
| Velociraptor | if you later need always-on agent-based DFIR | https://github.com/Velocidex/velociraptor/releases |

`-Mode Setup` downloads and installs the first four into `tools\` automatically (zips extract to `tools\<name>\`, found recursively). Manual placement anywhere in `tools\` works too. **This repo ships with the tools pre-installed in `tools\`** — the kit is self-contained; keep them updated via `-Mode Setup` or each tool's `update-rules`/release page.

Analyst-side quick wins on a collected case:
```
vol.exe -f memory\physmem.raw windows.pslist.PsList
chainsaw analyse shimcache raw\registry\SYSTEM.hiv -a raw\registry\Amcache.hve
chainsaw hunt raw\evtx -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

## Analyze mode

Merges N case zips → `fleet_report.csv` + **`fleet_report.html`** (host summary, high-priority findings, cross-host indicator matrix) + `fleet_summary.txt`; optionally runs one hayabusa Sigma timeline across all hosts' evtx (auto-discovered in `tools\` or pass `-HayabusaPath`).

## Design rules

- Read-only; degrades gracefully without admin (logs what failed)
- PowerShell 5.1 baseline (Win 2008 R2+ with updates), no dependencies
- Fallbacks for 2008-era boxes (netstat/arp/ipconfig parsing when cmdlets missing)
- Per-module failure isolation — one broken module never kills the run

## Roadmap

- [ ] HTML report with verdict rendering
- [ ] Chainsaw-style shimcache/amcache inline parsing
- [ ] Role-based presets (WebServer / DC / Workstation)
- [ ] Optional YARA scan of flagged binaries

## License

MIT
