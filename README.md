# Ophira

**One PowerShell script** (5.1+, zero dependencies) for Windows incident response: collect evidence on an endpoint, push it across a fleet, analyze the results, and fetch companion tools.

## Get the kit

`git clone` is the reliable path (long file paths in the bundled rule packs exceed Windows' 260-char ZIP limit in some locations):

```
git clone https://github.com/Aryan4lx/Ophira-Tool.git
```

If you download the ZIP instead, do **not** use Explorer's built-in extractor - use either:

```
tar -xf Ophira-Tool-main.zip        # tar.exe ships with Windows 10+ and handles long paths
```

or 7-Zip ("Extract" from the context menu).

**Read-only by design** — never kills processes, never deletes files, never modifies the system. Only reads and copies.

## One script, every role covered

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

# SETUP / LINKS / UPDATERULES / TUNE / PARSE:
.\Ophira.ps1 -Mode Setup -SetupTools hayabusa,AmcacheParser,RBCmd,loldrivers
.\Ophira.ps1 -Mode Links
.\Ophira.ps1 -Mode UpdateRules       # refresh hayabusa Sigma rules
.\Ophira.ps1 -Mode Tune              # pick noisy Sigma rules -> exclude/demote (travels with -PushTools)
.\Ophira.ps1 -Mode Parse -ParsePath .\OPHIRA_HOST_20260926_120000.zip   # finish a case on YOUR pc
.\Ophira.ps1 -Mode Process -ParsePath .\OPHIRA_HOST_20260926_120000.zip -ProcessName evil.exe   # pivot on one process
```

**Owner handoff:** send the whole folder. They double-click `RUN-OPHIRA.bat`, accept UAC, wait 3-5 minutes. A folder window opens with the result file selected and its path is copied to the clipboard — they paste it into an email. If you pre-fill `ophira.config.txt` (SHARE=/CASE=/ANALYST=), results upload to your share automatically and there's literally nothing to send.

## Interactive launcher (role gate + task menu)

Running `.\Ophira.ps1` bare (no flags) first asks **who is using the tool**:

- `[1] Security / IR team` → **task menu**: collect this PC · push & run on remote PCs · analyze collected results · setup tools · update rules · **tune Sigma rules** · tool links · **finish a collected case (analyst-side parse)** · **analyze a single process**. Deploy and Analyze are guided wizards (targets, credentials, depth, share — plain questions with `[defaults]`, confirm summary, then the existing parallel engine runs). Deploy has an **advanced options** prompt (Full depth, log analysis window, host parallelism). After each task you return to the menu.
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
   - LOGS — Security (4625 brute-force candidates), PowerShell 4104, Sysmon (auto-detected, **EID 3 network + EID 22 DNS**), RDP, System 7045, raw evtx export, **detection pack** (hayabusa Sigma timeline with MITRE ATT&CK tags + HTML + logon summary with RDP sessions + **base64/obfuscated PowerShell command recovery**), **YARA scan of flagged/user-path binaries** (bundled rule pack, drop your own `*.yar` into `tools\yara\rules\`), **C2 beaconing analysis** (periodicity/jitter/regularity on Sysmon network **and DNS** events → `beacon_candidates.csv` + `dns_beacon_candidates.csv`, feeds verdict + report)
   - ARTIFACTS — Prefetch (copied **+ parsed run counts via PECmd**), registry hives (SYSTEM/SOFTWARE/SAM/SECURITY, Amcache.hve), UserAssist, SRUM, **chainsaw execution timeline + SRUM + evtx gap detection**, **NTFS forensics** (live `$MFT` filtered executable inventory + **USN journal ransomware-burst detection** with suspicious-extension matching via MFTECmd, **all fixed NTFS drives**)
   - CONTEXT — **attacker activity** (PowerShell console history, RDP client targets, recycle bin), **LNK + Jump Lists** (raw save + parse via LECmd/JLECmd), **ShellBags** (folder-browsing history via SBECmd), **browser artifacts** (Chrome/Edge raw save **+ SQLECmd parse**: history/downloads/searches + **IOC domain cross-check**), **certificate store inventory** (T1553: recent/self-signed root CAs flagged), **security posture audit** (LSA protection, SMBv1, RDP+NLA, PowerShell logging, UAC, Defender exclusions, BitLocker, WinRM → `posture.csv`), **LOLDrivers hash check** (all drivers SHA256-hashed × malicious/vulnerable datasets → `loldrivers_hits.csv`, malicious = verdict signal), **user registry saves** (NTUSER.DAT/UsrClass.dat all profiles), **coverage & context** (Sysmon config, task XML, BITS jobs, domain info), **EZ parsers** (AmcacheParser execution inventory with SHA1×IOC cross-check, RBCmd)
   - DEFENDER — detections, exclusions, status, operational log
   - MEMORY — optional RAM capture (winpmem), optional Volatility 3 quick pass (pslist/cmdline/svcscan + **malfind** → verdict signal + netscan on hits)
3. **Packaging** — SHA256 manifest (per file + package + script self-hash + tool inventory), `case.json`, **compromise verdict** (`verdict.json`: 5-level verdict + coverage-weighted confidence + signals + caveats), `report.html`, **supertimeline.csv** (all events merged chronologically), **delta_new.csv** (new findings vs previous collection), **siem_export.ndjson** (Splunk/Elastic-ready records incl. verdict/beacon/mass-modification), **attack_layer.json** (MITRE ATT&CK Navigator layer — load at navigator.mitre.org), **logging_gaps.csv** (log cleared/stopped + evtx gap tamper check), ZIP

## Endpoint vs analyst-side parsing

The bundled forensic parsers run **on the endpoint during collection** so the case zip arrives with ready-made CSVs, verdict and report. Their inputs are **also preserved raw**, so anything the endpoint couldn't finish (tool missing, .NET too old, module skipped, non-admin) can be finished on your PC:

```
.\Ophira.ps1 -Mode Parse -ParsePath .\OPHIRA_HOST_20260926_120000.zip
```

One command re-runs the raw-driven parsers from *your* kit (AmcacheParser, RBCmd, PECmd, LECmd, JLECmd, SQLECmd + chainsaw + the hayabusa detection pack) against the case's `raw\` evidence, then regenerates supertimeline, verdict, SIEM export and `report.html`. Zip inputs are repacked in place.

Every collection also writes **`csv\parse_needed.csv`**: for each missing artifact it names the parser, the .NET requirement, whether the raw evidence is even in the zip, and the exact way to finish it — so ".NET 9 missing on endpoint" is never confused with "module skipped". `case.json` records the endpoint's .NET inventory (`DotNet`).

| Parser | .NET need | Raw input shipped in the zip |
|---|---|---|
| AmcacheParser / RBCmd / PECmd / LECmd / JLECmd / SBECmd / MFTECmd | .NET 4.x (OS-built-in on Win8.1+) | yes (except MFTECmd: live-volume only) |
| SQLECmd | .NET 9 desktop runtime (often absent - parse analyst-side) | yes (`raw\browser\`) |
| hayabusa / chainsaw (Rust) | none | yes (`raw\evtx\`, `raw\registry\`) |

Full NTFS preservation: the `Full` preset additionally keeps the **unfiltered** `mft_full_<drive>.csv` / `usn_full_<drive>.csv` under `raw\analysis\` (auto-skipped if the endpoint has <10 GB free) - big servers on Standard stay lean, deep dives get everything.

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
- **`-Mode Tune`** — the FP feedback loop: shows your top-hit Sigma rules with counts, pick offenders, exclude them entirely or demote to informational. Written into hayabusa's native `exclude_rules.txt` / `level_tuning.txt`, so the tuning travels with Deploy `-PushTools` to every host you push to. `[V]`iew / `[ED]`it open the rule's actual .yml in Notepad so you can see (or adjust) exactly what it matches before deciding
- **Sigma rule logs** — every matched rule gets its own event log: `csv\sigma_rules\<rule>.csv` (time, host, event ID, RecordID, hayabusa-extracted details) + an index, and `report.html` lets you expand each rule to read the matched events inline. RecordID locates the exact record in the shipped `raw\evtx\`
- **`-Mode Process`** — single-process pivot: point it at a case (zip or folder) with a name, path fragment or hash; it searches every collected CSV, auto-pivots hash → path → name, groups what the evidence says (processes, network, execution history, persistence, YARA, Sigma, ...) and writes `csv\process_pivot.csv`
- **Amcache SHA1 × IOC** — historical execution matched against your IOC list = near-certain TP with a timestamp
- **report.html** — **compromise assessment report v2**: verdict banner with confidence bar + contributing signals + "what would change this verdict" caveats, evidence coverage table, **MITRE ATT&CK grid** (tactic chips + technique table from hayabusa tags, with cannot-rule-out telemetry notes), findings grouped by tactic, defanged copy-ready IOC list, YARA findings, logon/account analysis, **recovered attacker commands** (decoded base64/obfuscated PowerShell), persistence inventory, **file-system evidence section** (USN mass-modification windows + ransomware extensions, most-run prefetch, MFT user-path executables), **C2 beaconing candidates (connections + DNS)**, **driver check (LOLDrivers)**, **host snapshot** (AV state + detections, stored credentials, outbound RDP, BITS, malfind, browser IOCs, **security posture audit**), recommendations incl. **hardening actions from BAD posture findings**, **evidence index** (every CSV with row counts + what to look for — the map into all collected artifacts), VT deep links
- **Raw evidence** — every flag is backed by raw CSV/evtx/hive so any verdict can be verified

## Analyze mode

Merges N case zips → `fleet_report.csv` + **`fleet_report.html`** (**per-host verdicts inherited from each case's `verdict.json`**: verdict chips, worst-first host matrix, ATTENTION FIRST list, **fleet ATT&CK roll-up** with `attack_layer_fleet.json`) + **`fleet_hosts.csv`** (host/verdict/confidence for SIEM), high-priority findings, cross-host indicator + hash dedup, top fleet Sigma detections, **baselining proposals** + one merged hayabusa timeline (**deduped via `sort-csv`** - overlapping/backup evtx no longer double-count). Accepts legacy `IRCASE_*` packages too (shown as "no verdict").

**Fleet baselining:** publishers present on ≥60% of hosts with zero HIGH verdicts are written to `proposed_trusted.txt` — review once, merge into `tools\trusted.txt`, and your false-positive rate drops with every host you scan.

## Companion tools

Two folders — **`tools\endpoint\`** is what `Deploy -PushTools` ships to remote hosts (hayabusa, chainsaw, yara, the EZ parsers, LOLDrivers lists, winpmem ≈ 72 MB zipped, 9979 files); **`tools\analyst\`** never leaves your PC (volatility3 memory analysis, SQLECmd browser parser — it needs .NET 9 which endpoints rarely have; its targets are parsed analyst-side via `-Mode Parse`). Ophira finds tools recursively in both. Refresh via `-Mode Setup` or each project's releases:

| Tool | Enables | Download |
|---|---|---|
| winpmem | RAM capture (7.1) — endpoint | https://github.com/Velocidex/winpmem/releases |
| hayabusa | Sigma timeline (4.6) + fleet + `-Mode UpdateRules` — endpoint | https://github.com/Yamato-Security/hayabusa/releases |
| Volatility 3 | offline memory analysis + optional on-host pass — analyst | https://github.com/volatilityfoundation/volatility3/releases |
| chainsaw | execution timeline, SRUM, evtx gaps (5.4) + offline Sigma — endpoint | https://github.com/WithSecureOpenSource/chainsaw/releases |
| AmcacheParser (EZ) | execution inventory + SHA1×IOC (8.4) — endpoint | https://github.com/EricZimmerman/AmcacheParser/releases |
| RBCmd (EZ) | recycle bin parse (8.4) — endpoint | https://github.com/EricZimmerman/RBCmd/releases |
| MFTECmd (EZ) | live $MFT + USN journal forensics, all NTFS drives (5.5) — endpoint | https://download.ericzimmermanstools.com/MFTECmd.zip |
| PECmd (EZ) | prefetch run counts (5.1) — endpoint | https://download.ericzimmermanstools.com/PECmd.zip |
| LECmd / JLECmd (EZ) | LNK + Jump List parse (8.5) — endpoint | https://download.ericzimmermanstools.com/LECmd.zip |
| SBECmd (EZ) | ShellBags folder-browsing history (8.8) — endpoint | https://download.ericzimmermanstools.com/SBECmd.zip |
| SQLECmd (EZ, .NET 9) | browser History/Downloads SQLite parse (8.7) — analyst (.NET 9) | https://download.ericzimmermanstools.com/net9/SQLECmd.zip |
| LOLDrivers datasets | malicious/vulnerable driver hash xref (8.10) — endpoint | https://github.com/magicsword-io/LOLDrivers |
| yara-x | YARA scan of flagged binaries (4.7), MIT rule pack bundled — endpoint | https://github.com/VirusTotal/yara-x/releases |

**Push tools packaging is AV-resilient**: Defender flags a few bundled Sigma `.yml` files (rules that *describe* Defender tampering) and can block bulk archiving - `-PushTools` zips per-file and skips whatever AV objects to, with the skip count shown.

**KAPE and Kansa:** Ophira deliberately replaces Kansa (push/run/remove + log modules are built in, with verdicts and fleet on top). [KAPE](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape) is a great **complement, not a replacement**: when one box needs deep full-disk acquisition beyond triage scope, run KAPE separately on that box - our `raw\` evidence covers the common artifacts so you only escalate when needed.

**Analyst-side quick wins on a collected case:**
```
vol.exe -f memory\physmem.raw windows.pslist.PsList
chainsaw hunt raw\evtx -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

## Deploy Sysmon (recommended config)

`tools\sysmon\ophira-sysmon.xml` is a lean, commented Sysmon config that enables exactly the telemetry Ophira's hunt rules consume: process creations with hashes (1), file-creation-time changes (2), network connections (3), image loads (7), **ProcessAccess filtered to lsass targets** (10 - the LSASS-dump signal without the usual noise), **registry events filtered to hot keys** (Run/IFEO/ms-settings/services - UAC-bypass + persistence), and DNS queries (22).

Ophira never installs anything (read-only by design) - deploy it yourself on hosts you want full telemetry from, elevated, once per endpoint:
```
sysmon64.exe -accepteula -i ophira-sysmon.xml
```
When a case shows Sysmon running but no ProcessAccess/registry telemetry arrives, the report's hunt section flags the config gap and points at this file. Stock Sysmon or a default-swift config also works - the filter above just keeps volume sane while preserving every event class Ophira parses.

## Design rules

- Read-only; degrades gracefully without admin (logs what failed)
- **Seeing odd ASCII art when you launch `. \Ophira.ps1` directly?** That is your own PowerShell profile (`$PROFILE` - it loads for every script started in that console), not Ophira. `RUN-OPHIRA.bat` launches with `-NoProfile`, so the owner flow never shows it
- PowerShell 5.1 baseline (Win 2008 R2+ with updates), no dependencies. Hosts with PowerShell < 5.0 get a clear fail-fast message with remote-collection alternatives instead of cryptic errors
- Fallbacks for 2008-era boxes (netstat/arp/ipconfig parsing when cmdlets missing)
- Per-module failure isolation; speed/precision via presets (Flash 15s → Quick 1-2 min → Standard 3-5 min)
- **Phased parallel collection** — volatile first (order of volatility), then independent categories in parallel runspaces, then heavy analytics (hayabusa/chainsaw/EZ) in parallel; `-Sequential` forces the old serial behavior
- **hayabusa time-boxing** — scans only the configured log range (`--time-offset`) with eid-filter (`-E`); per-module timings recorded in `case.json` (`ModuleTimings`)
- Native tools launched console-less (`.NET CreateNoWindow`) — avoids console handshake stalls and runspace pipe overhead

## OS support

| OS | Status |
|---|---|
| Windows 10/11, Server 2016-2025 (PowerShell 5.1) | Full support |
| Windows 8/8.1, Server 2012/R2 (PS 5.0/5.1) | Full support |
| Windows 7 SP1 / 2008 R2 **with WMF 5.1** (needs .NET 4.5.2) | Supported - OS cmdlets missing on Win7 (Get-Net*, Get-Smb*, Defender) are guard-wrapped and skip gracefully; SQLECmd needs .NET 9 which does not install on Win7, so browser artifacts finish analyst-side via `-Mode Parse` |
| Any host with PowerShell < 5.0 (stock Win7 = PS 2.0) | Blocked by design with a clear fail-fast message (v2.21: the whole script parses under PS 2.0, so the friendly gate + WinRM-push guidance renders everywhere instead of parser errors) |

Role telemetry follows the host, not the preset: a DC auto-enables module 4.9 (Kerberos/DS), an IIS box auto-enables 8.12 (web artifacts) under Standard/Full; `-Preset DC` / `-Preset WebServer` force them on.

## Testing on a VM (safe demo recipe)

Snapshot first, host-only networking is enough (nothing below needs internet), revert after.

**Recommended MalwareBazaar sample: Mimikatz** (browse the `mimikatz` tag) - it lights up every detection surface:

1. Before running the collection, add the sample's hashes to `tools\iocs.txt` (one per line - the SHA256 **and** SHA1 shown on the MalwareBazaar page):
   ```
   <sha256 of sample>
   <sha1 of sample>
   ```
2. Run the sample on the VM, then collect (`RUN-OPHIRA.bat` or `.\Ophira.ps1 -NoMenu -Preset Standard`).
3. What you should see: flash-triage IOC hit (if still running), **amcache historical-execution hit** ("this exact hash executed on DATE" = verdict-forcing evidence), **YARA high hit** (bundled `ophira-pack.yar` has Mimikatz/Cobalt Strike/Metasploit/LaZagne/Rubeus/BloodHound rules) → verdict **COMPROMISED**.

Cobalt Strike beacon samples (tag `cobalt-strike`) also match the YARA pack; current families (tags `AgentTesla`, `Lumma`, `Remcos`...) are realistic but only light up the IOC path - add their hashes to `iocs.txt`.

**Beaconing demo without live C2** (most sample C2s are dead) - run this on the VM as the "malware", it generates a textbook periodic callback that module 4.8 flags `[high]`:

```powershell
while ($true) { try { (New-Object Net.Sockets.TcpClient('1.1.1.1', 443)).Close() } catch {}; Start-Sleep -Seconds 60 }
```

**Ransomware/USN demo without ransomware** - mass-create files with ransom extensions in a user folder; module 5.5 detects the write burst + extensions (verdict floor 3):

```powershell
1..3000 | ForEach-Object { Set-Content "C:\Users\$env:USERNAME\Documents\doc$_.docx.locked" 'x' }
```

**The real test**: run a collection, then re-run it and check the delta ("NEW findings"), and run `-Mode Process -ProcessName <sample>` to see the single-process pivot pull the whole story together.

## Roadmap

- [x] YARA scan of flagged binaries (module 4.7 + bundled `ophira-pack.yar`)
- [x] C2 beaconing detection (module 4.8, v2.9)
- [x] NTFS forensics: $MFT + USN ransomware bursts + prefetch/LNK parsing (v2.10)
- [x] Persistence sweep + quick wins: ASEP, cert store, firewall log, browser copy (v2.11)
- [x] Report completeness: evidence index + snapshots; ATT&CK Navigator layers; SIEM verdict/beacon/USN records (v2.12)
- [x] Research-driven Phase F: posture audit w/ hardening recs, ShellBags, browser parse + IOC xref, ransomware extensions, multi-drive NTFS, malfind quick-pass (v2.13)
- [x] Detection depth: DNS beaconing (EID 22), `-Mode Tune` Sigma FP feedback, LOLDrivers hash xref, hayabusa 4.1 wins (extract-base64 command recovery, RDP logon summary, sort-csv dedupe) (v2.14)
- [x] Analyst-side completion: `-Mode Parse` (finish a case on your PC), `parse_needed.csv` honesty + endpoint .NET inventory, Full-preset full-NTFS preservation (v2.15)
- [x] Triage depth v2: sigma per-rule event logs + report drill-down, `-Mode Process` single-process pivot, Tune V/ED rule viewer/editor, endpoint/analyst tool split for PushTools (v2.16)
- [x] Analyst-side completion: `-Mode Parse` (finish a case on your PC), `parse_needed.csv` + endpoint .NET inventory, Full-preset full-NTFS preservation (v2.15); hotfix helper scoping (v2.17)
- [x] **Connections: cross-source entity correlation** - binaries/accounts/remotes joined across all artifacts with category-strength scoring, report drill-down + SRUM per-app network consumers; repo trim + long-path hardening (v2.18)
- [x] **Hunt pack**: R1-R7 technique detections (renamed LOLBin, DLL side-loads live+static, download-exec, USB trail, account lifecycle, public RDP) with ATT&CK tags + verdict floors; BAM/DAM, USB history, UAL, Office MRU, local-admins, audit-policy artifacts; module 7.2 flagged-process minidumps + YARA (v2.19)
- [x] **APT depth**: structured parses (4688 process-creation w/ cmdline, 4698 task installs, 5140/5145 share access, Sysmon EID 10/13/2, Defender 5001/5007) + hunt rules R8-R15 (LSASS access, Office→interpreter chains, proxy-exec LOLBin command lines, UAC bypass, timestomping, admin-share staging, discovery storms, Defender tamper); fleet lateral-chain stitching + SIEM hunt records (v2.20)
- [x] **Sysmon config + timestamp forgery**: bundled `ophira-sysmon.xml` (config-gap detection + report hint), `CreatedFN` (FILE_NAME birth) in mft_recent, hunt rule R22 - future-birth / ran-before-born / $Si-vs-FILE_NAME skew checks on flagged binaries with EID 2 corroboration (v2.22)
- [x] **KAPE parity pack**: module 4.10 Application log (crashes + MSI installs, supertimeline-merged), module 8.13 host extras (StartupInfo launches, WER crash reports, QuickAssist/RemoteHelp artifacts, PCA, RecentFileCache, MOF, local GPO dirs, WSL dotfiles), module 8.14 server logs (DNS/DHCP audit, SYSVOL policies, NTDS.dit VSS copy on Full+DC), SDB shim persistence in the ASEP sweep (v2.23)
- [x] **Master timeline + correlation tightening**: `supertimeline.csv` rebuilt as the one-file chronology of every artifact (~25 sources, normalized `Timestamp/Source/Type/Actor/Entity/Detail` schema, UTC-normalized, capped, deduped) - filter to any timeframe in Excel/Timeline Explorer; MFT paths drive-prefixed for full-path entity joins; top entity cards gain a +/-15 min context window from the timeline (v2.24)
- [x] **Analyst deep-dive pack**: `-Mode Timeline` pivot (filter the master timeline to a window -> filtered CSV + busiest-minutes/actor summary), RECmd batch registry deep-dive in Parse mode (bundled `tools\recmd\ophira-registry.bn` over saved hives -> `registry_recmd.csv`), EvtxECmd full evtx->CSV conversion (`csv\evtx_ecmd\`) (v2.25)
- [x] **IOC feeds + credential sweep + custody**: drop STIX 2.x/MISP JSON into `tools\iocs\` (offline, no API keys) and every collection xrefs them against DNS queries, historical connections and $MFT filenames with feed attribution; module 8.15 credential-exposure sweep (auto-logon, WLAN keys -> raw\wifi, DPAPI vault -> raw\vault, LSASS-dump hunt, browser Login Data); manifest.txt upgraded to a chain-of-custody block (v2.26)
- [x] **Real-host pilot run**: Server 2025 DC (corp.lab) + domain-joined Win11 over WinRM deploy; Full preset ~1 min/host - hayabusa pack 44s, live $MFT+USN 3-10s, NTDS.dit VSS copy, Sysmon/IIS W3C/Kerberos/4720 telemetry validated, hunt rules fired on planted R1/R12-class activity (Defender ML even flagged the renamed cmd), supertimeline UTC-aligned across TZ-skewed hosts. Pilot found 5 real bugs, all fixed in v2.27/v2.28: deploy worker tools blackout, empty-CaseID break, VSS snapshot contention, renamed-LOLBin-at-rest blindness, AmcacheParser 2026 split-CSV output
- [x] **Detection canary**: menu [C] / `-Mode Canary` self-tests the pipeline on one host - enables the logging the rules need (restores after), plants self-labeled test activity (renamed binary, canary user, recon burst, certutil fetch), collects, and prints a FIRED / MISS / BLIND scorecard for R1b/R6/R10/R13. First live run immediately caught R6 dead on real hosts (account-management EIDs never reached security_auth_events) - fixed (v2.29)
- [x] **RDP bitmap cache + fleet inventory**: `raw\rdp_cache` .bmc tiles preserved (what inbound RDP sessions displayed - view with RdpCacheStudio), `case.json`/`fleet_hosts.csv` record the collection Preset, Analyze summary prints the fleet verdict distribution (v2.30)
- [ ] Offline/mounted-image triage
- [x] **Role presets + correlation spine**: auto-detected host role (DC/WebServer/Workstation) + `DC`/`WebServer` presets with auto role-pack; module 4.9 Kerberos/DS parses (4768/4769/4771/4776, 4662 DCSync GUIDs, 5136), module 8.12 IIS/HTTPERR raw + W3C parse; hunt rules R16-R21 (DCSync, Kerberoasting, AS-REP, password spray, webshell chains, web anomalies); session attribution (4624 LogonId x 4688/5145), process-lineage chains for flagged binaries, new sources in entity correlation; Win7/PS2.0 parse-compat sweep (friendly gate fires everywhere) (v2.21)

## Coverage vs Velociraptor (built-in Windows artifacts)

Ophira is a read-only single script (no resident agent, no driver), so Velociraptor's live-query artifacts are partially out of reach by design:

| Bucket | Share of VR's ~98 Windows artifacts | Examples |
|---|---|---|
| Full equivalent | ~45 | Amcache, Prefetch, USN, SRUM, ShellBags, LNK, JumpLists, RecycleBin, Timeline, DNS cache, hosts, services, tasks, WMI, certs, logon/process events, memory acquisition, hunt detections (R1-R3) |
| Partial | ~12 | SAM (hive saved, hashes not extracted), Signers, SVCHost anomalies, VAD (→ minidumps), FilenameSearch |
| Live-only (VR's agent/driver moat) | ~10 | Handles, live DLL/Thread enumeration, Mutants, Impersonation, VBScript-in-proc, UEFI |
| Niche/campaign-specific | ~12 | Notepad tabs, RDP bitmap cache, PST search, BulkExtractor, campaign one-offs |

Everything in the "full" bucket produces parsed CSVs + verdict/report integration; partials preserve the raw evidence for analyst-side completion (`-Mode Parse`).

## License

MIT
