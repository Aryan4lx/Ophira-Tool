# Changelog

## v2.18
- **Connections: cross-source entity correlation** (`New-EntityCorrelation`, runs at packaging + in `-Mode Parse`):
  - **Binaries** joined across ~16 artifacts (flash verdict, running processes, hashes, amcache+IOC, prefetch, services/tasks/autoruns/ASEP persistence, connections, beacons, SRUM usage, YARA, LOLDrivers, MFT created, sigma alerts) → `entities_binaries.csv` with evidence-category counts, first/last seen, hashes, SRUM bytes
  - **Accounts** joined across logon events (types/failures/sources), RDP sessions, RDP-out MRU targets, console history, brute-force → `entities_accounts.csv`
  - **Remote endpoints** joined across connections, beacon flags, brute-force sources, RDP targets → `entities_remotes.csv`
  - Report "**Connections - correlated entities**" section: top multi-source binaries as expandable story cards, account-activity + remote-endpoint tables, and a "**Top network consumers (SRUM)**" table finally surfacing the ~30-day per-app byte history
  - Report-only (no verdict changes); graceful when sources are missing
- **Repo trim**: removed upstream test fixtures/docs from bundled rule packs (~21 MB / 883 files; deepest path 229→211 chars - GitHub ZIP no longer hits MAX_PATH when extracted with `tar -xf` or 7-Zip)
- **`\\?\` long-path hardening** in push packaging + remote tool extraction
- README: "Get the kit" (git clone / `tar -xf` / 7-Zip) + "Testing on a VM" guide (MalwareBazaar sample recipe, iocs.txt hash prep, beacon + ransomware simulators)
- Real-case fix: empty `Image`/`ProcessPath` values no longer abort correlation; SRUM device-style paths (`\device\harddiskvolumeN\`) normalize to drive letters

## v2.17
- **Hotfix**: `Get-LvlRank` (plus `Split-TagList`/`Get-TacticLabel`) promoted from nested-in-`New-HtmlReport` to top-level functions - v2.16's `New-SigmaRuleLogs` called it from top-level scope and every collection printed `CommandNotFound` errors at the sigma-rule-logs step (rule CSVs were still written; only the worst-first index sorting broke). Caught on Windows Server 2025, present everywhere. Regression guard added: the test suite asserts these helpers are top-level (column-0 definitions) and the live full-run was re-verified
- Test harnesses updated to declare the (now top-level) helper dependencies explicitly

## v2.16
- **Sigma rule logs**: one CSV per matched rule under `csv\sigma_rules\` (time, host, event ID, RecordID, details) + `index.csv`; `report.html` Sigma section now has per-rule drill-down - expand a rule to read its matched events inline
- **`-Mode Tune` gains `[V]`iew / `[ED]`it**: locates the rule's .yml in the bundled rules by RuleID and opens it in Notepad (ED waits for close); edits apply on the next run
- **`-Mode Process`** (new mode + menu item 9): single-process pivot over a collected case - name, path fragment or hash; auto-pivots hash → path → name; groups evidence by artifact type → `csv\process_pivot.csv`
- **`tools\` split**: `tools\endpoint\` (shipped via Deploy `-PushTools`: hayabusa/chainsaw/yara/EZ parsers/loldrivers/winpmem, ~72 MB zip) vs `tools\analyst\` (vol3, SQLECmd — never shipped); Setup downloads into the right folder; tool discovery is recursive so existing layouts keep working
- **AV-resilient push packaging**: Defender flags some bundled Sigma `.yml` files and blocks `Compress-Archive` entirely — `-PushTools` now zips per-entry, skipping AV-blocked files with a visible skip count; remote extraction does the same
- Parse mode refactored onto shared `Open-CaseSession` (also used by Process mode)

## v2.15
- **`-Mode Parse`** (new mode + menu item 8): analyst-side completion of a collected case — re-runs the raw-driven parsers from your kit (AmcacheParser/RBCmd/PECmd/LECmd/JLECmd/SQLECmd, chainsaw execution history, hayabusa detection pack) against the case's `raw\` evidence, then regenerates supertimeline, verdict, SIEM export and `report.html`; zip inputs are repacked in place. Closes the contractor flow: endpoint does what it can, one command finishes the rest
- **`csv\parse_needed.csv`**: for every missing artifact — parser, .NET requirement, whether the raw evidence shipped, and the exact way to finish it (endpoint-only vs `-Mode Parse`); shown in the report evidence index
- **`case.json` records the endpoint's .NET inventory** (`DotNet`: Framework 4.x release + .NET 9 desktop runtime presence) — EZ parsers need 4.x, SQLECmd needs .NET 9
- **Full-preset full-NTFS preservation**: module 5.5 keeps unfiltered `mft_full_<drive>.csv` / `usn_full_<drive>.csv` under `raw\analysis\` for analyst-side work; auto-skipped when the endpoint has <10 GB free (Standard/Quick stay lean)
- Verdict confidence in Parse mode now uses the **endpoint's** recorded elevation (not the analyst PC's)
- Shared `Invoke-RegenerateOutputs` (New-Package + Parse mode) and `Invoke-BrowserIocXref` (module 8.7 + Parse mode)

## v2.14
- **DNS beaconing** (module 4.8 + 4.3): Sysmon EID 22 DNS queries parsed → `sysmon_dns.csv`; same periodicity engine applied per process+domain → `dns_beacon_candidates.csv`; verdict signals (high=floor 3, medium=floor 2), report section, domains+resolved IPs in IOC block, SIEM kind `dns_beacon`
- **`-Mode Tune`** (new mode + menu item 6): shows top-hit Sigma rules from the newest case, exclude (`exclude_rules.txt`) or demote (`level_tuning.txt`) — hayabusa-native formats that travel with Deploy `-PushTools`
- **LOLDrivers hash check** (module 8.10): all drivers SHA256-hashed and cross-checked against keyless LOLDrivers datasets (`tools\loldrivers\`, bundled) → `loldrivers_hits.csv`; malicious driver = verdict signal floor 2; Setup catalog entry (raw GitHub download); report "Driver check" section; SIEM kind `loldriver`
- **hayabusa 4.1 wins**: `extract-base64` over exported evtx → `ps_decoded_commands.csv` (decoded attacker PowerShell commands, report section); `logon-summary` now aggregates RDP sessions (4778/4779/1149/25); `sort-csv` dedupe applied to the supertimeline and the fleet Analyze timeline (overlapping/backup evtx no longer double-count)
- Fixed: `Import-CaseCsv` was missing from the worker function whitelist — module 8.7's browser IOC cross-check silently did nothing in parallel (Phase B) runs
- Fixed: driver `PathName` normalization handles both `\??\` and `\\??\` NT path prefixes

## v2.13
- **Security posture audit** (module 8.9): LSA Protection, NTLM level, SMBv1, RDP+NLA, PowerShell script-block logging, UAC, Defender exclusions/real-time/service, BitLocker, WinRM TrustedHosts → `posture.csv`; BAD findings become hardening actions in the report recommendations
- **ShellBags** (module 8.8): folder-browsing history via SBECmd → `shellbags.csv` (attacker folder traversal incl. deleted/USB locations)
- **Browser parse** (module 8.7): SQLECmd on raw-copied Chrome/Edge DBs → `browser_history.csv` / `browser_downloads.csv` / `browser_searches.csv` + **IOC domain cross-check** → `ioc_hits_browser.csv` (verdict signal floor 2)
- **USN ransomware extensions** (module 5.5): suspicious new extensions (`.locked`, `.enc`, `.crypt*`, …) during mass-modification bursts enrich the Impact signal
- **Multi-drive NTFS forensics** (module 5.5): $MFT + USN now parsed on every fixed NTFS volume (Drive column added)
- **Memory quick-pass** (module 7.1): volatility malfind → `memory_malfind.csv` (verdict signal floor 2) + netscan on hits
- Tools bundled: SBECmd, SQLECmd (.NET 9 required for SQLECmd — degrades gracefully); new SIEM kinds `malfind`, `browser_ioc`

## v2.12
- Report completeness: **evidence index** — every CSV with row counts + "what to look for" guidance + pointers to supertimeline/SIEM/verdict/layer files
- Host snapshot section: Defender state + detection history, stored credentials, outbound RDP targets, BITS jobs
- **MITRE ATT&CK Navigator layer export** (`attack_layer.json`, per case; `attack_layer_fleet.json` in Analyze mode) + fleet ATT&CK roll-up table in `fleet_report.html`
- SIEM export: new record kinds `beacon`, `mass_modification`, `verdict`; export now runs after the verdict is computed
- Codified test suite (`tests/run-tests.ps1`), GitHub Actions CI, CHANGELOG, AGENTS.md

## v2.11
- ASEP persistence deep sweep (module 2.6): IFEO debuggers (incl. sticky-keys), AppInit_DLLs, Winlogon Shell/Userinit/Notify, HKCU COM hijack suspects, netsh helpers, LSA packages, StartupApproved stamps → `asep_sweep.csv` + verdict signal (floor 2)
- Certificate store inventory (T1553): LocalMachine/CurrentUser Root + CA + TrustedPublisher, recent/self-signed flags → `certificates.csv`
- Firewall profiles (`firewall_profiles.csv`) + `pfirewall.log` copy to `raw\firewall\`
- Browser artifacts raw save: Chrome/Edge History/Downloads/Preferences/Bookmarks per profile, `esentutl /vss` fallback → `raw\browser\` + `browser_files.csv`
- Report: uncommon-persistence table (with Target column), recent self-signed cert table; coverage sources for ASEP/browser

## v2.10
- NTFS forensics (module 5.5): live `$MFT` parse via MFTECmd (filtered executable/user-path/recent inventory → `mft_recent.csv`), USN journal write-burst detection (ransomware-style mass modification → `usn_write_bursts.csv`, verdict signal floor 3)
- Prefetch parsing via PECmd → `prefetch_parsed.csv` (run counts + times)
- LNK + Jump Lists: raw save + LECmd/JLECmd parse (modules 8.5)
- Setup catalog: MFTECmd/PECmd/LECmd/JLECmd (direct URLs) + `Unblock-File` after extraction; tools bundled in repo
- Report: "File-system evidence" section (USN windows, most-run prefetch, MFT user-path executables); coverage sources USN/MFT

## v2.9
- C2 beaconing detection (module 4.8): periodicity/jitter/regularity on Sysmon network events → `beacon_candidates.csv`; verdict signals (high=floor 3, medium=floor 2); report section + beacon IPs in IOC block
- PowerShell < 5.0 fail-fast gate with remote-collection guidance
- Deploy wizard advanced options (Full depth, log window via new `-LogHours` passthrough, host parallelism)

## v2.8
- Fleet verdict inheritance: per-host verdicts from `verdict.json` in Analyze mode — verdict chips, worst-first host matrix, ATTENTION FIRST list, `fleet_hosts.csv`

## v2.7
- Report v2: verdict banner + confidence bar + signals + caveats, coverage table, MITRE ATT&CK grid (tactic chips + technique table), defanged copy-ready IOC block, findings by tactic, YARA section, logon analysis, persistence inventory, recommendations

## v2.6
- Compromise verdict engine: 5-level scale, signal floors, coverage-weighted confidence, caveats → `verdict.json` + owner-screen RESULT line

## v2.5
- Role gate + 6-entry task menu, deploy/analyze/setup wizards, config memory (`ophira.config.txt`)
- YARA module (4.7) with bundled `ophira-pack.yar`, hayabusa verbose profile (ATT&CK tags)

## v2.4
- Phased parallel collection (volatile → parallel categories → heavy analytics), `-Sequential`, worker runspaces with rehydrated functions
- hayabusa time-boxing (`--time-offset` + eid-filter), `ModuleTimings` telemetry in `case.json`, parallel zip extraction in Analyze

## v2.3
- Delta collection (new findings vs previous run), fleet baselining proposals, SIEM export (`siem_export.ndjson`), WinRM PushBin (push tools, run, remove)

## v2.2
- Rebrand to Ophira, owner experience (SimpleUI), context modules (attacker activity, user hives), parallel fleet deploy

## v2.1
- hayabusa v4 compat, chainsaw execution history, unified HTML report

## v2.0
- Single-script consolidation with `-Mode` dispatch

## v1.2
- IR-Triage: agentless Windows IR triage collector
