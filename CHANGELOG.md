# Changelog

## v2.28
- **AmcacheParser 2026+ split-CSV merge** (second pilot-redeploy finding): AmcacheParser 2026.5 writes split outputs (`amcache_UnassociatedFileEntries.csv`, `amcache_DriveBinaries.csv`, ...) and no longer a single `amcache.csv`, so module 8.4 reported "produced no output" and every downstream consumer (IOC SHA1 xref, hunt R3 static, entity correlation, YARA targets) ran blind. The file-entry family (ApplicationName-headered splits) is now merged back into `csv\amcache.csv` (DriveBinaries fallback) before the existing IOC xref
- Pilot redeploy validation with v2.27: kit-root seed live (hayabusa/amcache/RBCmd all run on endpoints), NTDS.dit VSS copy succeeds under parallel SRUM load (40MB), R1b + structured EID1 in place
- Tests: module 8.4 merge covered in `tests\test_v227.ps1` (27 checks total)

## v2.27
- **Real-host pilot fixes** (first live-host run: Server 2025 DC + Win11 over WinRM deploy; four real bugs found and fixed):
  - **Worker tools blackout**: `Get-KitRoot` fell back to CWD; deploy-spawned workers inherit `C:\Windows\System32`, so every tools-dependent module (hayabusa, chainsaw, Amcache/RBCmd, hunt packs) silently skipped on remote endpoints while local runs (CWD = kit folder) worked by accident. Kit root is now seeded into workers via the shared preamble
  - **Deploy with empty `-CaseID` broke remote runs**: `-CaseID ""` collapsed in the outer `powershell.exe -Command` re-parse, `-CaseID` swallowed `-LogHours` and parameter binding died (exit 1, "no result zip"). `-CaseID` is now only added when non-empty
  - **Parallel VSS snapshot contention**: concurrent `esentutl /vss` copies (SRUM module 5.3 x NTDS module 8.14 in different workers) race on the VSS snapshot set - one failed with no detail. New `Copy-LockedFile` helper (retry with backoff + real esentutl error in the log) used by SRUM, NTDS.dit and the browser-DB fallback
  - **Renamed LOLBins invisible at rest**: live R1 only sees running processes. New structured **Sysmon EID 1** parse (`csv\sysmon_proc_create.csv`: Image/OriginalFileName/CommandLine/User) + hunt rule **R1b** - executed name vs `OriginalFileName` identity mismatch (winupd.exe-running-Cmd.Exe class), high severity, floor-2 verdict signal, deduped; EID 1 events also woven into the master timeline with an `ORIGINAL NAME:` highlight
- Tests: `tests\test_v227.ps1` (23 checks) - R1b through the real hunt function (fires/mutes/dedupes; caught an `.exe`-suffix comparison bug pre-release), Copy-LockedFile retry+logging, Get-KitRoot seed override, deploy guard + wiring

## v2.26
- **IOC feed ingest (STIX/MISP) + widened xref**:
  - `Get-IocList` now also reads **`tools\iocs\*.json`** - drop STIX 2.x bundles or MISP exports (direct or response-wrapped) into the folder; hashes/domains/IPS/filenames parse into the same internal lists (`tools/iocs/` gitignored). No network, no API keys - works air-gapped; every hit is attributed to its source feed
  - **New-IocHits** (in the shared packaging/Parse pipeline): feed domains x Sysmon DNS queries (`ioc_hits_dns`), feed IPs x historical connections (`ioc_hits_network`), feed filenames x $MFT exact-name matches (`ioc_hits_mft`); verdict signals (floor 2) for DNS/network and known-bad filename on disk; new indicators join the defanged report block
- **Credential-exposure sweep (module 8.15)**: auto-logon (user + password PRESENT/absent - value not copied to CSV), WLAN profiles with `key=clear` capture -> `raw\wifi`, DPAPI Credentials/Protect blobs -> `raw\vault` (analyst-side decrypt), shallow LSASS-dump hunt over known drop spots (recorded, never copied), browser **Login Data** + `Local State` added to the browser raw copy -> `credential_sweep.csv` + report snapshot table
- **Evidence manifest + chain of custody**: manifest header gains Packaged-UTC, scope and custody notes (case zip = evidence unit, keep the zip hash with case notes); script + every file SHA256'd as before
- Tests: `tests\test_v226.ps1` (19 checks) - STIX/MISP parsing, feed attribution, DNS/network/MFT xref precision, credential sweep + manifest + wiring

## v2.25
- **Analyst deep-dive pack**:
  - **`-Mode Timeline` pivot** (menu [T]): `-Path <case> -TimelineStart 'yyyy-MM-dd HH:mm' -TimelineEnd ...` filters the master timeline (UTC) to a window -> `csv\timeline_<start>_<end>.csv` + console summary (by source, busiest minutes, top actors). The "someone reported weird activity at 14:00" workflow as a one-command mode
  - **RECmd batch registry deep-dive** (Parse mode): new whitelisted-everywhere EZ tool (Setup catalog) runs the bundled **`tools\recmd\ophira-registry.bn`** batch (~30 curated keys: autoruns/persistence, IFEO/AppInit/Winlogon, services+drivers, USBSTOR, Lsa, RDP Terminal Server Client, TypedPaths/RunMRU/RecentApps, MuiCache/TrayNotify) over every saved hive -> `csv\registry_recmd.csv` (Hive/KeyPath/ValueName/Value/LastWrite)
  - **EvtxECmd full evtx->CSV** (Parse mode, Setup catalog, analyst tools folder): converts every exported evtx into `csv\evtx_ecmd\<log>.csv` for timeframe deep-dives beyond the EID-filtered endpoint parses (stays out of the master timeline - it is the full-fidelity drill-down layer)
  - Report case meta + evidence index updated; batch file ships in the kit and is AV-resilient (text only)
- Tests: `tests\test_v225.ps1` (20 checks) - Timeline mode end-to-end (window edges, swapped range, empty case), Parse-mode RECmd/EvtxECmd execution with mapped output, structural wiring

## v2.24
- **Master timeline** - `csv\supertimeline.csv` rebuilt as the one-file chronology of EVERYTHING (KAPE-timeline style): ~25 source adapters weave logons, 4688/4698/5140/5145, Kerberos/DS, all Sysmon structured telemetry (network/DNS/image-load/ProcessAccess/registry/file-time), prefetch, amcache, $MFT births, USN bursts, browser history/downloads, LNK, ShellBags, recycle bin, BAM, StartupInfo, WER, Office MRU, session activity, IIS requests, hunt findings and logging gaps into a normalized schema (`Timestamp, Source, Type, Actor, Entity, Detail`), UTC-normalized and sorted; per-source caps + 60k total cap; hayabusa sort-csv dedupe. Analyst opens ONE file and filters to any timeframe ("weird activity at 14:00")
- **Correlation tightening**:
  - Module 5.5 now prefixes the drive letter on MFT paths (`\Users\...` -> `c:\Users\...`) so entity correlation joins on full paths instead of falling back to leaf names
  - Report Connections: top entity cards gain a **context window** - everything happening +/-15 min around the binary's first seen, pulled from the master timeline (capped 8 rows; entity FirstSeen converted to UTC to align with the timeline - timezone-skew bug caught by test on a UTC+3:30 host)
- Evidence index: supertimeline description upgraded to the master-timeline role
- Tests: `tests\test_v224.ps1` (15 checks) - 9-source weave fixtures (schema, sort, normalization, per-type adapter output), MFT drive fix, context-window rendering incl. out-of-window exclusion

## v2.23
- **KAPE parity pack** - closes the meaningful gaps vs [kapefiles](https://github.com/ericzimmerman/kapefiles) targets (bulk folder copies, raw NTFS internals and consumer artifacts deliberately not taken):
  - **Module 4.10 Application log**: crashes (1000/1001/1002), MSI installs (1033/11707/11724) -> `application_events.csv` + `Application.evtx`; merged into the supertimeline. Crashed attacker tooling surfaces here
  - **Module 8.13 Host extras**: **StartupInfo** per-session app launches (`System32\WDI\LogFiles\StartupInfo` XML parse -> `startup_info.csv` + raw), **WER crash reports** (ProgramData + per-user, Report.wer parse -> `wer_reports.csv`), **QuickAssist/RemoteHelp** temp artifacts (AitM/scam tradecraft marker), **PCA** (`Windows\appcompat\pca` - Win11 last-exec evidence), **RecentFileCache.bcf**, **MOF** dir, **local GroupPolicy/GroupPolicyUsers** dirs (GPO-script persistence surface), **WSL dotfiles** (.bash_history etc.) -> `raw\extras\`
  - **Module 8.14 Server logs**: DNS + DHCP audit logs raw copy, **SYSVOL Policies** (capped), **NTDS.dit VSS copy** gated on DC role + Full preset (esentutl /vss, same pattern as SRUM; hash extraction is analyst-side only) -> `raw\server\` + `server_logs.csv` inventory
  - **ASEP sweep (2.6) gains SDB check**: custom shim databases (`AppCompatFlags\Custom` / `InstalledSDB`, HKLM+HKCU) - classic rare-legit persistence
  - parse_needed gains RecentFileCache -> AppCompatParser row; coverage row for host extras; whitelisted parsers `Get-StartupInfoRows` / `Get-WerReportRows`
- Tests: `tests\test_v223.ps1` (17 checks) - StartupInfo/WER parser fixtures, live 4.10 Run block, structural wiring incl. NTDS gate

## v2.22
- **Bundled recommended Sysmon config** (`tools\sysmon\ophira-sysmon.xml`): lean commented config enabling exactly what Ophira parses - process creations w/ hashes (1), file-time changes (2), network (3), image loads (7), **ProcessAccess filtered to lsass targets** (10 - LSASS-dump signal without the noise), **registry hot keys** (Run/IFEO/ms-settings/services - UAC bypass + persistence), DNS queries (22). Install one-liner in the header (`sysmon64.exe -accepteula -i ophira-sysmon.xml`); Ophira itself stays read-only - you deploy it
  - Setup kit inventory points at the file; README gains a "Deploy Sysmon" section
  - Report hunt section flags the **config gap**: Sysmon present but no EID 10 telemetry -> hint to deploy the bundled config (the LSASS/registry/beacon rules run blind without it)
- **Hunt rule R22 - timestamp forgery indicators** (T1070.006, medium, report-only): scans every executable in `mft_recent` with three O(1) checks:
  - **future-birth** - $Si birth after collection time (+1d margin; backdated or clock-skewed)
  - **ran-before-born** - amcache evidence predates the claimed birth by >24h (executed before it "existed")
  - **$Si-vs-FILE_NAME skew** - Created0x10 vs Created0x30 disagree by >90 days (classic backdated-$Si signature)
  - Sysmon EID 2 events for the same file cited as corroboration
- Module 5.5 now projects `CreatedFN` (FILE_NAME birth, Created0x30) into `mft_recent` alongside the existing $Si `Created`
- Tests: `tests\test_v221.ps1` unchanged; new `tests\test_v222.ps1` (15 checks) - R22 fixtures per check + negatives, config XML validity + filter sanity (lsass include, hot keys, unfiltered DNS)

## v2.21
- **Role presets + correlation spine**
  - **Host role detection** (`Get-HostRole`, startup): DC (NTDS registry key), WebServer (InetStp/W3SVC), else Workstation; shown in the menu banner + collection log, recorded in `case.json` (`Role`) and `fleet_hosts.csv` (+ fleet-report host table)
  - **`-Preset DC` / `-Preset WebServer`** force the role modules on; Standard/Full **auto-enable** the role pack on a detected DC/IIS host (menu can untick, Quick/Flash never carry it)
  - **Module 4.9** (DC role): Kerberos + directory events via `Get-EventDataRows` - 4768 (PreAuthType), 4769 (TicketEncryptionType), 4771, 4776, 4662 (replication GUIDs), 5136 (AD object changes) -> `security_kerberos.csv` + `security_ds_access.csv`; honest skip-note when audit policy is off
  - **Module 8.12** (web role): inetpub LogFiles + HTTPERR + applicationHost.config raw copy; new whitelisted `Get-IisW3cRows` W3C parser -> `iis_requests.csv` + `iis_anomalies.csv` (500 bursts, suspicious URIs, POSTs to upload paths, headless POSTs)
  - **Hunt rules R16-R21**: R16 **DCSync** - 4662 Get-Changes by a user account (high, floor 2); R17 **Kerberoasting** - >=10 RC4 TGS to distinct SPNs per source (medium); R18 **AS-REP roast** - 4768 without pre-auth (medium); R19 **password spray** - >=10 distinct accounts failing from one source across 4771+4625 (high, floor 2); R20 **webshell chain** - w3wp/tomcat/httpd spawning interpreters (high, floor 2); R21 **web anomalies** (medium, report-only)
  - **Session attribution** (`New-SessionAttribution`): 4624 LogonId x 4688/5145 SubjectLogonId joins -> `session_activity.csv` - process creations and admin-share writes attributed to the logon session (account + source IP + logon type); report "Attributed activity" table + account-entity evidence
  - **Process lineage** (`New-ProcessChains`): parent-child graph from 4688 + live PPID map; ancestry chains for flagged binaries (HIGH/MEDIUM verdicts + high hunt findings) -> `process_chains.csv` + report "Process lineage" table (`explorer.exe -> winword.exe -> powershell.exe` style stories)
  - **Entity correlation grows**: 4688 executions, admin-share staged files, IIS anomalies as new binary categories; Kerberos/DS/attributed activity as new account evidence; **fixed v2.19 ordering bug** - hunt findings now run BEFORE entity correlation, so the `hunt` category is fresh in a single pass
  - Coverage rows (Kerberos/DS, Web, session/lineage), SIEM unchanged, evidence index documents all 6 new CSVs
- **Win7/PS 2.0 parse-compat sweep**: removed every PS3+ operator (`-in`/`-notin` -> `-contains`/`-notcontains`, 18 sites) and PS5-only `::new()` (5 sites) - the whole script now PARSES under stock Win7's PowerShell 2.0, so the friendly PS<5 gate + WMF 5.1 guidance renders everywhere instead of parser errors; regression-checked in `test_v221.ps1`; README gains an OS support matrix
- Tests: `tests\test_v221.ps1` (36 checks) - role detection via cmdlet shadowing, preset role packs, R16-R21 fixtures, session attribution, lineage reconstruction, W3C parser, compat greps

## v2.20
- **APT depth**: structured event parses + hunt rules R8-R15
  - **Structured parses** via new `Get-EventDataRows` helper (named EventData fields from the event XML, newest-first, capped; added to the worker whitelist):
    - `security_proc_events.csv` - 4688 process creations (account, process, command line, parent; empty CommandLine = cmdline audit policy off, rules degrade to parent-child chains)
    - `security_task_install.csv` - 4698 task installs with the action command; `security_share_access.csv` - 5140/5145 (share, target name, source IP, access list; capped 8000)
    - `sysmon_process_access.csv` - EID 10 (LSASS-access data source); `sysmon_registry.csv` - EID 13 (UAC-bypass/persistence); `sysmon_file_time.csv` - EID 2 (timestomping)
    - `defender_config_events.csv` - 5001 real-time-protection off / 5007 config changes
  - **Hunt rules**: R8 **LSASS access** - non-system process opens lsass.exe w/ core-process allowlist (high); R9 **Office→interpreter chain** - WINWORD/EXCEL/OUTLOOK parent spawning cmd/powershell/wscript/mshta/rundll32... (high); R10 **proxy-execution LOLBin command lines** - encoded commands, certutil download/decode, mshta remote, comsvcs minidump, regsvr32 scriptlet (high) + bitsadmin/msiexec-remote/wmic-create (medium); R11 **UAC bypass** - ms-settings shell\open\command registry hijack (medium); R12 **admin-share executable staging** - 5145 WriteData of exe/dll/ps1... on ADMIN$/x$ (high); R13 **discovery command storms** - per-account recon-tool bursts (medium); R14 **Defender tamper** - RT disabled / exclusion changed (high); R15 **timestomping** - EID 2 creation-time changes (medium)
  - R8/R9/R10/R12/R14 join R1-R4 as **floor-2 verdict signals** (signal text updated); R11/R13/R15 are report-only leads
  - SIEM export gains `hunt_finding` records (high+medium); evidence index documents all 7 new CSVs; new coverage row "Structured telemetry (4688 / Sysmon 10-13)"
- **Fleet lateral-chain stitching**: each host's `security_share_access.csv` source IPs joined against every other host's `net_interfaces.csv` → `fleet_lateral_chain.csv` + console summary + fleet-report "Lateral movement chains" table (host A → share → host B); hunt hits now surface as fleet HuntHit high-priority findings
- Hygiene: removed stray `Ophira_dbg.ps1` / `SQLite.Interop.dll` from repo root; `tests\test_v220.ps1` (26 checks)

## v2.19
- **Hunt pack** (`New-HuntFindings`, R1-R7) - technique-based detections ported from Velociraptor-style logic → `hunt_findings.csv` (Rule/Severity/Entity/ATT&CK/Evidence) + report "Hunt findings" section:
  - R1 **renamed LOLBin** (T1036.003): embedded version-info identity vs filename against the BinaryRename LOLBin table (cmd/powershell/mshta/regsvr32/rundll32/certutil/...)
  - R2 **DLL side-load live** (T1574.002): Sysmon EID 7 proxy-DLLs (version.dll, winmm.dll, dbghelp.dll...) loaded from user-writable paths + unsigned-outside-Windows variant
  - R3 **DLL side-load static** (T1574.002): system-DLL name planted in a user-writable path (amcache/MFT/EID 7 union)
  - R4 **downloaded-then-executed** (T1105/T1204.002): browser downloads × execution evidence
  - R5 USB execution trail, R6 account-created + group-change, R7 RDP-in from public IP (report-only)
  - R1-R4 are high-precision → **floor-2 verdict signals**; all findings feed entity correlation as a `hunt` category
- **New artifacts**: Sysmon EID 7 parse (`sysmon_image_load.csv`), BAM/DAM last-exec (`bam_lastexec.csv`), USB device history (`usb_devices.csv` + setupapi.dev.log raw), Office File MRU (`office_mru.csv`), local admins (`local_admins.csv`), audit policy → posture rows, UAL .mts raw copy
- **Module 7.2 live memory triage** (opt-in, admin): minidumps of flagged processes only (cap 10, >1.5GB skipped, LSASS/security-critical excluded, 2GB/10GB-disk budgets) via `MiniDumpWriteDump` → YARA over the dumps → `memory_live_scan.csv` + report section (catches injected/unpacked code disk scans miss; dumps are Volatility-readable)
- Coverage doc: README now maps Ophira vs Velociraptor's built-in Windows artifacts (full/partial/live-only/niche)
- Fixed: `@($list)` around generic lists in hunt emit (PS 5.1 "Argument types do not match")

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
