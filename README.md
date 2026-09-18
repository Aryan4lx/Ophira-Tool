# IR-Triage

Agentless Windows incident-response triage collector. One PowerShell script (5.1+, zero dependencies), handed to a system owner or pushed to many endpoints. Runs a **flash triage** in seconds, collects evidence by module, packages everything into a hashed ZIP for the analyst.

**Read-only by design** — never kills processes, never deletes files, never modifies the system. Only reads and copies.

```
.\IR-Triage.ps1 -NoMenu -Preset Standard -CaseID INC-2026-042
```

## What it does

1. **Flash triage (auto, ~15s)** — process anomalies with **correlation scoring** (Verdict LOW/MEDIUM/HIGH per process), public IP connections, DNS/ARP, SMB + saved credentials (`cmdkey`), Defender last detection, **IOC matching**
2. **Deep modules** (menu or presets `Flash|Quick|Standard|Full`):
   - VOLATILE — processes (cmdline/parent/company/flags), full hashing, connections, DNS+ARP, sessions, drivers
   - PERSISTENCE — Run keys, startup folders, services, scheduled tasks, WMI subscriptions
   - NETWORK MAP — interfaces, reachable subnets, SMB hosted/mounted/active, saved creds, Kerberos tickets, proxy/WPAD, optional active probes (opt-in, flagged)
   - LOGS — Security (incl. 4625 brute-force candidates), PowerShell 4104, Sysmon (auto-detected), RDP, System 7045 + **raw evtx export** + optional **Hayabusa Sigma hunt**
   - ARTIFACTS — Prefetch, registry hives (`reg save` SYSTEM/SOFTWARE/SAM/SECURITY, Amcache.hve), UserAssist, SRUM
   - DEFENDER — detections, exclusions, status, operational log
   - MEMORY — optional RAM capture via winpmem, optional Volatility 3 quick pass
3. **Packaging** — `manifest.txt` with SHA256 per file + package hash, `case.json` metadata, ZIP (memory dump excluded, hashed separately)

## FP/TP decision support

The report layers evidence so you can call it:
- **Correlation score** — a binary appearing as process + service + scheduled task + public connection scores HIGH; a lone Electron app in AppData scores LOW
- **IOC matching** — drop hashes/IPs/domains in `tools\iocs.txt` (see `tools\iocs.txt.sample`); hits print red on flash and land in `flash_ioc_hits.csv`
- **Sigma severity** — put `hayabusa.exe` in `tools\` and every collection gets a scored detection timeline (`csv\hayabusa_timeline.csv`)
- **Raw evidence** — every flag is backed by the raw CSV/evtx/hive so any verdict can be verified

## Deploy at scale

```powershell
# WinRM push (copy kit, run, pull zips back):
.\Deploy-Remote.ps1 -ComputerName SRV01,SRV02 -Preset Quick -Credential (Get-Credential)

# Or have endpoints upload to a central share themselves:
.\IR-Triage.ps1 -NoMenu -Preset Quick -SharePath \\IR-SRV\collections$

# Works over GPO startup script / PDQ / SCCM / anything that can run a BAT:
RUN-TRIAGE.bat   (owner double-clicks, accepts UAC, sends back the zip)

# Merge any number of case zips into one fleet view:
.\Analyze-Fleet.ps1 -Path .\collections -Hayabusa C:\Tools\hayabusa.exe
```

`Analyze-Fleet.ps1` flags the same indicator on multiple hosts (outbreak signal), summarizes per-host findings, and can run one Hayabusa Sigma timeline across all hosts' event logs.

## tools\ folder (all optional)

| File | Enables |
|---|---|
| `winpmem64.exe` | RAM capture (module 7.1) |
| `vol.exe` (Volatility 3 standalone) | on-host pslist/cmdline/svcscan quick pass after capture |
| `hayabusa*.exe` | Sigma detection timeline over exported evtx (module 4.6) |
| `iocs.txt` | hash/IP/domain matching in flash triage |

## Analyst-side companions (offline)

- **Volatility 3** — `pslist, netscan, malfind, cmdline` against `memory\physmem.raw`
- **Chainsaw** — `chainsaw analyse shimcache raw\registry\SYSTEM.hiv -a raw\registry\Amcache.hve` → program execution timeline
- **Hayabusa** — `hayabusa csv-timeline -d <evtx dir>` against the exported evtx if it wasn't run on-host

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

## Related tools

If you need always-on endpoint visibility at enterprise scale, look at [Velociraptor](https://docs.velociraptor.app/). IR-Triage fills the agentless gap: no infrastructure, no installed agent, one script you can hand to anyone or push through anything.

## License

MIT
