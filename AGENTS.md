# AGENTS.md — conventions for coding agents working on this repo

## What this is
Ophira: **single-file** PowerShell 5.1 Windows IR triage toolkit (`Ophira.ps1`, ~4000 lines). READ-ONLY by design (only reads/copies; Setup downloads tools). Committed companion binaries live in `tools\` (hayabusa, yara-x, EZ parsers - they are tracked in git). `collections/`, `*.zip`, `OPHIRA_*/`, `tools/iocs.txt` are gitignored.

## Commands (run before every commit)
```powershell
# syntax gate (PS 5.1 parser)
$e=$null; [void][System.Management.Automation.PSParser]::Tokenize((Get-Content .\Ophira.ps1 -Raw),[ref]$e); if($e.Count){$e|select -First 5}

# full test suite (syntax gate + all fixture suites; exits 1 on failure)
powershell -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1
```
CI (GitHub Actions, `windows-latest`) runs the same suite on every push.

## Release convention
1. Bump `Ophira vN.N` header comment AND `$ScriptVersion`.
2. Update `README.md` (module bullets / tools table / roadmap) and `CHANGELOG.md`.
3. Full test suite green → single commit `vN.N: description` → push to `main`.

## PowerShell 5.1 quirks that bite here (learned the hard way)
- `@($genericList)` throws "Argument types do not match" on some 5.1 builds → use `$list.ToArray()`.
- Function returns unroll single-element arrays → wrap in `@()` before `.Count` (see `Import-CaseCsv` consumers: `@(Import-CaseCsv 'x.csv')`).
- `$rows += ...` inside a nested function does NOT reach the parent scope → use `List[object].Add()`.
- Manual `(Get-Content f -First 1) -split ','` on quoted CSV headers keeps the quote chars → `.Trim(' "')` before matching column names.
- The agent's shell tool IS PowerShell 5.1: nested `powershell.exe -Command "$var"` gets interpolated — write test scripts to files and run with `-File`. `-File` stringifies bool params → use `[int]`.
- Test harnesses extract functions/modules from Ophira.ps1 by regex: `(?s)function NAME \{.*?\r?\n\}` (column-0 closing brace) and `(?s)Id = 'N.N';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '<NEXT>'`.

## Architecture map (all inside Ophira.ps1)
- Top: param block → PS<5 gate → config load (`ophira.config.txt`) → helpers → `Show-RoleGate`/`Show-TaskMenu`/wizards → `-Mode` dispatch.
- Modules: array of `[pscustomobject]@{ Id; Cat; Name; Default; Quick; Run = { ... } }` (IDs 2.x persistence, 3.x network, 4.x logs, 5.x artifacts, 6.x defender, 7.x memory, 8.x context).
- Execution: `Invoke-SelectedModules` phases A (volatile, sequential) → B (parallel pool) → C/CI (heavy analytics pool); workers get functions rehydrated from `$script:SharedFunctions` + seed vars (CaseDir/CsvDir/RawDir/MemDir/Computer/Preset — `$LogHours` is NOT seeded; don't use it in modules).
- IO: `Save-Rows -Name x -Rows $r` → `csv\x.csv` (writes `# no entries` marker when empty — `Import-CaseCsv` returns `@()` for missing/marker files). Raw copies → `raw\<sub>\`.
- Verdict: `Get-CompromiseVerdict` — `Add-Signal name floor count detail`, coverage `Add-Cov name present weight`; floors: 4=near-certain IOC/YARA-high, 3=strong (live IOC, crit Sigma, beacon-high, USN bursts), 2=suspicious, two strong signals escalate to 3. NOT every artifact deserves a signal (avoid FP storms — e.g. COM hijacks stay report-only).
- Report: `New-HtmlReport` imports every CSV at top, renders sections with nav anchors; verdict computed BEFORE report in `New-Package`.
- Fixture tests: extract real functions/modules from the script, stub `Save-Rows`/`Invoke-NativeTool`/`Write-CaseLog`, feed synthetic CSVs, assert on captured rows / rendered HTML. Keep one `tests\test_*.ps1` per feature.

## Floor & dependencies
- Targets PowerShell 5.1 (hard floor 5.0, enforced by startup gate). No PS6+ syntax. .NET-native tool calls go through `Invoke-NativeTool` (console-less, optional `-CaptureOut`).
- New parsers must degrade gracefully: tool missing / not elevated → log + skip + coverage row shows missing (never crash a module).
