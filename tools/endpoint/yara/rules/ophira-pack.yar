/*
    Ophira bundled YARA pack v1.0
    Copyright (c) 2026 - MIT License

    Generic hacktool / attacker-tooling indicators for endpoint triage.
    These are HEURISTICS: verify every hit against context before acting.
    Severity in meta: "high"  = near-certain attacker tooling
                      "medium" = strongly suspicious, verify
                      "low"    = dual-use software, informational

    Add your own *.yar files next to this one - Ophira scans them all.
*/

rule OPHIRA_Hacktool_Mimikatz
{
    meta:
        severity = "high"
        description = "Mimikatz credential dumper family"
        reference = "https://attack.mitre.org/software/S0002/"
    strings:
        $a1 = "mimikatz" nocase wide ascii
        $a2 = "gentilkiwi" nocase wide ascii
        $a3 = "sekurlsa::logonpasswords" nocase ascii
        $a4 = "lsadump::sam" nocase ascii
        $a5 = "Invoke-Mimikatz" nocase wide ascii
        $a6 = "DPAPI_BACKUP_KEY" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule OPHIRA_Hacktool_CobaltStrike_Beacon
{
    meta:
        severity = "high"
        description = "Cobalt Strike beacon artifacts"
        reference = "https://attack.mitre.org/software/S0154/"
    strings:
        $a1 = "ReflectiveLoader" ascii
        $a2 = "%s as %s\\ from %s" ascii
        $a3 = "beacon.dll" nocase ascii
        $a4 = "postex" ascii
        $a5 = "spawnto_x64" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule OPHIRA_Hacktool_Metasploit_meterpreter
{
    meta:
        severity = "high"
        description = "Metasploit / meterpreter payload artifacts"
        reference = "https://attack.mitre.org/software/S0020/"
    strings:
        $a1 = "meterpreter" nocase wide ascii
        $a2 = "metsrv" nocase ascii
        $a3 = "windows/exec" ascii
        $a4 = "EXITFUNC=thread" ascii
        $a5 = "METSVC" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule OPHIRA_Hacktool_LaZagne
{
    meta:
        severity = "high"
        description = "LaZagne credential harvester"
        reference = "https://attack.mitre.org/software/S0349/"
    strings:
        $a1 = "lazagne" nocase wide ascii
        $a2 = "browsers\\cheeseburger" ascii
        $a3 = "-password all" ascii
    condition:
        2 of them
}

rule OPHIRA_Hacktool_Rubeus_Kerberos
{
    meta:
        severity = "high"
        description = "Rubeus kerberos abuse toolkit"
        reference = "https://attack.mitre.org/software/S1071/"
    strings:
        $a1 = "Rubeus" wide ascii
        $a2 = "asreproast" nocase ascii
        $a3 = "kerberoast" nocase ascii
        $a4 = "hashdump" nocase ascii
    condition:
        2 of them
}

rule OPHIRA_Hacktool_BloodHound_Collector
{
    meta:
        severity = "high"
        description = "BloodHound / SharpHound AD collector"
        reference = "https://attack.mitre.org/software/S0521/"
    strings:
        $a1 = "BloodHound" nocase wide ascii
        $a2 = "SharpHound" nocase wide ascii
        $a3 = "HighvalueTargets" ascii
    condition:
        2 of them
}

rule OPHIRA_Hacktool_PowerSploit_Empire
{
    meta:
        severity = "high"
        description = "PowerSploit / Empire framework artifacts"
        reference = "https://attack.mitre.org/software/S0194/"
    strings:
        $a1 = "Invoke-Empire" nocase wide ascii
        $a2 = "PowerSploit" nocase wide ascii
        $a3 = "Get-GPPPassword" nocase wide ascii
        $a4 = "Invoke-NinjaCopy" nocase wide ascii
        $a5 = "Get-Keystrokes" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule OPHIRA_Hacktool_PwDump_Family
{
    meta:
        severity = "high"
        description = "Classic SAM dump tooling (pwdump/wce/gsecdump)"
    strings:
        $a1 = "pwdump" nocase wide ascii
        $a2 = "gsecdump" nocase wide ascii
        $a3 = "wce.exe" nocase wide ascii
        $a4 = "Windows Credentials Editor" nocase wide ascii
        $a5 = "lsassremote" ascii
    condition:
        2 of them
}

rule OPHIRA_Hacktool_Chisel_Tunnel
{
    meta:
        severity = "medium"
        description = "Chisel network tunnel tool"
    strings:
        $a1 = "chisel" nocase wide ascii
        $a2 = "jpillora" nocase ascii
        $a3 = "chisel_server" ascii
    condition:
        2 of them
}

rule OPHIRA_Hacktool_Frp_Proxy
{
    meta:
        severity = "medium"
        description = "frp fast reverse proxy client/server"
    strings:
        $a1 = "frpc.ini" ascii
        $a2 = "frps.ini" ascii
        $a3 = "fatedier/frp" ascii
    condition:
        2 of them
}

rule OPHIRA_DualUse_RemoteAdmin_Tool
{
    meta:
        severity = "low"
        description = "Common remote-admin/RAT-capable software in unexpected location (AnyDesk/TeamViewer/ScreenConnect/Ammyy)"
    strings:
        $a1 = "AnyDesk" nocase wide ascii
        $a2 = "TeamViewer" nocase wide ascii
        $a3 = "ScreenConnect" nocase wide ascii
        $a4 = "Ammyy" nocase wide ascii
        $a5 = "GoToHTTP" nocase wide ascii
        $a6 = "RustDesk" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule OPHIRA_DualUse_Network_Tool
{
    meta:
        severity = "low"
        description = "Dual-use network tooling (nmap/netcat/advanced scanner)"
    strings:
        $a1 = "Nmap Scripting Engine" ascii
        $a2 = "Ncat: A modern incarnation of Netcat" ascii
        $a3 = "Advanced IP Scanner" wide ascii
        $a4 = "Angry IP Scanner" wide ascii
    condition:
        1 of them
}

rule OPHIRA_Suspicious_Ransomware_Behavior_Strings
{
    meta:
        severity = "high"
        description = "PE embedding shadow-copy deletion / recovery tampering commands"
    strings:
        $a1 = "vssadmin delete shadows /all /quiet" nocase wide ascii
        $a2 = "wbadmin delete catalog -quiet" nocase wide ascii
        $a3 = "bcdedit /set {default} recoveryenabled no" nocase wide ascii
        $a4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase wide ascii
    condition:
        2 of them
}

rule OPHIRA_Suspicious_PS_Downloader_Embedded
{
    meta:
        severity = "medium"
        description = "PE embedding PowerShell download-cradle patterns"
    strings:
        $a1 = "FromBase64String" wide ascii
        $a2 = "DownloadString" wide ascii
        $a3 = "Net.WebClient" wide ascii
        $a4 = "IEX (" wide ascii
        $a5 = "-nop -w hidden -enc" wide ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule OPHIRA_Suspicious_PS_Downloader_Script
{
    meta:
        severity = "medium"
        description = "Script file with download-cradle / encoded command pattern"
    strings:
        $a1 = "IEX (New-Object Net.WebClient).DownloadString" nocase wide ascii
        $a2 = "Invoke-Expression (New-Object Net.WebClient).DownloadString" nocase wide ascii
        $a3 = "-nop -w hidden -enc" wide ascii
        $a4 = "Invoke-Obfuscation" wide ascii
    condition:
        filesize < 5MB and any of them
}

rule OPHIRA_Suspicious_Cryptominer
{
    meta:
        severity = "medium"
        description = "Cryptominer indicators (xmrg/stratum pool strings)"
    strings:
        $a1 = "stratum+tcp://" nocase wide ascii
        $a2 = "xmrig" nocase wide ascii
        $a3 = "donate.v2.xmrig.com" nocase ascii
        $a4 = "pool.minexmr.com" nocase ascii
    condition:
        2 of them
}

rule OPHIRA_Suspicious_Keylogger_Strings
{
    meta:
        severity = "medium"
        description = "Keylogger-indicative API/keyword cluster"
    strings:
        $a1 = "GetAsyncKeyState" wide ascii
        $a2 = "SetWindowsHookEx" wide ascii
        $a3 = "keylog" nocase wide ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}
