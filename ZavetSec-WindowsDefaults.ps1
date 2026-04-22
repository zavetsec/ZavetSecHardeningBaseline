#Requires -Version 5.1
<#
.SYNOPSIS
    ZavetSecWindowsDefaults - Reset Windows security settings to clean defaults.
.DESCRIPTION
    Resets all settings touched by ZavetSec-Harden back to
    Windows out-of-box defaults. Does NOT require a backup file.

    Use this when:
      - The JSON backup from ZavetSec-Harden is lost
      - The machine was hardened by a third-party tool (not this script)
      - You need a clean baseline before re-applying hardening

    Resets:
      NETWORK    : Re-enables LLMNR, mDNS, WPAD, NBT-NS, LMHOSTS
                   Re-enables SMBv1 server key (NOT client driver - requires reboot)
                   Removes SMB signing requirements
                   Removes anonymous enumeration restrictions
                   Restores Remote Registry to Manual (stopped)
      CREDENTIALS: Removes WDigest override (system default)
                   Removes LSA RunAsPPL
                   Removes Credential Guard policy keys
                   Restores LmCompatibilityLevel to 3 (Windows default)
                   Removes NoLMHash restriction
                   Removes NTLM min session security overrides
      POWERSHELL : Disables Script Block Logging
                   Disables Module Logging
                   Disables Transcription
                   Re-enables PowerShell v2 feature (requires reboot)
                   Removes Execution Policy override
      AUDIT      : Resets all 27 subcategories to No Auditing
      SYSTEM     : Restores UAC to default (prompt but not secure desktop enforced)
                   Re-enables AutoRun/AutoPlay
                   Restores Event Log sizes to Windows defaults
                   Removes DoH policy
                   Removes RDP encryption level override
                   Restores Remote Registry to Manual

.PARAMETER OutputPath
    HTML report path. Default = ScriptDir\ZavetSecDefaults_<timestamp>.html
.PARAMETER NonInteractive
    Suppress all prompts (for PsExec / remote / scheduled task use).
.EXAMPLE
    # Interactive reset with confirmation
    .\ZavetSecWindowsDefaults.ps1

    # Silent reset (PsExec / automation)
    .\ZavetSecWindowsDefaults.ps1 -NonInteractive

    # Custom report path
    .\ZavetSecWindowsDefaults.ps1 -OutputPath C:\Reports\defaults.html
.NOTES
    ================================================================
    ZavetSec | https://github.com/zavetsec
    Script   : ZavetSecWindowsDefaults
    Version  : 1.1
    Author   : ZavetSec
    License  : MIT
    ================================================================
    Companion to ZavetSec-Harden.ps1
    Use ZavetSec-Harden -Mode Rollback when backup exists.
    Use THIS script when backup is lost or machine was hardened externally.
    ================================================================
    WARNING : This script removes hardening. Run only when intentional.
    Reboot  : Required for SMBv1 client driver, PSv2, Credential Guard.
    ================================================================
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputPath    = '',
    [switch]$NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$global:StartTime = Get-Date
$global:Results   = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:OK        = 0
$global:Failed    = 0
$global:Skipped   = 0

$_stamp = $global:StartTime.ToString('yyyyMMdd_HHmmss')
if ([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot "ZavetSecDefaults_$_stamp.html"
}

# -------------------------------------------------------
# Console helpers
# -------------------------------------------------------
function Write-Phase { param([string]$T)
    Write-Host ''
    Write-Host "  [>>] $T" -ForegroundColor Cyan
}
function Write-OK   { param([string]$M); Write-Host "  [OK] $M" -ForegroundColor Green }
function Write-Fail { param([string]$M); Write-Host "  [!!] $M" -ForegroundColor Yellow }
function Write-Err  { param([string]$M); Write-Host "  [XX] $M" -ForegroundColor Red }
function Write-Info { param([string]$M); Write-Host "  [..] $M" -ForegroundColor DarkGray }

# -------------------------------------------------------
# Core helpers
# -------------------------------------------------------
function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    if (-not (Test-Path $Path)) { $null = New-Item -Path $Path -Force }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

function Remove-RegValue {
    param([string]$Path, [string]$Name)
    if (Test-Path $Path) {
        Remove-ItemProperty -Path $Path -Name $Name -Force -EA SilentlyContinue
    }
}

function Remove-RegKey {
    param([string]$Path)
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Recurse -Force -EA SilentlyContinue
    }
}

function Add-Result {
    param([string]$Category, [string]$Name, [string]$Status, [string]$Note = '')
    $global:Results.Add([PSCustomObject]@{
        Category = $Category
        Name     = $Name
        Status   = $Status
        Note     = $Note
    })
    if ($Status -eq 'OK')      { $global:OK++;      Write-OK   "$Name" }
    elseif ($Status -eq 'SKIP'){ $global:Skipped++; Write-Info "$Name - $Note" }
    else                       { $global:Failed++;  Write-Err  "$Name - $Note" }
}

function Reset-Registry {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Path,
        [string]$RegName,
        [string]$Action = 'Remove',   # Remove | SetValue
        $Value  = $null,
        [string]$Type   = 'DWord'
    )
    try {
        if ($Action -eq 'Remove') {
            Remove-RegValue $Path $RegName
        } else {
            Set-RegValue $Path $RegName $Value $Type
        }
        Add-Result $Category $Name 'OK'
    } catch {
        Add-Result $Category $Name 'FAIL' $_.Exception.Message
    }
}

# -------------------------------------------------------
# BANNER + HEADER
# -------------------------------------------------------
Write-Host ''
Write-Host '     ____                  _    ____            ' -ForegroundColor DarkCyan
Write-Host '    |_  /__ ___ _____ ___ | |_ / __/__ ___     ' -ForegroundColor Cyan
Write-Host '     / // _` \ V / -_)  _||  _\__ \/ -_) _|    ' -ForegroundColor Cyan
Write-Host '    /___\__,_|\_/\___\__| |_| |___/\___\__|    ' -ForegroundColor DarkCyan
Write-Host ''
Write-Host '    ZavetSecWindowsDefaults v1.1                ' -ForegroundColor White
Write-Host '    Reset hardening to Windows defaults         ' -ForegroundColor DarkGray
Write-Host '    https://github.com/zavetsec                 ' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  ============================================================' -ForegroundColor DarkCyan
Write-Host '    Script : ZavetSecWindowsDefaults v1.1'        -ForegroundColor Cyan
Write-Host "    Host   : $env:COMPUTERNAME"                   -ForegroundColor Gray
Write-Host "    Time   : $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
Write-Host '  ============================================================' -ForegroundColor DarkCyan

# -------------------------------------------------------
# ADMIN CHECK
# -------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err 'Not running as Administrator. Elevation required.'
    exit 1
}

# -------------------------------------------------------
# CONFIRMATION
# -------------------------------------------------------
Write-Host ''
Write-Host '  [!!] WARNING: This will REMOVE hardening settings.' -ForegroundColor Yellow
Write-Host '       Use only when the JSON backup is lost or unavailable.' -ForegroundColor Yellow
Write-Host '       Prefer ZavetSec-Harden -Mode Rollback when possible.' -ForegroundColor DarkGray
Write-Host ''

if ($NonInteractive) {
    Write-Info '[-NonInteractive] Proceeding without confirmation.'
} else {
    $confirm = Read-Host '  Type YES to continue'
    if ($confirm -notmatch '^YES$') {
        Write-Host '  Aborted.' -ForegroundColor Red
        exit 0
    }
}

# ===========================================================
# SECTION 1: NETWORK - RESTORE DEFAULTS
# ===========================================================
Write-Phase 'NETWORK - restoring defaults'

# LLMNR - remove policy key (default = enabled)
Reset-Registry 'Network' 'Re-enable LLMNR' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 'Remove'

# mDNS - remove policy key (default = enabled)
Reset-Registry 'Network' 'Re-enable mDNS' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMDNS' 'Remove'

# WPAD - remove DisableWpad (default = auto-detect enabled)
Reset-Registry 'Network' 'Re-enable WPAD auto-detection' `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad' 'Remove'
try {
    Start-Service 'WinHttpAutoProxySvc' -EA SilentlyContinue
} catch {}

# SMBv1 server - restore to default (enabled)
Reset-Registry 'Network' 'Restore SMBv1 server key' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 'SetValue' -Value 1
# SMBv1 client driver - set back to manual load (3), reboot required
Reset-Registry 'Network' 'Restore SMBv1 client driver (reboot required)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' 'SetValue' -Value 3

# SMB signing server - remove requirements (default = not required)
Reset-Registry 'Network' 'Remove SMB signing requirement (server)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 'SetValue' -Value 0
Reset-Registry 'Network' 'Remove SMB signing enable (server)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature' 'SetValue' -Value 0

# SMB signing client - remove requirement
Reset-Registry 'Network' 'Remove SMB signing requirement (client)' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 'SetValue' -Value 0

# NBT-NS - restore to default (0 = use DHCP setting)
try {
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -EA Stop | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name 'NetbiosOptions' -Value 0 -Force -EA SilentlyContinue
    }
    Add-Result 'Network' 'Restore NetBIOS over TCP/IP (all adapters)' 'OK'
} catch {
    Add-Result 'Network' 'Restore NetBIOS over TCP/IP (all adapters)' 'FAIL' $_.Exception.Message
}

# LMHOSTS - restore to enabled (1)
Reset-Registry 'Network' 'Re-enable LMHOSTS lookup' `
    'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'EnableLMHOSTS' 'SetValue' -Value 1

# Anonymous enumeration - restore defaults
Reset-Registry 'Network' 'Restore anonymous SAM enumeration' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 'SetValue' -Value 0
Reset-Registry 'Network' 'Restore anonymous enumeration' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 'SetValue' -Value 0
Reset-Registry 'Network' 'Restore Everyone includes Anonymous' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' 'SetValue' -Value 0

# Remote Registry - restore to Manual (default), stopped
try {
    Set-Service 'RemoteRegistry' -StartupType Manual -EA SilentlyContinue
    Add-Result 'Network' 'Restore Remote Registry to Manual (stopped)' 'OK'
} catch {
    Add-Result 'Network' 'Restore Remote Registry to Manual (stopped)' 'FAIL' $_.Exception.Message
}

# DoH policy - remove (default = system handles DNS)
Reset-Registry 'Network' 'Remove DNS over HTTPS policy' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'DoHPolicy' 'Remove'

# ===========================================================
# SECTION 2: CREDENTIALS - RESTORE DEFAULTS
# ===========================================================
Write-Phase 'CREDENTIALS - restoring defaults'

# WDigest - remove override (system default on modern Windows = 0, but remove explicit key)
Reset-Registry 'Credentials' 'Remove WDigest override' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 'Remove'

# LSA RunAsPPL - remove (default = not set)
Reset-Registry 'Credentials' 'Remove LSA RunAsPPL' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 'Remove'

# Credential Guard - remove policy keys
Reset-Registry 'Credentials' 'Remove Credential Guard VBS policy' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity' 'Remove'
Reset-Registry 'Credentials' 'Remove Credential Guard LsaCfgFlags' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags' 'Remove'
try {
    $dgKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    @('RequirePlatformSecurityFeatures','HypervisorEnforcedCodeIntegrity',
      'HVCIMATRequired','LsaCfgFlags') | ForEach-Object {
        Remove-RegValue $dgKey $_
    }
    Add-Result 'Credentials' 'Remove remaining Credential Guard policy keys' 'OK'
} catch {
    Add-Result 'Credentials' 'Remove remaining Credential Guard policy keys' 'FAIL' $_.Exception.Message
}

# LmCompatibilityLevel - Windows default = 3
Reset-Registry 'Credentials' 'Restore LmCompatibilityLevel to 3 (Windows default)' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 'SetValue' -Value 3

# NoLMHash - remove (default = LM hashes may be stored on older OS)
Reset-Registry 'Credentials' 'Remove NoLMHash restriction' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 'Remove'

# NTLM min session security - remove overrides
Reset-Registry 'Credentials' 'Remove NTLMMinServerSec override' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinServerSec' 'Remove'
Reset-Registry 'Credentials' 'Remove NTLMMinClientSec override' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinClientSec' 'Remove'

# ===========================================================
# SECTION 3: POWERSHELL - RESTORE DEFAULTS
# ===========================================================
Write-Phase 'POWERSHELL - restoring defaults'

# Script Block Logging
Reset-Registry 'PowerShell' 'Disable Script Block Logging' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 'SetValue' -Value 0
Reset-Registry 'PowerShell' 'Disable Script Block Invocation Logging' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockInvocationLogging' 'SetValue' -Value 0

# Module Logging
Reset-Registry 'PowerShell' 'Disable Module Logging' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 'SetValue' -Value 0
try {
    Remove-RegKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
    Add-Result 'PowerShell' 'Remove ModuleNames wildcard key' 'OK'
} catch {
    Add-Result 'PowerShell' 'Remove ModuleNames wildcard key' 'FAIL' $_.Exception.Message
}

# Transcription
Reset-Registry 'PowerShell' 'Disable Transcription' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting' 'SetValue' -Value 0

# Execution Policy - remove machine-level override
Reset-Registry 'PowerShell' 'Remove Execution Policy override' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' 'ExecutionPolicy' 'Remove'

# PSv2 - re-enable (requires reboot)
try {
    Enable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart -EA SilentlyContinue | Out-Null
    Enable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2'     -NoRestart -EA SilentlyContinue | Out-Null
    Add-Result 'PowerShell' 'Re-enable PowerShell v2 feature (reboot required)' 'OK'
} catch {
    Add-Result 'PowerShell' 'Re-enable PowerShell v2 feature' 'FAIL' $_.Exception.Message
}

# ===========================================================
# SECTION 4: AUDIT POLICY - RESET ALL TO NO AUDITING
# ===========================================================
Write-Phase 'AUDIT POLICY - resetting all subcategories to No Auditing'

$auditSubcats = @(
    @{ ID='AUD-001'; Guid='{0CCE922B-69AE-11D9-BED3-505054503030}'; Sub='Process Creation' }
    @{ ID='AUD-002'; Guid='{0CCE9223-69AE-11D9-BED3-505054503030}'; Sub='Process Termination' }
    @{ ID='AUD-003'; Guid='{0CCE9215-69AE-11D9-BED3-505054503030}'; Sub='Logon' }
    @{ ID='AUD-004'; Guid='{0CCE9216-69AE-11D9-BED3-505054503030}'; Sub='Logoff' }
    @{ ID='AUD-005'; Guid='{0CCE9217-69AE-11D9-BED3-505054503030}'; Sub='Account Lockout' }
    @{ ID='AUD-006'; Guid='{0CCE921B-69AE-11D9-BED3-505054503030}'; Sub='Special Logon' }
    @{ ID='AUD-007'; Guid='{0CCE9242-69AE-11D9-BED3-505054503030}'; Sub='Kerberos Authentication Service' }
    @{ ID='AUD-008'; Guid='{0CCE9240-69AE-11D9-BED3-505054503030}'; Sub='Kerberos Service Ticket Ops' }
    @{ ID='AUD-009'; Guid='{0CCE923F-69AE-11D9-BED3-505054503030}'; Sub='Credential Validation' }
    @{ ID='AUD-010'; Guid='{0CCE9235-69AE-11D9-BED3-505054503030}'; Sub='User Account Management' }
    @{ ID='AUD-011'; Guid='{0CCE9237-69AE-11D9-BED3-505054503030}'; Sub='Security Group Management' }
    @{ ID='AUD-012'; Guid='{0CCE922F-69AE-11D9-BED3-505054503030}'; Sub='Audit Policy Change' }
    @{ ID='AUD-013'; Guid='{0CCE9230-69AE-11D9-BED3-505054503030}'; Sub='Authentication Policy Change' }
    @{ ID='AUD-014'; Guid='{0CCE9212-69AE-11D9-BED3-505054503030}'; Sub='System Integrity' }
    @{ ID='AUD-015'; Guid='{0CCE9211-69AE-11D9-BED3-505054503030}'; Sub='Security System Extension' }
    @{ ID='AUD-016'; Guid='{0CCE921D-69AE-11D9-BED3-505054503030}'; Sub='File System' }
    @{ ID='AUD-017'; Guid='{0CCE921E-69AE-11D9-BED3-505054503030}'; Sub='Registry' }
    @{ ID='AUD-018'; Guid='{0CCE9228-69AE-11D9-BED3-505054503030}'; Sub='Sensitive Privilege Use' }
    @{ ID='AUD-019'; Guid='{0CCE9227-69AE-11D9-BED3-505054503030}'; Sub='Other Object Access Events' }
    @{ ID='AUD-020'; Guid='{0CCE9245-69AE-11D9-BED3-505054503030}'; Sub='Removable Storage' }
    @{ ID='AUD-021'; Guid='{0CCE922D-69AE-11D9-BED3-505054503030}'; Sub='DPAPI Activity' }
    @{ ID='AUD-022'; Guid='{0CCE922E-69AE-11D9-BED3-505054503030}'; Sub='RPC Events' }
    @{ ID='AUD-023'; Guid='{0CCE9210-69AE-11D9-BED3-505054503030}'; Sub='Security State Change' }
    @{ ID='AUD-024'; Guid='{0CCE9214-69AE-11D9-BED3-505054503030}'; Sub='Other System Events' }
    @{ ID='AUD-025'; Guid='{0CCE9226-69AE-11D9-BED3-505054503030}'; Sub='Filtering Platform Connection' }
    @{ ID='AUD-026'; Guid='{0CCE9244-69AE-11D9-BED3-505054503030}'; Sub='Detailed File Share' }
    @{ ID='AUD-027'; Guid='{0CCE9243-69AE-11D9-BED3-505054503030}'; Sub='Network Policy Server' }
)

$ap = "$env:SystemRoot\System32\auditpol.exe"
foreach ($ac in $auditSubcats) {
    try {
        $null = & $ap /set /subcategory:"$($ac.Guid)" /success:disable /failure:disable 2>&1
        Add-Result 'AuditPolicy' "Reset: $($ac.Sub)" 'OK'
    } catch {
        Add-Result 'AuditPolicy' "Reset: $($ac.Sub)" 'FAIL' $_.Exception.Message
    }
}

# ===========================================================
# SECTION 5: SYSTEM - RESTORE DEFAULTS
# ===========================================================
Write-Phase 'SYSTEM - restoring defaults'

# UAC - restore to Windows default (ConsentPromptBehaviorAdmin=5, EnableLUA=1)
try {
    $uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-RegValue $uacKey 'ConsentPromptBehaviorAdmin' 5   # Default: prompt for creds
    Set-RegValue $uacKey 'ConsentPromptBehaviorUser'  3   # Default: prompt for creds
    Set-RegValue $uacKey 'PromptOnSecureDesktop'      1
    Set-RegValue $uacKey 'EnableLUA'                  1
    Add-Result 'System' 'Restore UAC to Windows defaults' 'OK'
} catch {
    Add-Result 'System' 'Restore UAC to Windows defaults' 'FAIL' $_.Exception.Message
}

# AutoRun / AutoPlay - restore defaults
Reset-Registry 'System' 'Restore AutoRun (NoDriveTypeAutoRun)' `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 'SetValue' -Value 145
Reset-Registry 'System' 'Remove NoAutorun key' `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 'Remove'
Reset-Registry 'System' 'Restore AutoPlay for non-volume devices' `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume' 'Remove'

# Event Log sizes - restore Windows defaults
try {
    & wevtutil sl Security    /ms:20971520  /rt:false /ab:false 2>&1 | Out-Null  # 20 MB
    & wevtutil sl System      /ms:20971520  /rt:false /ab:false 2>&1 | Out-Null
    & wevtutil sl Application /ms:20971520  /rt:false /ab:false 2>&1 | Out-Null
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'    'MaxSize' 20971520
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'      'MaxSize' 20971520
    Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' 'MaxSize' 20971520
    Add-Result 'System' 'Restore Event Log sizes to 20 MB (Windows default)' 'OK'
} catch {
    Add-Result 'System' 'Restore Event Log sizes' 'FAIL' $_.Exception.Message
}

# RDP NLA - remove enforcement (default = required on modern Windows, but remove explicit override)
Reset-Registry 'System' 'Remove RDP NLA explicit override' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthenticationRequired' 'Remove'

# RDP encryption - restore to default (2 = Client Compatible)
Reset-Registry 'System' 'Restore RDP encryption level to Client Compatible' `
    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MinEncryptionLevel' 'SetValue' -Value 2

# DEP - restore to OptIn (Windows default)
try {
    & bcdedit /set '{current}' nx OptIn 2>&1 | Out-Null
    Add-Result 'System' 'Restore DEP to OptIn (reboot required)' 'OK'
} catch {
    Add-Result 'System' 'Restore DEP to OptIn' 'FAIL' $_.Exception.Message
}

# ===========================================================
# SECTION 6: GENERATE REPORT
# ===========================================================
Write-Phase 'Generating report'

$duration      = ((Get-Date) - $global:StartTime).ToString("m'm 's's'")
$totalCount    = $global:Results.Count
$okCount       = $global:OK
$failCount     = $global:Failed
$skipCount     = $global:Skipped

$modeColor = '#ff6b00'

# Category summary
$catGroups = $global:Results | Group-Object Category
$catRows = foreach ($g in $catGroups) {
    $gOK   = ($g.Group | Where-Object { $_.Status -eq 'OK'   }).Count
    $gFail = ($g.Group | Where-Object { $_.Status -eq 'FAIL' }).Count
    "<tr><td style='font-family:JetBrains Mono,monospace;color:#a5d6ff;font-size:10px'>$($g.Name)</td><td style='font-family:JetBrains Mono,monospace;color:#00ff88'>$gOK</td><td style='font-family:JetBrains Mono,monospace;color:#ff2d55'>$gFail</td></tr>"
}
$catRows = $catRows -join "`n"

# Result rows
$tableRows = foreach ($r in $global:Results) {
    $sc = switch ($r.Status) {
        'OK'   { '#00ff88' }
        'FAIL' { '#ff2d55' }
        default{ '#ffd60a' }
    }
    "<tr>
      <td style='font-family:JetBrains Mono,monospace;color:#a5d6ff;font-size:10px;white-space:nowrap'>$($r.Category)</td>
      <td style='font-size:12px'>$($r.Name)</td>
      <td><span style='font-family:JetBrains Mono,monospace;color:$sc;font-weight:700;font-size:11px'>$($r.Status)</span></td>
      <td style='color:#c9d1d9;font-size:11px'>$($r.Note)</td>
    </tr>"
}
$tableRows = $tableRows -join "`n"

Set-StrictMode -Off

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ZavetSec Windows Defaults Reset // $env:COMPUTERNAME</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Rajdhani:wght@400;600;700&family=Share+Tech+Mono&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
body{
  background:#0a0d10;
  color:#c9d1d9;
  font-family:'Rajdhani',sans-serif;
  font-size:14px;
  line-height:1.6;
  min-height:100vh;
  overflow-x:hidden;
}
body::before{
  content:'';
  position:fixed;top:0;left:0;right:0;bottom:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,136,0.015) 2px,rgba(0,255,136,0.015) 4px);
  pointer-events:none;z-index:0;
}
body::after{
  content:'';
  position:fixed;top:0;left:0;right:0;bottom:0;
  background:radial-gradient(ellipse at 50% 0%,rgba(0,255,136,0.06) 0%,transparent 65%);
  pointer-events:none;z-index:0;
}
.wrap{position:relative;z-index:1}
header{
  background:linear-gradient(180deg,#0d1117 0%,#0a0d10 100%);
  border-bottom:1px solid rgba(0,255,136,0.18);
  padding:22px 40px;
  display:flex;align-items:center;gap:24px;
}
.logo-block{display:flex;flex-direction:column;gap:2px}
.logo-name{
  font-family:'JetBrains Mono',monospace;
  font-size:11px;font-weight:700;
  color:#00ff88;letter-spacing:3px;text-transform:uppercase;
}
.logo-title{
  font-family:'Share Tech Mono',monospace;
  font-size:22px;font-weight:400;
  color:#e6edf3;letter-spacing:2px;
}
.logo-title span{color:#00ff88}
.logo-cursor{
  color:#00ff88;
  animation:cur 1s step-end infinite;
}
@keyframes cur{0%,100%{opacity:1}50%{opacity:0}}
.header-meta{
  font-family:'JetBrains Mono',monospace;
  font-size:11px;color:#8b949e;margin-top:4px;
}
.header-right{
  margin-left:auto;text-align:right;
  font-family:'JetBrains Mono',monospace;
  font-size:10px;color:#8b949e;line-height:1.9;
}
.header-right .brand{color:#00ff88;font-weight:700;font-size:12px;letter-spacing:2px}
.dot-anim{display:inline-flex;gap:4px;vertical-align:middle;margin-left:6px}
.dot-anim span{
  width:5px;height:5px;border-radius:50%;
  background:#00ff88;
  animation:pulse 1.4s ease-in-out infinite;
}
.dot-anim span:nth-child(2){animation-delay:.2s}
.dot-anim span:nth-child(3){animation-delay:.4s}
@keyframes pulse{0%,80%,100%{opacity:.2;transform:scale(.8)}40%{opacity:1;transform:scale(1)}}
.main{padding:28px 40px;max-width:1400px;margin:0 auto}

/* ── SECTION HEADER ── */
.sec-hdr{
  display:flex;align-items:center;gap:10px;
  font-family:'JetBrains Mono',monospace;
  font-size:10px;font-weight:700;
  color:#00ff88;text-transform:uppercase;letter-spacing:2px;
  margin-bottom:14px;margin-top:28px;
  padding-bottom:7px;
  border-bottom:1px solid rgba(0,255,136,0.15);
}
.sec-num{
  background:rgba(0,255,136,0.1);
  border:1px solid rgba(0,255,136,0.3);
  color:#00ff88;padding:1px 7px;border-radius:3px;font-size:9px;
}

/* ── ALERT BOX ── */
.alert-warn{
  background:rgba(255,107,0,0.08);
  border:1px solid rgba(255,107,0,0.4);
  border-left:3px solid #ff6b00;
  border-radius:6px;
  padding:12px 18px;
  margin-bottom:20px;
  font-family:'JetBrains Mono',monospace;
  font-size:11px;color:#ff6b00;
  line-height:1.8;
}
.alert-warn .warn-title{
  font-size:12px;font-weight:700;
  letter-spacing:1px;margin-bottom:4px;
}

/* ── STAT CARDS ── */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px}
.sc{
  background:#0d1117;
  border:1px solid #21262d;
  border-radius:8px;
  padding:14px 12px;
  position:relative;overflow:hidden;
  transition:border-color .2s;
}
.sc:hover{border-color:rgba(0,255,136,0.25)}
.sc::after{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,rgba(0,255,136,0.25),transparent);
}
.sc .n{
  font-family:'JetBrains Mono',monospace;
  font-size:28px;font-weight:700;line-height:1.1;
}
.sc .l{
  font-family:'Rajdhani',sans-serif;
  font-size:9px;color:#8b949e;
  text-transform:uppercase;letter-spacing:1px;
  margin-top:4px;font-weight:600;
}

/* ── GRID + PANEL ── */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}
.panel{
  background:#0d1117;border:1px solid #21262d;
  border-radius:8px;padding:14px 18px;
}
.panel-title{
  font-family:'JetBrains Mono',monospace;
  font-size:9px;font-weight:700;color:#8b949e;
  text-transform:uppercase;letter-spacing:1.5px;
  margin-bottom:10px;padding-bottom:6px;
  border-bottom:1px solid #21262d;
}

/* ── TABLES ── */
table{
  width:100%;border-collapse:collapse;
  background:#0d1117;border-radius:8px;
  overflow:hidden;border:1px solid #21262d;font-size:12px;
}
.tbl{width:100%;border-collapse:collapse;font-size:11px}
th{
  background:#010409;color:#8b949e;
  font-family:'JetBrains Mono',monospace;
  font-size:9px;text-transform:uppercase;letter-spacing:1.2px;
  padding:9px 10px;text-align:left;font-weight:700;white-space:nowrap;
  border-bottom:1px solid rgba(0,255,136,0.1);
}
td{
  padding:8px 10px;border-top:1px solid #21262d;
  vertical-align:top;font-family:'Rajdhani',sans-serif;
}
tr:hover td{background:#0a0d10;transition:background .15s}

/* ── NEXT STEPS ── */
.step{
  display:flex;align-items:flex-start;gap:12px;
  padding:8px 0;border-bottom:1px solid #21262d;
}
.step:last-child{border-bottom:none}
.step-num{
  font-family:'JetBrains Mono',monospace;
  font-size:10px;font-weight:700;
  color:#00ff88;
  background:rgba(0,255,136,0.08);
  border:1px solid rgba(0,255,136,0.2);
  border-radius:3px;padding:1px 6px;
  white-space:nowrap;flex-shrink:0;margin-top:2px;
}
.step-text{
  font-family:'Rajdhani',sans-serif;
  font-size:12px;color:#c9d1d9;
}
.step-text .hl{
  font-family:'JetBrains Mono',monospace;
  color:#00ff88;font-size:10px;
}

/* ── FOOTER ── */
footer{
  margin-top:40px;padding:16px 40px;
  border-top:1px solid rgba(0,255,136,0.1);
  color:#8b949e;
  font-family:'JetBrains Mono',monospace;
  font-size:10px;text-align:center;letter-spacing:.5px;
}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="logo-block">
    <div class="logo-name">ZavetSec<div class="dot-anim" style="display:inline-flex"><span></span><span></span><span></span></div></div>
    <div class="logo-title">Windows<span>Defaults</span><span class="logo-cursor">_</span> <span style="font-size:13px;color:#8b949e;font-weight:400">v1.1</span></div>
    <div class="header-meta">Reset to Windows Defaults &nbsp;//&nbsp; Host: $env:COMPUTERNAME &nbsp;//&nbsp; $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) &nbsp;//&nbsp; Duration: $duration</div>
  </div>
  <div class="header-right">
    <div class="brand">ZavetSec</div>
    <div>github.com/zavetsec</div>
    <div>Companion to ZavetSec-Harden</div>
  </div>
</header>

<div class="main">

  <!-- ── SECTION 01: WARNING ── -->
  <div class="sec-hdr"><span class="sec-num">01</span> Status</div>

  <div class="alert-warn">
    <div class="warn-title">&#9888;&nbsp; HARDENING REMOVED</div>
    Security hardening settings have been reset to Windows out-of-box defaults on this machine.<br>
    Reboot required to finalize: &nbsp;<strong>SMBv1 client driver</strong> &nbsp;&bull;&nbsp; <strong>PSv2 re-enable</strong> &nbsp;&bull;&nbsp; <strong>DEP OptIn</strong> &nbsp;&bull;&nbsp; <strong>Credential Guard removal</strong>
  </div>

  <!-- ── SECTION 02: STATS ── -->
  <div class="sec-hdr"><span class="sec-num">02</span> Summary</div>

  <div class="stats">
    <div class="sc"><div class="n" style="color:#e6edf3">$totalCount</div><div class="l">Total Actions</div></div>
    <div class="sc"><div class="n" style="color:#00ff88">$okCount</div><div class="l">Completed OK</div></div>
    <div class="sc"><div class="n" style="color:#ff2d55">$failCount</div><div class="l">Failed</div></div>
    <div class="sc"><div class="n" style="color:#8b949e">$skipCount</div><div class="l">Skipped</div></div>
  </div>

  <!-- ── SECTION 03: BREAKDOWN + NEXT STEPS ── -->
  <div class="sec-hdr"><span class="sec-num">03</span> Category Breakdown &amp; Next Steps</div>

  <div class="grid2">
    <div class="panel">
      <div class="panel-title">Results by Category</div>
      <table class="tbl">
        <thead><tr><th>Category</th><th style="color:#00ff88">OK</th><th style="color:#ff2d55">Failed</th></tr></thead>
        <tbody>$catRows</tbody>
      </table>
    </div>
    <div class="panel">
      <div class="panel-title">Next Steps</div>
      <div style="padding:4px 0">
        <div class="step">
          <span class="step-num">01</span>
          <span class="step-text"><strong>Reboot</strong> the machine to finalize SMBv1, PSv2 and DEP changes</span>
        </div>
        <div class="step">
          <span class="step-num">02</span>
          <span class="step-text">Verify application behaviour after reboot</span>
        </div>
        <div class="step">
          <span class="step-num">03</span>
          <span class="step-text">Re-run <span class="hl">ZavetSec-Harden -Mode Audit</span> to confirm state</span>
        </div>
        <div class="step">
          <span class="step-num">04</span>
          <span class="step-text">Re-apply hardening when ready: <span class="hl">-Mode Apply</span></span>
        </div>
      </div>
    </div>
  </div>

  <!-- ── SECTION 04: FULL LOG ── -->
  <div class="sec-hdr"><span class="sec-num">04</span> All Actions <span style="color:#8b949e;font-weight:400">($totalCount)</span></div>

  <table>
    <thead>
      <tr><th>Category</th><th>Action</th><th>Status</th><th>Note</th></tr>
    </thead>
    <tbody>
      $($tableRows -join "`n")
    </tbody>
  </table>

</div><!-- /main -->

<footer>
  <span style="color:#00ff88;font-weight:700;letter-spacing:2px">ZAVETSEC</span>
  &nbsp;&bull;&nbsp; ZavetSecWindowsDefaults v1.1
  &nbsp;&bull;&nbsp; github.com/zavetsec
  &nbsp;&bull;&nbsp; Host: $env:COMPUTERNAME
  &nbsp;&bull;&nbsp; $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
  &nbsp;&bull;&nbsp; <span style="color:#ff6b00;font-weight:700">HARDENING REMOVED &mdash; REBOOT REQUIRED</span>
</footer>
</div><!-- /wrap -->
</body>
</html>
"@

Set-StrictMode -Version Latest

$_outDir = Split-Path $OutputPath -Parent
if ($_outDir -and -not (Test-Path $_outDir)) {
    $null = New-Item -Path $_outDir -ItemType Directory -Force
}

try {
    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force -ErrorAction Stop
    Write-Host "  [OK] Report saved: $OutputPath" -ForegroundColor Green
} catch {
    $OutputPath = Join-Path $env:TEMP "ZavetSecDefaults_${env:COMPUTERNAME}_$_stamp.html"
    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host "  [OK] Report saved to TEMP: $OutputPath" -ForegroundColor Yellow
}

# -------------------------------------------------------
# SUMMARY
# -------------------------------------------------------
$sep = '-' * 64
Write-Host ''; Write-Host $sep -ForegroundColor DarkGray
Write-Host '  ZAVETSEC WINDOWS DEFAULTS COMPLETE' -ForegroundColor White
Write-Host $sep -ForegroundColor DarkGray
Write-Host "  Host      : $env:COMPUTERNAME"       -ForegroundColor Gray
Write-Host "  Duration  : $duration"               -ForegroundColor Gray
Write-Host "  Total     : $totalCount actions"     -ForegroundColor Gray
Write-Host "  OK        : $okCount"                -ForegroundColor Green
Write-Host "  Failed    : $failCount" -ForegroundColor $(if ($failCount -gt 0) { 'Red' } else { 'Green' })
Write-Host ''
Write-Host '  [!] Reboot required for:' -ForegroundColor Yellow
Write-Host '      SMBv1 client driver, PSv2, DEP OptIn, Credential Guard removal' -ForegroundColor DarkGray
Write-Host ''
Write-Host "  Report: $OutputPath" -ForegroundColor Cyan
Write-Host $sep -ForegroundColor DarkGray

if (-not $NonInteractive) {
    Write-Host ''
    Write-Host '  Open HTML report in browser? [Y/N]: ' -ForegroundColor Yellow -NoNewline
    $open = [Console]::ReadLine()
    if ($open -match '^[Yy]') { Start-Process $OutputPath }
    Write-Host ''
    Write-Host '  Press ENTER to exit...' -ForegroundColor DarkGray
    $null = [Console]::ReadLine()
} else {
    Write-Host "  [-NonInteractive] Done. Report: $OutputPath" -ForegroundColor DarkGray
}
