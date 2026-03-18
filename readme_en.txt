================================================================================
  ZavetSec | HardeningBaseline v1.0
  Windows Security Hardening Baseline -- Quick Reference (English)
  https://github.com/zavetsec
================================================================================

DESCRIPTION
-----------
ZavetSecHardeningBaseline is a PowerShell 5.1 script that audits and enforces
Windows security hardening settings on workstations and servers. Covers CIS
Benchmark L1/L2, DISA STIG, and Microsoft Security Baseline requirements,
mapped to MITRE ATT&CK techniques. Designed for both manual interactive use
(via BAT launcher) and mass deployment via PsExec, scheduled tasks, or
automation pipelines.

FILES
-----
  ZavetSecHardeningBaseline.ps1   Main script
  Run-Hardening.bat               Interactive launcher with menu (recommended
                                  for manual use on individual machines)

QUICKSTART
----------

  METHOD 1 -- BAT LAUNCHER (recommended for manual use)
  -------------------------------------------------------
  Right-click Run-Hardening.bat -> "Run as administrator"

  A menu appears:
    [1] AUDIT    -- check current state, no changes made
    [2] APPLY    -- apply all hardening settings
    [3] ROLLBACK -- restore previous state from a backup file
    [4] EXIT

  The launcher automatically:
    - Verifies Administrator rights before proceeding
    - Creates a Reports\ subfolder next to the scripts
    - Saves timestamped HTML reports and JSON backups to Reports\
    - Offers to open the HTML report in browser after each run
    - In ROLLBACK mode: lists available backup files by number,
      no manual path entry required

  METHOD 2 -- POWERSHELL DIRECTLY
  ---------------------------------
  # Audit only (no changes)
  .\ZavetSecHardeningBaseline.ps1 -Mode Audit

  # Apply hardening (interactive confirmation)
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply

  # Apply without prompts (PsExec / scheduled task / automation)
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply -NonInteractive

  # Apply with custom paths
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply `
      -OutputPath C:\Reports\hardening.html `
      -BackupPath C:\Reports\backup.json

  # Rollback
  .\ZavetSecHardeningBaseline.ps1 -Mode Rollback `
      -BackupPath .\Reports\HardeningBackup_20260318_120000.json

  # Skip individual sections
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply -SkipAuditPolicy
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply -SkipNetworkHardening
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply -SkipCredentialProtection
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply -SkipPowerShell

  # PrintNightmare mitigation (opt-in)
  .\ZavetSecHardeningBaseline.ps1 -Mode Apply -EnablePrintSpoolerDisable

  METHOD 3 -- MASS DEPLOYMENT VIA PSEXEC
  ----------------------------------------
  psexec \\TARGET -s -c .\ZavetSecHardeningBaseline.ps1 -Mode Apply -NonInteractive

CAPABILITIES
------------
  Network Hardening      (NET-001 to NET-010)
    - Disable LLMNR, mDNS, WPAD, NBT-NS, LMHOSTS
    - Disable SMBv1 (server + client driver)
    - Require SMB signing (server + client)
    - Restrict anonymous SAM and share enumeration
    - Disable Remote Registry service

  Credential Protection  (CRED-001 to CRED-006)
    - Disable WDigest plaintext credential caching (anti-Mimikatz)
    - Enable LSA Protection (RunAsPPL)
    - Enable Windows Defender Credential Guard (VBS)
    - Force NTLMv2 authentication only
    - Disable LM hash storage
    - Require 128-bit NTLM session security

  PowerShell Hardening   (PS-001 to PS-005)
    - Enable Script Block Logging (Event 4104)
    - Enable Module Logging (Event 4103)
    - Enable Transcription to C:\ProgramData\PSTranscripts
    - Disable PowerShell v2 engine (AMSI bypass vector)
    - Set Execution Policy to RemoteSigned (Machine scope)

  Audit Policy           (AUD-001 to AUD-027)
    - 27 subcategories configured via auditpol (GUID-based, locale-independent)
    - Covers: Logon/Logoff, Kerberos, Process Creation, Account Management,
      Object Access, Privilege Use, Policy Change, DPAPI, Scheduled Tasks,
      Removable Storage, Firewall events, and more

  System Hardening       (SYS-001 to SYS-010)
    - Enable UAC with full enforcement (secure desktop prompt)
    - Disable AutoRun / AutoPlay on all drive types
    - Enable Windows Firewall on all profiles
    - Require RDP Network Level Authentication (NLA)
    - Enable DEP (Data Execution Prevention) for all programs
    - Set Security log to 1 GB, overwrite mode (no archive files)
    - Enable DNS over HTTPS policy
    - Set RDP encryption level to High
    - Optionally disable Print Spooler (PrintNightmare)

MODES
-----
  Audit     Read-only. No changes. Generates HTML report.
  Apply     Apply all hardening. Creates JSON backup first.
  Rollback  Restore from backup JSON.

OUTPUT
------
  HTML Report  : Dark-themed, ZavetSec branded, filterable
                 Includes severity, MITRE reference, remediation per check
  JSON Backup  : Saved before any Apply; used by Rollback mode

  Location:
    Via Run-Hardening.bat  -> .\Reports\ (created automatically)
    Via PowerShell direct  -> script directory (or -OutputPath / -BackupPath)

REQUIREMENTS
------------
  PowerShell : 5.1+
  OS         : Windows 10/11, Windows Server 2016/2019/2022
  Rights     : Local Administrator (for Apply and Rollback modes)
  Reboot     : Required for Credential Guard, DEP, PSv2 disable, SMBv1 client

================================================================================
  ZavetSec -- MIT License -- https://github.com/zavetsec
================================================================================
