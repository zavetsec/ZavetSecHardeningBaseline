@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title ZavetSec - Windows Security Hardening Baseline

:: ============================================================
::  Run-Hardening.bat - Launcher for ZavetSecHardeningBaseline.ps1
::  ZavetSec Information Security
:: ============================================================

:: Check Admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [!!] ERROR: Run this script as Administrator!
    echo       Right-click ^> "Run as administrator"
    echo.
    pause
    exit /b 1
)

:: Paths - use script directory for all output (avoids UAC/profile path issues)
set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%ZavetSecHardeningBaseline.ps1"
set "REPORT_DIR=%SCRIPT_DIR%Reports"

:: Create Reports subfolder if not exists
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

:: Check PS script exists
if not exist "%PS_SCRIPT%" (
    echo.
    echo  [!!] ERROR: ZavetSecHardeningBaseline.ps1 not found in: %SCRIPT_DIR%
    echo.
    pause
    exit /b 1
)

:: ============================================================
:MENU
cls
echo.
echo  ============================================================
echo   ZavetSec - Windows Security Hardening Baseline
echo  ============================================================
echo.
echo   Reports saved to: %REPORT_DIR%
echo.
echo   [1]  AUDIT    - Check current state (no changes)
echo   [2]  APPLY    - Apply all hardening settings
echo   [3]  ROLLBACK - Revert changes (requires backup file)
echo   [4]  EXIT
echo.
echo  ============================================================
echo.
set /p CHOICE="  Select option [1-4]: "

if "%CHOICE%"=="1" goto AUDIT
if "%CHOICE%"=="2" goto APPLY
if "%CHOICE%"=="3" goto ROLLBACK
if "%CHOICE%"=="4" goto EXIT
echo  Invalid option. Try again.
timeout /t 2 >nul
goto MENU

:: ============================================================
:AUDIT
cls
call :TIMESTAMP
set "REPORT=%REPORT_DIR%\HardeningBaseline_%TS%.html"
set "BACKUP=%REPORT_DIR%\HardeningBackup_%TS%.json"
echo.
echo  [>>] AUDIT mode - no changes will be made
echo  [..] Report will be saved to:
echo       %REPORT%
echo.
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; & '%PS_SCRIPT%' -Mode Audit -OutputPath '%REPORT%' -BackupPath '%BACKUP%' -NonInteractive }"
echo.
if exist "%REPORT%" (
    echo  [OK] Report created: %REPORT%
    set /p OPEN="  Open report in browser? [Y/N]: "
    if /i "!OPEN!"=="Y" start "" "%REPORT%"
) else (
    echo  [!!] Report NOT found at: %REPORT%
    echo  [..] Files in Reports folder:
    dir /b "%REPORT_DIR%\" 2>nul || echo  (empty)
)
echo.
pause
goto MENU

:: ============================================================
:APPLY
cls
echo.
echo  [!!] WARNING: APPLY will change system settings!
echo       Backup will be created before changes.
echo.
set /p CONFIRM="  Type YES to continue: "
if /i not "%CONFIRM%"=="YES" ( echo  Cancelled. & timeout /t 2 >nul & goto MENU )
call :TIMESTAMP
set "REPORT=%REPORT_DIR%\HardeningBaseline_%TS%.html"
set "BACKUP=%REPORT_DIR%\HardeningBackup_%TS%.json"
echo.
echo  [>>] APPLY mode
echo  [..] Report: %REPORT%
echo  [..] Backup: %BACKUP%
echo.
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; & '%PS_SCRIPT%' -Mode Apply -OutputPath '%REPORT%' -BackupPath '%BACKUP%' -NonInteractive }"
echo.
if exist "%REPORT%" (
    echo  [OK] Report created: %REPORT%
    echo  [..] Backup saved : %BACKUP%
    set /p OPEN="  Open report in browser? [Y/N]: "
    if /i "!OPEN!"=="Y" start "" "%REPORT%"
) else (
    echo  [!!] Report NOT found at: %REPORT%
    echo  [..] Files in Reports folder:
    dir /b "%REPORT_DIR%\" 2>nul || echo  (empty)
)
echo.
pause
goto MENU

:: ============================================================
:ROLLBACK
cls
echo.
echo  [>>] ROLLBACK - restores settings from backup file
echo  [..] Backup files are in: %REPORT_DIR%
echo.

:: Build numbered list of backup files
set "IDX=0"
for %%F in ("%REPORT_DIR%\HardeningBackup_*.json") do (
    set /a IDX+=1
    set "BACKUP_!IDX!=%%~fF"
    echo   [!IDX!]  %%~nxF
)
if %IDX%==0 (
    echo  [!!] No backup files found in: %REPORT_DIR%
    echo.
    pause & goto MENU
)
echo.
set /p SEL="  Select backup number [1-%IDX%]: "

:: Validate selection and resolve path via call trick
set "BACKUP_PATH="
call set "BACKUP_PATH=%%BACKUP_%SEL%%%"
if not defined BACKUP_PATH (
    echo  [!!] Invalid selection: %SEL%
    pause & goto MENU
)
if not exist "%BACKUP_PATH%" (
    echo  [!!] File not found: %BACKUP_PATH%
    pause & goto MENU
)

echo.
echo  [..] Selected: %BACKUP_PATH%
echo.
call :TIMESTAMP
set "REPORT=%REPORT_DIR%\HardeningRollback_%TS%.html"
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; & '%PS_SCRIPT%' -Mode Rollback -BackupPath '%BACKUP_PATH%' -OutputPath '%REPORT%' -NonInteractive }"
echo.
if exist "%REPORT%" (
    echo  [OK] Rollback complete. Report: %REPORT%
    set /p OPEN="  Open report in browser? [Y/N]: "
    if /i "!OPEN!"=="Y" start "" "%REPORT%"
) else (
    echo  [OK] Rollback complete.
)
echo.
pause
goto MENU

:: ============================================================
:EXIT
echo. & echo  Goodbye. & echo.
exit /b 0

:: ============================================================
:TIMESTAMP
for /f "tokens=*" %%i in ('PowerShell.exe -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set "TS=%%i"
exit /b 0
