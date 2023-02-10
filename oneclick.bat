@echo off


goto check_Permissions

:check_Permissions
    echo Administrative permissions required. Detecting permissions...
    
    net session >nul 2>&1
    if %errorLevel% == 0 (
        Echo  Success: Administrative permissions confirmed.
        powershell curl.exe https://raw.githubusercontent.com/markagoston/winutil/main/ctt-oneclick-source.ps1 -o ctt.ps1
        powershell -ExecutionPolicy Bypass -NoProfile -File ctt.ps1
        del ctt.ps1
    ) else (
        Echo  Failure: Current permissions inadequate. You have to run this script as an Administrator.
        pause
    )

