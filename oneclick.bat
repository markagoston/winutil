powershell curl.exe https://raw.githubusercontent.com/markagoston/winutil/main/ctt-oneclick-source.ps1 -o ctt.ps1
powershell -ExecutionPolicy Bypass -NoProfile -File ctt.ps1
del ctt.ps1