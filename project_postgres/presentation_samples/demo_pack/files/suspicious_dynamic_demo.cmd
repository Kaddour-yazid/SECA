@echo off
rem SECA DEMO SAMPLE - SUSPICIOUS BUT SAFE
rem This file is intended for sandbox testing only.
rem It performs harmless actions that can still generate observable behavior.

set "DEMO_DIR=%TEMP%\seca_sandbox_demo"
mkdir "%DEMO_DIR%" 2>nul

echo SECA suspicious dynamic demo > "%DEMO_DIR%\suspicious_marker.txt"
echo User context: >> "%DEMO_DIR%\suspicious_marker.txt"
whoami >> "%DEMO_DIR%\suspicious_marker.txt"

rem Harmless process and network-environment commands for sandbox visibility.
cmd /c ver > "%DEMO_DIR%\system_version.txt"
ipconfig /all > "%DEMO_DIR%\network_snapshot.txt"

rem Suspicious-looking encoded command string stored as text only.
echo powershell -enc SQBFAFgA > "%DEMO_DIR%\encoded_command_marker.txt"

echo Done. Files written to "%DEMO_DIR%".
