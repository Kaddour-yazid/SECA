@echo off
rem SECA DEMO SAMPLE - MALICIOUS-BEHAVIOR SIMULATOR, NOT REAL MALWARE
rem Safety boundaries:
rem - Uses only %TEMP%\seca_sandbox_demo.
rem - Writes one harmless marker under %APPDATA%\seca_sandbox_demo to exercise suspicious-path detection.
rem - Deletes only a file that this script creates itself.
rem - Does not persist, steal credentials, encrypt user data, or modify system settings.
rem - Network target uses reserved .invalid domain and should not resolve.

set "DEMO_DIR=%TEMP%\seca_sandbox_demo"
set "APPDATA_MARKER_DIR=%APPDATA%\seca_sandbox_demo"
mkdir "%DEMO_DIR%" 2>nul
mkdir "%APPDATA_MARKER_DIR%" 2>nul

echo SECA malicious behavior simulator > "%DEMO_DIR%\stage_1_dropper_marker.tmp"
echo fake secret data for demo only > "%DEMO_DIR%\created_then_deleted.tmp"
echo harmless suspicious-path marker > "%APPDATA_MARKER_DIR%\roaming_marker.txt"

rem Child process creation.
cmd /c echo child process executed > "%DEMO_DIR%\child_process_marker.txt"

rem Script interpreter usage.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='%%TEMP%%\seca_sandbox_demo\powershell_marker.txt'; 'PowerShell executed in demo sandbox' | Out-File -Encoding ascii $p"

rem High-risk-looking Windows utilities kept alive briefly so the sandbox monitor can observe them.
rem The VBS sleeps only; it performs no action.
(
  echo WScript.Sleep 20000
  echo WScript.Echo "SECA harmless WScript marker"
) > "%DEMO_DIR%\sleep_marker.vbs"
start "" wscript.exe "%DEMO_DIR%\sleep_marker.vbs"
start "" cscript.exe //nologo "%DEMO_DIR%\sleep_marker.vbs"

rem certutil is used only to decode a local benign base64 string into a local demo file.
echo U0VDQSBoYXJtbGVzcyBkZW1vIGJsb2I= > "%DEMO_DIR%\blob.b64"
certutil -f -decode "%DEMO_DIR%\blob.b64" "%DEMO_DIR%\decoded_blob.txt" > "%DEMO_DIR%\certutil_output.txt" 2>&1

rem Encoded-looking artifact creation, useful for static and dynamic scoring.
powershell -NoProfile -Command "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('SECA demo payload only')) | Out-File -Encoding ascii '%%TEMP%%\seca_sandbox_demo\encoded_blob.txt'"

rem Safe deletion: remove only the file created above.
del "%DEMO_DIR%\created_then_deleted.tmp" 2>nul

rem Non-resolving beacon-like attempt to a reserved domain.
powershell -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 'http://training-c2.example.invalid/beacon?id=seca-demo' | Out-Null } catch { 'network attempt failed as expected' | Out-File -Encoding ascii '%%TEMP%%\seca_sandbox_demo\network_attempt.txt' }"

rem Keep the script alive a little longer for process/file telemetry collection.
timeout /t 12 /nobreak >nul

echo Simulator complete. Artifacts written to "%DEMO_DIR%".
