@echo off
rem SECA DEMO SAMPLE - DOUBLE EXTENSION SCRIPT
rem This file demonstrates a deceptive attachment name such as "report.pdf.cmd".
rem If Windows hides known extensions, it may visually look closer to a PDF name.
rem It is not malware. It runs a safe behavior simulator for sandbox testing.

if exist "%~dp0malicious_behavior_simulator.cmd" (
  call "%~dp0malicious_behavior_simulator.cmd"
  exit /b
)

set "DEMO_DIR=%TEMP%\seca_sandbox_demo"
set "APPDATA_MARKER_DIR=%APPDATA%\seca_sandbox_demo"
mkdir "%DEMO_DIR%" 2>nul
mkdir "%APPDATA_MARKER_DIR%" 2>nul

echo SECA double-extension simulator > "%DEMO_DIR%\fake_report_marker.tmp"
echo fake secret data for demo only > "%DEMO_DIR%\created_then_deleted.tmp"
echo harmless suspicious-path marker > "%APPDATA_MARKER_DIR%\roaming_marker.txt"
cmd /c echo child process executed > "%DEMO_DIR%\child_process_marker.txt"

(
  echo WScript.Sleep 20000
  echo WScript.Echo "SECA harmless WScript marker"
) > "%DEMO_DIR%\sleep_marker.vbs"
start "" wscript.exe "%DEMO_DIR%\sleep_marker.vbs"
start "" cscript.exe //nologo "%DEMO_DIR%\sleep_marker.vbs"

echo U0VDQSBoYXJtbGVzcyBkZW1vIGJsb2I= > "%DEMO_DIR%\blob.b64"
certutil -f -decode "%DEMO_DIR%\blob.b64" "%DEMO_DIR%\decoded_blob.txt" > "%DEMO_DIR%\certutil_output.txt" 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='%%TEMP%%\seca_sandbox_demo\powershell_marker.txt'; 'PowerShell executed in demo sandbox' | Out-File -Encoding ascii $p"
powershell -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 'http://training-c2.example.invalid/beacon?id=seca-demo' | Out-Null } catch { 'network attempt failed as expected' | Out-File -Encoding ascii '%%TEMP%%\seca_sandbox_demo\network_attempt.txt' }"

del "%DEMO_DIR%\created_then_deleted.tmp" 2>nul
timeout /t 12 /nobreak >nul
