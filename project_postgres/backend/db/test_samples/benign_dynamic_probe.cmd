@echo off
setlocal EnableExtensions

set "LOG_FILE=%TEMP%\seca_benign_dynamic.log"
echo [%DATE% %TIME%] benign sandbox probe started > "%LOG_FILE%"

rem Open a harmless TCP socket and keep it alive for telemetry sampling.
start "" /B powershell -NoProfile -ExecutionPolicy Bypass -Command ^
 "$ErrorActionPreference='SilentlyContinue';" ^
 "$client = New-Object System.Net.Sockets.TcpClient('example.com',443);" ^
 "Start-Sleep -Seconds 24;" ^
 "if ($client) { $client.Close() }"

rem Keep at least one low-risk child process active.
start "" /B notepad.exe

rem Stay alive long enough for sandbox snapshot collection.
timeout /t 26 /nobreak >nul

echo [%DATE% %TIME%] benign sandbox probe finished >> "%LOG_FILE%"
endlocal
exit /b 0
