# Managed monitor script for Windows Sandbox dynamic scans.
# This script runs inside the sandbox guest and processes trigger files
# from the mapped host share. It supports per-scan guest shutdown via
# trigger flag: shutdownAfterDone=true.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$ShareRoot = "C:\sandbox_share"
$BootstrapLog = "C:\Windows\Temp\seca_monitor_bootstrap.log"
$StartupTimeoutSec = 30

function LogBootstrap {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $BootstrapLog -Append -Encoding UTF8
}

function Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
}

function RequestSandboxShutdown {
    Log "shutdownAfterDone requested; attempting guest shutdown."
    try {
        Stop-Computer -Force -ErrorAction Stop
        Start-Sleep -Seconds 2
    } catch {
        Log "Stop-Computer failed: $_"
    }
    try {
        shutdown.exe /s /t 0 /f | Out-Null
    } catch {
        Log "shutdown.exe fallback failed: $_"
    }
}

$deadline = (Get-Date).AddSeconds($StartupTimeoutSec)
while (-not (Test-Path -Path $ShareRoot)) {
    LogBootstrap "Waiting for mapped share root: $ShareRoot"
    if ((Get-Date) -ge $deadline) {
        LogBootstrap "FATAL: mapped share root not found after $StartupTimeoutSec seconds: $ShareRoot"
        exit 2
    }
    Start-Sleep -Seconds 1
}

$script:LogFile = Join-Path $ShareRoot "monitor_debug.txt"
$Inbox = Join-Path $ShareRoot "inbox"
$ToAnalyze = Join-Path $ShareRoot "to_analyze"
$OutRoot = Join-Path $ShareRoot "out"
$Tools = Join-Path $ShareRoot "tools"
$ReadyMarker = Join-Path $ShareRoot "sandbox_ready.txt"

try {
    New-Item -ItemType Directory -Path $Inbox -Force | Out-Null
    New-Item -ItemType Directory -Path $ToAnalyze -Force | Out-Null
    New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $Tools -Force | Out-Null
} catch {
    Log "ERROR creating directories: $_"
}

try {
    "$(Get-Date -Format o) - sandbox monitor started" | Out-File -FilePath $ReadyMarker -Encoding UTF8
    Log "Ready marker written: $ReadyMarker"
} catch {
    Log "ERROR writing ready marker: $_"
}

while ($true) {
    if (-not (Test-Path -Path $Inbox)) {
        Log "Inbox path missing: $Inbox"
        Start-Sleep -Seconds 2
        continue
    }

    $triggers = @()
    try {
        $triggers = @(Get-ChildItem -Path $Inbox -Filter "*.scan.json" -ErrorAction Stop)
    } catch {
        Log "ERROR listing triggers: $_"
    }

    foreach ($t in $triggers) {
        try {
            $json = Get-Content -Path $t.FullName -Raw | ConvertFrom-Json
            $session = if ($json.sessionId) { "$($json.sessionId)" } else { [guid]::NewGuid().ToString() }

            $scanMode = "file"
            if ($json.PSObject.Properties.Name -contains "scanMode" -and "$($json.scanMode)" -ne "") {
                $scanMode = "$($json.scanMode)".ToLowerInvariant()
            }

            $targetRel = ""
            if ($json.PSObject.Properties.Name -contains "targetRelativePath" -and "$($json.targetRelativePath)" -ne "") {
                $targetRel = "$($json.targetRelativePath)"
            }

            $targetUrl = ""
            if ($json.PSObject.Properties.Name -contains "targetUrl" -and "$($json.targetUrl)" -ne "") {
                $targetUrl = "$($json.targetUrl)".Trim()
            }

            $duration = 60
            if ($json.PSObject.Properties.Name -contains "durationSeconds" -and $null -ne $json.durationSeconds -and "$($json.durationSeconds)" -ne "") {
                $duration = [int]$json.durationSeconds
            }
            if ($duration -le 0) { $duration = 60 }
            $shutdownAfterDone = $false
            if ($json.PSObject.Properties.Name -contains "shutdownAfterDone" -and $null -ne $json.shutdownAfterDone) {
                $shutdownAfterDone = [bool]$json.shutdownAfterDone
            }

            Log "Processing trigger: $($t.Name) mode=$scanMode session=$session duration=${duration}s shutdownAfterDone=$shutdownAfterDone"

            $targetPath = Join-Path $ToAnalyze $targetRel
            $sessionOut = Join-Path $OutRoot "session_$session"
            New-Item -ItemType Directory -Path $sessionOut -Force | Out-Null

            @{
                session = $session
                start_time = (Get-Date).ToString("o")
                duration = $duration
                target = $targetPath
                scan_mode = $scanMode
                target_url = $targetUrl
                shutdown_after_done = $shutdownAfterDone
            } | ConvertTo-Json | Out-File -FilePath (Join-Path $sessionOut "meta_$session.json") -Encoding UTF8

            $openAction = "none"
            $openSuccess = $false
            $openError = ""

            if ($scanMode -eq "url") {
                if ([string]::IsNullOrWhiteSpace($targetUrl) -or -not ($targetUrl -match '^https?://')) {
                    $openAction = "url-invalid"
                    $openError = "targetUrl is missing or invalid"
                } else {
                    try {
                        Start-Process -FilePath "msedge.exe" -ArgumentList @("--inprivate", "--disable-extensions", "--no-first-run", "--new-window", "`"$targetUrl`"") -ErrorAction Stop
                        $openAction = "msedge-url"
                        $openSuccess = $true
                        Log "URL launch succeeded via Edge: $targetUrl"
                    } catch {
                        $openAction = "msedge-url"
                        $openError = "$_"
                        Log "Edge URL launch failed, trying shell fallback: $openError"
                        try {
                            Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", "start", "", "`"$targetUrl`"") -ErrorAction Stop
                            $openAction = "default-browser-url"
                            $openSuccess = $true
                            $openError = ""
                            Log "URL launch succeeded via shell fallback: $targetUrl"
                        } catch {
                            $openError = "$_"
                            Log "Shell URL launch failed: $openError"
                        }
                    }
                }
            } else {
                if (Test-Path $targetPath) {
                    $ext = [System.IO.Path]::GetExtension($targetPath).ToLowerInvariant()
                    try {
                        if ($ext -in @(".txt", ".log", ".ini", ".cfg")) {
                            Start-Process -FilePath "notepad.exe" -ArgumentList "`"$targetPath`"" -ErrorAction Stop
                            $openAction = "notepad"
                            $openSuccess = $true
                        } elseif ($ext -eq ".pdf") {
                            Start-Process -FilePath "msedge.exe" -ArgumentList "`"$targetPath`"" -ErrorAction Stop
                            $openAction = "msedge-pdf"
                            $openSuccess = $true
                        } elseif ($ext -in @(".exe", ".com", ".scr", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf")) {
                            Start-Process -FilePath $targetPath -ErrorAction Stop
                            $openAction = "execute"
                            $openSuccess = $true
                        } else {
                            Invoke-Item $targetPath -ErrorAction Stop
                            $openAction = "invoke-item"
                            $openSuccess = $true
                        }
                    } catch {
                        $openError = "$_"
                        if ($ext -in @(".txt", ".log", ".ini", ".cfg")) {
                            $openAction = "notepad"
                        } else {
                            try {
                                Start-Process -FilePath $targetPath -ErrorAction Stop
                                $openAction = "fallback-start-process"
                                $openSuccess = $true
                            } catch {
                                $openError = "$_"
                            }
                        }
                    }
                } else {
                    $openAction = "target-missing"
                    $openError = "Target file not found at $targetPath"
                }
            }

            Start-Sleep -Seconds $duration

            (Get-Process | Select-Object Id, ProcessName, CPU) |
                ConvertTo-Json -Depth 3 |
                Out-File (Join-Path $sessionOut "processes_$session.json") -Encoding UTF8

            (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                Select-Object @{N='protocol';E={'TCP'}}, RemoteAddress, RemotePort) |
                ConvertTo-Json -Depth 3 |
                Out-File (Join-Path $sessionOut "network_$session.json") -Encoding UTF8

            @{
                session = $session
                end_time = (Get-Date).ToString("o")
                out_dir = $sessionOut
                scan_mode = $scanMode
                target_url = $targetUrl
                open_action = $openAction
                open_success = $openSuccess
                open_error = $openError
                shutdown_after_done = $shutdownAfterDone
            } | ConvertTo-Json | Out-File -FilePath (Join-Path $sessionOut "done_$session.json") -Encoding UTF8

            Remove-Item -Path $t.FullName -Force -ErrorAction SilentlyContinue
            Log "Trigger consumed: $($t.Name)"

            if ($shutdownAfterDone) {
                RequestSandboxShutdown
                Start-Sleep -Seconds 2
                exit 0
            }
        } catch {
            Log "ERROR processing trigger $($t.FullName): $_"
            try { Remove-Item -Path $t.FullName -Force -ErrorAction SilentlyContinue } catch {}
        }
    }

    Start-Sleep -Seconds 2
}
