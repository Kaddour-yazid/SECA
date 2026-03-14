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

function Resolve-ToolPath {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Candidates
    )

    foreach ($candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }
        $resolved = Join-Path $Tools $candidate
        if (Test-Path $resolved) {
            return $resolved
        }
    }

    return $null
}

function Open-TargetFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath
    )

    $ext = [System.IO.Path]::GetExtension($TargetPath).ToLowerInvariant()
    $textExts = @(".txt", ".log", ".ini", ".cfg", ".csv", ".json", ".xml", ".yaml", ".yml", ".md")
    $pdfExts = @(".pdf")
    $execExts = @(".exe", ".com", ".scr", ".pif", ".msi")
    $scriptExts = @(".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".hta")
    $documentExts = @(".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf")
    $mediaExts = @(".png", ".jpg", ".jpeg", ".gif", ".bmp", ".mp4", ".mp3", ".wav", ".avi", ".mkv")
    $archiveExts = @(".zip", ".rar", ".7z", ".cab", ".iso")

    $fileCategory = "generic"
    if ($textExts -contains $ext) {
        $fileCategory = "text"
    } elseif ($pdfExts -contains $ext) {
        $fileCategory = "pdf"
    } elseif (($execExts + $scriptExts) -contains $ext) {
        $fileCategory = "executable"
    } elseif ($documentExts -contains $ext) {
        $fileCategory = "document"
    } elseif ($mediaExts -contains $ext) {
        $fileCategory = "media"
    } elseif ($archiveExts -contains $ext) {
        $fileCategory = "archive"
    }

    $result = @{
        action = "none"
        success = $false
        error = ""
        extension = $ext
        category = $fileCategory
    }

    $notepadPath = Join-Path $env:WINDIR "System32\notepad.exe"
    $cmdPath = Join-Path $env:WINDIR "System32\cmd.exe"
    $explorerPath = Join-Path $env:WINDIR "explorer.exe"
    $edgePath = Join-Path $env:ProgramFiles "Microsoft\Edge\Application\msedge.exe"
    $paintPath = Join-Path $env:WINDIR "System32\mspaint.exe"
    $sumatraPath = Resolve-ToolPath @(
        "SumatraPDF.exe",
        "sumatrapdf\SumatraPDF.exe",
        "sumatra\SumatraPDF.exe"
    )
    $sevenZipPath = Resolve-ToolPath @(
        "7zFM.exe",
        "7zip\7zFM.exe",
        "7-Zip\7zFM.exe"
    )
    $vlcPath = Resolve-ToolPath @(
        "vlc.exe",
        "vlc\vlc.exe"
    )
    $libreOfficePath = Resolve-ToolPath @(
        "soffice.exe",
        "LibreOffice\program\soffice.exe",
        "libreoffice\program\soffice.exe"
    )

    try {
        if ($fileCategory -eq "text") {
            if ($sumatraPath) {
                Start-Process -FilePath $sumatraPath -ArgumentList @("`"$TargetPath`"") -ErrorAction Stop
                $result.action = "sumatra-text"
                $result.success = $true
                return $result
            }
            if (Test-Path $notepadPath) {
                Start-Process -FilePath $notepadPath -ArgumentList @($TargetPath) -ErrorAction Stop
                $result.action = "notepad"
                $result.success = $true
                return $result
            }
        }

        if ($fileCategory -eq "pdf") {
            if ($sumatraPath) {
                Start-Process -FilePath $sumatraPath -ArgumentList @("`"$TargetPath`"") -ErrorAction Stop
                $result.action = "sumatra-pdf"
                $result.success = $true
                return $result
            }
            Start-Process -FilePath $edgePath -ArgumentList @("--inprivate", "--disable-extensions", "--no-first-run", "--new-window", "`"$TargetPath`"") -ErrorAction Stop
            $result.action = "msedge-pdf"
            $result.success = $true
            return $result
        }

        if ($fileCategory -eq "executable") {
            Start-Process -FilePath $TargetPath -ErrorAction Stop
            $result.action = "execute"
            $result.success = $true
            return $result
        }

        if ($fileCategory -eq "document") {
            if ($libreOfficePath) {
                Start-Process -FilePath $libreOfficePath -ArgumentList @("`"$TargetPath`"") -ErrorAction Stop
                $result.action = "libreoffice"
                $result.success = $true
                return $result
            }
            if ($sumatraPath) {
                Start-Process -FilePath $sumatraPath -ArgumentList @("`"$TargetPath`"") -ErrorAction Stop
                $result.action = "sumatra-document"
                $result.success = $true
                return $result
            }
        }

        if ($fileCategory -eq "archive" -and $sevenZipPath) {
            Start-Process -FilePath $sevenZipPath -ArgumentList @("`"$TargetPath`"") -ErrorAction Stop
            $result.action = "7zip"
            $result.success = $true
            return $result
        }

        if ($fileCategory -eq "media") {
            if ($vlcPath) {
                Start-Process -FilePath $vlcPath -ArgumentList @("`"$TargetPath`"") -ErrorAction Stop
                $result.action = "vlc"
                $result.success = $true
                return $result
            }
            if (@(".png", ".jpg", ".jpeg", ".gif", ".bmp") -contains $ext -and (Test-Path $paintPath)) {
                Start-Process -FilePath $paintPath -ArgumentList @("`"$TargetPath`"") -ErrorAction Stop
                $result.action = "mspaint"
                $result.success = $true
                return $result
            }
        }

        Start-Process -FilePath $cmdPath -ArgumentList @("/c", "start", "", "`"$TargetPath`"") -ErrorAction Stop
        $result.action = "shell-open"
        $result.success = $true
        return $result
    } catch {
        $result.error = "$_"
    }

    try {
        Start-Process -FilePath $explorerPath -ArgumentList "/select,`"$TargetPath`"" -ErrorAction Stop
        $result.action = "explorer-select"
        $result.success = $true
        $result.error = ""
        return $result
    } catch {
        $result.error = "$_"
    }

    try {
        Invoke-Item $TargetPath -ErrorAction Stop
        $result.action = "invoke-item"
        $result.success = $true
        $result.error = ""
        return $result
    } catch {
        $result.error = "$_"
    }

    return $result
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

            Remove-Item -Path $t.FullName -Force -ErrorAction SilentlyContinue
            Log "Trigger consumed: $($t.Name)"

            $openAction = "none"
            $openSuccess = $false
            $openError = ""
            $fileExtension = ""
            $fileCategory = ""

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
                    $openResult = Open-TargetFile -TargetPath $targetPath
                    $openAction = "$($openResult.action)"
                    $openSuccess = [bool]$openResult.success
                    $openError = "$($openResult.error)"
                    $fileExtension = "$($openResult.extension)"
                    $fileCategory = "$($openResult.category)"
                    if ($openSuccess) {
                        Log "File launch succeeded via $openAction category=$fileCategory ext=$fileExtension path=$targetPath"
                    } else {
                        Log "File launch failed action=$openAction category=$fileCategory ext=$fileExtension error=$openError"
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
                file_extension = $fileExtension
                file_category = $fileCategory
                shutdown_after_done = $shutdownAfterDone
            } | ConvertTo-Json | Out-File -FilePath (Join-Path $sessionOut "done_$session.json") -Encoding UTF8

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
