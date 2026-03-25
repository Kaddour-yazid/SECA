$ErrorActionPreference = "Stop"

$BackendDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExePath = Join-Path $BackendDir "tools\\meilisearch.exe"
$DataDir = Join-Path $BackendDir ".meilisearch-data"
$EnvFile = Join-Path $BackendDir ".env"

if (Test-Path $EnvFile) {
  Get-Content $EnvFile | ForEach-Object {
    if ($_ -match '^\s*#' -or $_ -notmatch '=') { return }
    $name, $value = $_ -split '=', 2
    [System.Environment]::SetEnvironmentVariable($name.Trim(), $value.Trim(), 'Process')
  }
}

if (-not (Test-Path $ExePath)) {
  Write-Host "Meilisearch executable not found at $ExePath" -ForegroundColor Yellow
  Write-Host "Place meilisearch.exe in project_postgres\\backend\\tools\\ then run this script again." -ForegroundColor Yellow
  Write-Host "Configured URL: $env:SECA_MEILI_URL" -ForegroundColor DarkGray
  exit 1
}

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

if (-not $env:SECA_MEILI_MASTER_KEY) {
  $env:SECA_MEILI_MASTER_KEY = "seca-dev-master-key"
}

& $ExePath --db-path $DataDir --http-addr "127.0.0.1:7700" --master-key $env:SECA_MEILI_MASTER_KEY --no-analytics
