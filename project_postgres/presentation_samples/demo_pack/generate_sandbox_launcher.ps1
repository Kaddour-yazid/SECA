$ErrorActionPreference = "Stop"

$demoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$filesRoot = Join-Path $demoRoot "files"
$launcher = Join-Path $demoRoot "run_malicious_simulator_in_sandbox.local.wsb"

if (-not (Test-Path -LiteralPath $filesRoot)) {
    throw "Demo files folder not found: $filesRoot"
}

$escapedFilesRoot = [System.Security.SecurityElement]::Escape((Resolve-Path -LiteralPath $filesRoot).Path)

@"
<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$escapedFilesRoot</HostFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /c start "" "C:\Users\WDAGUtilityAccount\Desktop\files\fake_report.pdf.cmd"</Command>
  </LogonCommand>
</Configuration>
"@ | Set-Content -LiteralPath $launcher -Encoding UTF8

Write-Host "Created Windows Sandbox launcher:"
Write-Host $launcher
