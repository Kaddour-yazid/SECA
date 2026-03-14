$toolsRoot = "C:\sandbox_share\tools"
$readmePath = Join-Path $toolsRoot "README.txt"

New-Item -ItemType Directory -Path $toolsRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $toolsRoot "sumatrapdf") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $toolsRoot "7zip") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $toolsRoot "vlc") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $toolsRoot "LibreOffice\program") -Force | Out-Null

@"
SECA Sandbox Tools
==================

The Windows Sandbox guest automatically looks here for optional portable tools.
If a matching executable exists, SECA will use it when opening files dynamically.

Supported locations:

- C:\sandbox_share\tools\sumatrapdf\SumatraPDF.exe
  Used for: PDF, text, and fallback document viewing

- C:\sandbox_share\tools\7zip\7zFM.exe
  Used for: ZIP, RAR, 7Z, CAB, ISO

- C:\sandbox_share\tools\vlc\vlc.exe
  Used for: media files

- C:\sandbox_share\tools\LibreOffice\program\soffice.exe
  Used for: DOC, DOCX, XLS, XLSX, PPT, PPTX, RTF

Notes:
- Built-in Windows apps are still used first where appropriate.
- If no tool exists for a file type, SECA falls back to Explorer select view.
- Use portable builds here. Do not copy random installers into this folder.
"@ | Set-Content -Path $readmePath -Encoding UTF8

Write-Host "Prepared sandbox tools folder at $toolsRoot"
Write-Host "Read $readmePath for the exact filenames SECA will detect."
