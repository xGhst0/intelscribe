# Creates a Desktop shortcut to the built IntelScribe release executable, so it
# launches like an installed program. Run after `cargo build --release`.
#
#   powershell -ExecutionPolicy Bypass -File tools\make-shortcut.ps1

$repo = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $repo "target\release\intelscribe-app.exe"
$icon = Join-Path $repo "crates\app\icons\icon.ico"

if (-not (Test-Path $exe)) {
    Write-Error "Release exe not found. Run: cargo build --release -p intelscribe-app"
    exit 1
}

$desktop = [Environment]::GetFolderPath("Desktop")
$linkPath = Join-Path $desktop "IntelScribe.lnk"

$shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut($linkPath)
$sc.TargetPath = $exe
$sc.WorkingDirectory = Split-Path $exe -Parent
$sc.IconLocation = "$icon,0"
$sc.Description = "IntelScribe - offline cyber report writer"
$sc.Save()

Write-Output "Shortcut created: $linkPath"
