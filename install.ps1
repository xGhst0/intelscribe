# IntelScribe one-step installer for Windows.
#
# Run this once after cloning the repo to get the "installed program"
# experience: it builds the optimised release executable and drops a
# double-clickable IntelScribe shortcut (with the app icon) on your Desktop.
#
#   git clone https://github.com/xGhst0/intelscribe.git
#   cd intelscribe
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# Re-run any time to rebuild and refresh the shortcut. Requires Rust (MSVC) and
# the C++ Build Tools — see the README prerequisites.

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot
Set-Location $repo

Write-Host "==> Building IntelScribe (release)..." -ForegroundColor Cyan
cargo build --release -p intelscribe-app
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed. Ensure Rust (MSVC) and the C++ Build Tools are installed (see README)."
    exit 1
}

$exe = Join-Path $repo "target\release\intelscribe-app.exe"
if (-not (Test-Path $exe)) {
    Write-Error "Build reported success but the executable was not found at $exe"
    exit 1
}

# The application icon ships committed under crates\app\icons; regenerate it
# only if it is somehow missing (e.g. a partial checkout).
$icon = Join-Path $repo "crates\app\icons\icon.ico"
if (-not (Test-Path $icon)) {
    Write-Host "==> Generating application icon..." -ForegroundColor Cyan
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "tools\make-icon.ps1")
}

Write-Host "==> Creating Desktop shortcut..." -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "tools\make-shortcut.ps1")

Write-Host ""
Write-Host "IntelScribe is installed. Launch it from the 'IntelScribe' shortcut on your Desktop." -ForegroundColor Green
