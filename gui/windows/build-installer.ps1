<#
.SYNOPSIS
    Build the nettool Windows installer.

.DESCRIPTION
    Builds the Rust GUI, freezes the Python CLI if PyInstaller is available,
    generates the icon, then compiles the Inno Setup script into
    dist\nettool-<version>-setup.exe.

    Run it from anywhere; paths are resolved from the script's own location.

.PARAMETER Version
    Version stamped into the installer and its filename. Defaults to the
    version in gui/Cargo.toml.

.PARAMETER SkipCli
    Do not freeze the CLI. The installer then ships the Python source and
    relies on a system Python 3.8+, which is fine for a development machine
    and a poor bet for anyone else's.

.EXAMPLE
    pwsh gui\windows\build-installer.ps1
    pwsh gui\windows\build-installer.ps1 -Version 1.2.0
#>
[CmdletBinding()]
param(
    [string]$Version,
    [switch]$SkipCli
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$gui  = Split-Path -Parent $here
$repo = Split-Path -Parent $gui
$dist = Join-Path $repo 'dist'

function Step($message) { Write-Host "==> $message" -ForegroundColor Cyan }
function Need($name, $hint) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "$name was not found on PATH. $hint"
    }
}

if (-not $Version) {
    $cargo = Get-Content (Join-Path $gui 'Cargo.toml') -Raw
    if ($cargo -match '(?m)^version\s*=\s*"([^"]+)"') { $Version = $Matches[1] }
    else { $Version = '0.1.0' }
}
Step "Building nettool $Version"

New-Item -ItemType Directory -Force -Path $dist | Out-Null

# --- the GUI ---------------------------------------------------------------
Need 'cargo' 'Install Rust from https://rustup.rs'
Step 'Building the GUI (cargo build --release)'
Push-Location $gui
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
}
finally { Pop-Location }

$exe = Join-Path $gui 'target\release\nettool-gui.exe'
if (-not (Test-Path $exe)) { throw "the GUI did not build: $exe is missing" }

# --- the CLI ---------------------------------------------------------------
# The GUI shells out to the Python CLI for every reading it takes. Freezing it
# means the installer does not depend on the user having Python, which most
# Windows machines do not.
if (-not $SkipCli) {
    $frozen = Join-Path $dist 'cli\nettool.exe'
    if (Get-Command pyinstaller -ErrorAction SilentlyContinue) {
        Step 'Freezing the CLI (pyinstaller)'
        Push-Location $repo
        try {
            pyinstaller --onefile --name nettool --distpath (Join-Path $dist 'cli') `
                        --workpath (Join-Path $dist 'build') `
                        --specpath (Join-Path $dist 'build') `
                        --console nettool\__main__.py
            if ($LASTEXITCODE -ne 0) { throw 'pyinstaller failed' }
        }
        finally { Pop-Location }
    }
    elseif (Test-Path $frozen) {
        Step 'Reusing the frozen CLI already in dist\cli'
    }
    else {
        Write-Warning ('PyInstaller was not found, so the installer will ship the ' +
                       'Python source and require a system Python 3.8+. ' +
                       'Install it with:  pip install pyinstaller')
    }
}

# --- the icon --------------------------------------------------------------
$icon = Join-Path $here 'nettool.ico'
if (-not (Test-Path $icon)) {
    Step 'Generating the icon'
    $png = Join-Path $gui 'macos\icon.png'
    if ((Test-Path $png) -and (Get-Command python -ErrorAction SilentlyContinue)) {
        python (Join-Path $here 'make-icon.py') $png $icon
    }
}
if (-not (Test-Path $icon)) {
    Write-Warning 'No icon found; the installer will use the Inno Setup default.'
}

# --- the installer ---------------------------------------------------------
$iscc = Get-Command iscc -ErrorAction SilentlyContinue
if (-not $iscc) {
    foreach ($candidate in @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe")) {
        if (Test-Path $candidate) { $iscc = $candidate; break }
    }
}
if (-not $iscc) {
    throw ('Inno Setup 6 was not found. Install it from https://jrsoftware.org/isdl.php ' +
           '(or: winget install JRSoftware.InnoSetup)')
}

Step 'Compiling the installer'
& $iscc "/DAppVersion=$Version" (Join-Path $here 'nettool.iss')
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup failed' }

$setup = Join-Path $dist "nettool-$Version-setup.exe"
Step "Done: $setup"
if (Test-Path $setup) {
    '{0:N1} MB' -f ((Get-Item $setup).Length / 1MB) | Write-Host
}
