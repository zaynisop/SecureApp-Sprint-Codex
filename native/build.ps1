# Native helper build for Windows (PowerShell).
# Requires a C compiler on PATH: gcc (MinGW-w64) or cl (MSVC).
# Produces thumbgen_secure.dll loaded by app/native.py.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $here
try {
    $gcc = Get-Command gcc -ErrorAction SilentlyContinue
    if ($gcc) {
        Write-Host "Building thumbgen_secure.dll with gcc (hardened flags)..."
        & gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 -Wall -Wextra `
              -shared -o thumbgen_secure.dll thumbgen_secure.c
    } else {
        $cl = Get-Command cl -ErrorAction SilentlyContinue
        if (-not $cl) {
            Write-Warning "No gcc or cl found. The app will use its safe pure-Python preview fallback."
            exit 0
        }
        Write-Host "Building thumbgen_secure.dll with MSVC cl (/GS /sdl)..."
        & cl /LD /O2 /GS /sdl thumbgen_secure.c /Fe:thumbgen_secure.dll
    }
    Write-Host "Done." -ForegroundColor Green
} finally {
    Pop-Location
}
