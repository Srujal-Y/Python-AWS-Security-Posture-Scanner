param()
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $ProjectRoot
try {
    $Python = Join-Path $ProjectRoot ".venv/Scripts/python.exe"
    if (-not (Test-Path -LiteralPath $Python)) {
        throw "Create .venv and install requirements first; see README.md."
    }
    & $Python scripts/verify.py
    if ($LASTEXITCODE -ne 0) { throw "Local validation failed." }
} finally {
    Pop-Location
}
