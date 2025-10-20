#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Fix Broken Chocolatey Installation
.DESCRIPTION
    Completely removes any existing Chocolatey installation and prepares
    the system for a fresh installation.
#>

Write-Host "========================================"
Write-Host "Fix Broken Chocolatey Installation"
Write-Host "========================================"
Write-Host ""
Write-Host "This script will:"
Write-Host "  - Remove existing Chocolatey installation"
Write-Host "  - Clean up registry entries"
Write-Host "  - Remove PATH entries"
Write-Host "  - Prepare for fresh installation"
Write-Host ""
Write-Host "WARNING: This will remove Chocolatey and all packages installed via Chocolatey!"
Write-Host ""
Write-Host "Press any key to continue or Ctrl+C to cancel..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# ====================
# Step 1: Remove Chocolatey Directory
# ====================
Write-Host "========================================"
Write-Host "Step 1: Removing Chocolatey Directory"
Write-Host "========================================"
Write-Host ""

$chocoPath = "C:\ProgramData\chocolatey"

if (Test-Path $chocoPath) {
    Write-Host "[+] Removing $chocoPath..."
    try {
        Remove-Item $chocoPath -Recurse -Force -ErrorAction Stop
        Write-Host "[+] Chocolatey directory removed successfully"
    } catch {
        Write-Host "[!] WARNING: Some files could not be removed (may be in use)"
        Write-Host "[!] Try closing all terminals and running this script again"
    }
} else {
    Write-Host "[!] Chocolatey directory not found (already clean)"
}
Write-Host ""

# ====================
# Step 2: Clean Environment Variables
# ====================
Write-Host "========================================"
Write-Host "Step 2: Cleaning Environment Variables"
Write-Host "========================================"
Write-Host ""

# Remove Chocolatey from system PATH
Write-Host "[+] Cleaning PATH environment variable..."
try {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $newPath = ($machinePath.Split(';') | Where-Object { $_ -notlike "*chocolatey*" }) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    Write-Host "[+] PATH cleaned successfully"
} catch {
    Write-Host "[!] WARNING: Could not clean PATH variable"
}

# Remove ChocolateyInstall environment variable
Write-Host "[+] Removing ChocolateyInstall environment variable..."
try {
    [Environment]::SetEnvironmentVariable("ChocolateyInstall", $null, "Machine")
    [Environment]::SetEnvironmentVariable("ChocolateyInstall", $null, "User")
    Write-Host "[+] ChocolateyInstall variable removed"
} catch {
    Write-Host "[!] WARNING: Could not remove ChocolateyInstall variable"
}
Write-Host ""

# ====================
# Step 3: Clean Registry Entries
# ====================
Write-Host "========================================"
Write-Host "Step 3: Cleaning Registry Entries"
Write-Host "========================================"
Write-Host ""

Write-Host "[+] Removing Chocolatey registry entries..."
try {
    Remove-Item -Path "HKLM:\SOFTWARE\Chocolatey" -Recurse -Force -ErrorAction Stop
    Write-Host "[+] Registry entries removed"
} catch {
    Write-Host "[!] No registry entries found (already clean)"
}
Write-Host ""

# ====================
# Step 4: Clean User Profile
# ====================
Write-Host "========================================"
Write-Host "Step 4: Cleaning User Profile"
Write-Host "========================================"
Write-Host ""

$userChocoPath = "$env:USERPROFILE\.chocolatey"
if (Test-Path $userChocoPath) {
    Write-Host "[+] Removing $userChocoPath..."
    Remove-Item $userChocoPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] User profile cleaned"
} else {
    Write-Host "[!] User profile directory not found (already clean)"
}

$tempChocoPath = "$env:USERPROFILE\AppData\Local\Temp\chocolatey"
if (Test-Path $tempChocoPath) {
    Write-Host "[+] Removing temporary Chocolatey files..."
    Remove-Item $tempChocoPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Temporary files cleaned"
} else {
    Write-Host "[!] No temporary files found"
}
Write-Host ""

# ====================
# Summary
# ====================
Write-Host "========================================"
Write-Host "Cleanup Complete!"
Write-Host "========================================"
Write-Host ""
Write-Host "Chocolatey has been completely removed from your system."
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Close this terminal"
Write-Host "  2. Open a new terminal as Administrator"
Write-Host "  3. Run setup_hosts_redirect.ps1"
Write-Host ""
Write-Host "The setup script will now be able to install a fresh copy of Chocolatey."
Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

