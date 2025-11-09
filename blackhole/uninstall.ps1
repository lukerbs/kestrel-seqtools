# ============================================================================
# Blackhole Input Firewall - Uninstallation Script (PowerShell)
# Removes the service and cleans up all files from C:\ProgramData\AnyDeskClient
# ============================================================================

# Require administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator."
    Write-Host "Please right-click and select 'Run as Administrator'."
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Configuration variables
$ExeName = "AnyDeskClient.exe"
$ProcessName = "AnyDeskClient"
$InstallDir = "$env:ProgramData\AnyDeskClient"
$TaskName = "MicrosoftEdgeUpdateTaskMachineCore"

Write-Host ""
Write-Host "========================================"
Write-Host "  Task Host Service - Uninstall"
Write-Host "========================================"
Write-Host ""

Write-Host "[1/6] Stopping Task Scheduler service"
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Write-Host "  - Service stopped"
} else {
    Write-Host "  - Service not found or not running"
}
Write-Host ""

Write-Host "[2/6] Deleting Task Scheduler service"
if ($task) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "  - Service deleted"
} else {
    Write-Host "  - Service not found or already deleted"
}
Write-Host ""

Write-Host "[3/6] Terminating running processes"
$process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
if ($process) {
    Stop-Process -Name $ProcessName -Force
    Start-Sleep -Seconds 2  # Wait for process to fully terminate
    
    # Verify process is terminated
    $maxRetries = 5
    $retry = 0
    while ($retry -lt $maxRetries -and (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)) {
        Start-Sleep -Seconds 1
        $retry++
    }
    
    if (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue) {
        Write-Host "  - Warning: Process may still be running (file may be locked)"
    } else {
        Write-Host "  - Process terminated"
    }
} else {
    Write-Host "  - Process not found or already terminated"
}
Write-Host ""

Write-Host "[4/6] Deleting files"

$exePath = "$InstallDir\$ExeName"
if (Test-Path $exePath) {
    try {
        Remove-Item $exePath -Force
        Write-Host "  - Deleted: $exePath"
    } catch {
        Write-Host "  - Warning: Could not delete $ExeName (file may be locked)"
        Write-Host "  - You may need to reboot and run this script again"
    }
} else {
    Write-Host "  - Executable not found at $exePath"
}

$devModePath = "$InstallDir\.dev_mode"
if (Test-Path $devModePath) {
    Remove-Item $devModePath -Force
    Write-Host "  - Deleted: .dev_mode marker"
}

Write-Host ""

Write-Host "[5/6] Deleting data directory"
$DataDir = "$InstallDir\data"
if (Test-Path $DataDir) {
    try {
        Remove-Item $DataDir -Recurse -Force
        Write-Host "  - Deleted: data directory (whitelist.json, blacklist.json)"
    } catch {
        Write-Host "  - Warning: Could not delete data directory (may contain locked files)"
    }
} else {
    Write-Host "  - Data directory not found"
}
Write-Host ""

Write-Host "[6/6] Removing Windows Defender exclusion"
try {
    # Check if Defender module is available
    $defenderModule = Get-Module -ListAvailable -Name Defender
    if ($defenderModule -or (Get-Command Remove-MpPreference -ErrorAction SilentlyContinue)) {
        # Check if exclusion exists
        try {
            $existingExclusions = Get-MpPreference -ErrorAction Stop | Select-Object -ExpandProperty ExclusionPath
            if ($existingExclusions -contains $InstallDir) {
                Remove-MpPreference -ExclusionPath $InstallDir -ErrorAction Stop
                Write-Host "  - Removed folder exclusion: $InstallDir"
            } else {
                Write-Host "  - Folder exclusion not found (may already be removed)"
            }
        } catch {
            Write-Host "  - ERROR: Failed to check/remove exclusion" -ForegroundColor Red
            Write-Host "  - Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor Yellow
            Write-Host "  - Error Message: $($_.Exception.Message)" -ForegroundColor Yellow
            if ($_.Exception.InnerException) {
                Write-Host "  - Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Yellow
            }
            throw  # Re-throw to be caught by outer catch
        }
    } else {
        Write-Host "  - Windows Defender module not available (skipping exclusion removal)"
    }
} catch {
    Write-Host "  - ERROR: Failed to remove Defender exclusion" -ForegroundColor Red
    Write-Host "  - Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor Yellow
    Write-Host "  - Error Message: $($_.Exception.Message)" -ForegroundColor Yellow
    if ($_.Exception.InnerException) {
        Write-Host "  - Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Yellow
    }
    Write-Host "  - You may need to remove the exclusion manually in Windows Security settings" -ForegroundColor Yellow
}
Write-Host ""

# Try to remove the installation directory if it's empty
Write-Host "Cleaning up installation directory..."
if (Test-Path $InstallDir) {
    $remainingItems = Get-ChildItem $InstallDir -ErrorAction SilentlyContinue
    if ($remainingItems.Count -eq 0) {
        try {
            Remove-Item $InstallDir -Force
            Write-Host "  - Deleted: installation directory (now empty)"
        } catch {
            Write-Host "  - Warning: Could not delete installation directory"
        }
    } else {
        Write-Host "  - Installation directory contains remaining files, keeping it"
        Write-Host "  - Remaining items: $($remainingItems.Count)"
    }
}

Write-Host ""
Write-Host "========================================"
Write-Host "  Uninstall Complete!"
Write-Host "========================================"
Write-Host ""
Write-Host "Verification commands:"
Write-Host "  - Check Task Scheduler: Get-ScheduledTask -TaskName '$TaskName'"
Write-Host "  - Check running processes: Get-Process -Name '$ProcessName'"
Write-Host "  - Check directory: Get-ChildItem '$InstallDir'"
Write-Host ""
Write-Host "Note: If files could not be deleted, you may need to:"
Write-Host "  1. Reboot the system"
Write-Host "  2. Run this script again"
Write-Host ""

Read-Host "Press Enter to exit"

