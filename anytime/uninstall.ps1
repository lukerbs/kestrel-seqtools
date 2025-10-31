# Uninstall AnyDesk
# Removes the AnyDesk installation created by the anytime payload
# Must be run as Administrator

Write-Host ""
Write-Host "======================================"
Write-Host "  AnyDesk Uninstaller"
Write-Host "======================================"
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Find AnyDesk installation
$anydeskPaths = @(
    "${env:ProgramFiles(x86)}\AnyDesk\AnyDesk.exe",
    "$env:ProgramFiles\AnyDesk\AnyDesk.exe"
)

$anydeskExe = $null
foreach ($path in $anydeskPaths) {
    if (Test-Path $path) {
        $anydeskExe = $path
        Write-Host "Found AnyDesk at: $path" -ForegroundColor Cyan
        break
    }
}

if (-not $anydeskExe) {
    Write-Host "AnyDesk installation not found." -ForegroundColor Yellow
    Write-Host "Nothing to uninstall." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 0
}

Write-Host ""

# Step 1: Stop the AnyDesk service
Write-Host "Stopping AnyDesk service..." -ForegroundColor Cyan
try {
    $service = Get-Service -Name "AnyDesk" -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq 'Running') {
            Stop-Service -Name "AnyDesk" -Force -ErrorAction SilentlyContinue
            Write-Host "  Service stopped" -ForegroundColor Green
        } else {
            Write-Host "  Service already stopped" -ForegroundColor Gray
        }
    } else {
        Write-Host "  Service not found" -ForegroundColor Gray
    }
} catch {
    Write-Host "  Failed to stop service: $($_.Exception.Message)" -ForegroundColor Yellow
}

Start-Sleep -Seconds 1

# Step 2: Kill any running AnyDesk processes
Write-Host ""
Write-Host "Killing AnyDesk processes..." -ForegroundColor Cyan
$processes = Get-Process -Name "AnyDesk" -ErrorAction SilentlyContinue
if ($processes) {
    foreach ($proc in $processes) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            Write-Host "  Killed process: $($proc.Id)" -ForegroundColor Green
        } catch {
            Write-Host "  Failed to kill process $($proc.Id)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "  No running processes found" -ForegroundColor Gray
}

Start-Sleep -Seconds 1

# Step 3: Uninstall using AnyDesk CLI
Write-Host ""
Write-Host "Uninstalling AnyDesk..." -ForegroundColor Cyan
try {
    & $anydeskExe --uninstall | Out-Null
    Start-Sleep -Seconds 2
    Write-Host "  Uninstall command executed" -ForegroundColor Green
} catch {
    Write-Host "  Failed to execute uninstall: $($_.Exception.Message)" -ForegroundColor Yellow
}

Start-Sleep -Seconds 1

# Step 4: Verify uninstallation
Write-Host ""
Write-Host "Verifying uninstallation..." -ForegroundColor Cyan

$installDir = Split-Path $anydeskExe -Parent
if (Test-Path $installDir) {
    Write-Host "  WARNING: Installation directory still exists: $installDir" -ForegroundColor Yellow
    Write-Host "  Attempting manual cleanup..." -ForegroundColor Cyan
    
    try {
        Remove-Item -Path $installDir -Recurse -Force -ErrorAction Stop
        Write-Host "  Manually removed installation directory" -ForegroundColor Green
    } catch {
        Write-Host "  Failed to remove directory: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  You may need to manually delete: $installDir" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Installation directory removed successfully" -ForegroundColor Green
}

# Check if service still exists
$service = Get-Service -Name "AnyDesk" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "  WARNING: AnyDesk service still exists" -ForegroundColor Yellow
    Write-Host "  Attempting to remove service..." -ForegroundColor Cyan
    
    try {
        sc.exe delete AnyDesk | Out-Null
        Write-Host "  Service removed" -ForegroundColor Green
    } catch {
        Write-Host "  Failed to remove service" -ForegroundColor Red
    }
} else {
    Write-Host "  Service removed successfully" -ForegroundColor Green
}

# Check for remaining processes
$remainingProcesses = Get-Process -Name "AnyDesk" -ErrorAction SilentlyContinue
if ($remainingProcesses) {
    Write-Host "  WARNING: AnyDesk processes still running" -ForegroundColor Yellow
} else {
    Write-Host "  No remaining processes found" -ForegroundColor Green
}

# Clean up AppData
Write-Host ""
Write-Host "Cleaning up user data..." -ForegroundColor Cyan
$appdataPaths = @(
    "$env:APPDATA\AnyDesk",
    "$env:LOCALAPPDATA\AnyDesk"
)

foreach ($path in $appdataPaths) {
    if (Test-Path $path) {
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            Write-Host "  Removed: $path" -ForegroundColor Green
        } catch {
            Write-Host "  Failed to remove: $path" -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host "======================================"
Write-Host "  Uninstallation Complete!"
Write-Host "======================================"
Write-Host ""
Write-Host "AnyDesk has been removed from your system." -ForegroundColor Green
Write-Host ""
Read-Host "Press Enter to exit"

