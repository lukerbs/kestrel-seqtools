# ============================================================================
# Blackhole Input Firewall - Uninstall OLD Version Script (PowerShell)
# Removes the old "blackhole" service before installing the new disguised version
# ============================================================================

# Require administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Please right-click and select 'Run as Administrator'."
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Old service configuration
$OldTaskName = "blackhole"
$OldExeName = "blackhole.exe"
$OldProcessName = "blackhole"
$OldTaskHostExeName = "taskhostw.exe"
$OldTaskHostProcessName = "taskhostw"
$InstallDir = "$env:LOCALAPPDATA\Temp"

Write-Host ""
Write-Host "========================================"
Write-Host "  Uninstall OLD Blackhole Service"
Write-Host "========================================"
Write-Host ""

Write-Host "[1/4] Stopping old Task Scheduler service"
$task = Get-ScheduledTask -TaskName $OldTaskName -ErrorAction SilentlyContinue
if ($task) {
    Stop-ScheduledTask -TaskName $OldTaskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "  - Task stopped: $OldTaskName"
} else {
    Write-Host "  - Task not found: $OldTaskName (may already be uninstalled)"
}
Write-Host ""

Write-Host "[2/4] Removing old Task Scheduler entry"
if ($task) {
    Unregister-ScheduledTask -TaskName $OldTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  - Task removed: $OldTaskName"
} else {
    Write-Host "  - No task to remove"
}
Write-Host ""

Write-Host "[3/4] Terminating old process"
$process = Get-Process -Name $OldProcessName -ErrorAction SilentlyContinue
if ($process) {
    Stop-Process -Name $OldProcessName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Write-Host "  - Process terminated: $OldExeName"
} else {
    Write-Host "  - Process not running"
}
Write-Host ""

Write-Host "[4/4] Deleting old executable"
$OldExePath = "$InstallDir\$OldExeName"
if (Test-Path $OldExePath) {
    Remove-Item $OldExePath -Force -ErrorAction SilentlyContinue
    if (Test-Path $OldExePath) {
        Write-Host "  - WARNING: Failed to delete $OldExePath" -ForegroundColor Yellow
        Write-Host "  - File may be in use. Please delete manually or reboot and try again."
    } else {
        Write-Host "  - Deleted: $OldExePath"
    }
} else {
    Write-Host "  - Executable not found (may already be deleted)"
}

# Also remove .dev_mode marker if it exists
$OldDevMarker = "$InstallDir\.dev_mode"
if (Test-Path $OldDevMarker) {
    Remove-Item $OldDevMarker -Force -ErrorAction SilentlyContinue
    Write-Host "  - Deleted: .dev_mode marker"
}

# Also remove taskhostw.exe if it exists (old Blackhole build)
$OldTaskHostPath = "$InstallDir\$OldTaskHostExeName"
if (Test-Path $OldTaskHostPath) {
    try {
        # Check if any taskhostw process is running from Temp directory
        $taskHostProcesses = Get-Process -Name $OldTaskHostProcessName -ErrorAction SilentlyContinue
        if ($taskHostProcesses) {
            foreach ($proc in $taskHostProcesses) {
                try {
                    # Get process path using WMI
                    $procInfo = Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue
                    if ($procInfo -and $procInfo.ExecutablePath -like "*Temp*") {
                        Write-Host "  - Stopping $OldTaskHostExeName process from Temp (PID: $($proc.Id))..."
                        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 2
                    }
                } catch {
                    # Process may have exited, continue
                }
            }
        }
        
        Remove-Item $OldTaskHostPath -Force -ErrorAction SilentlyContinue
        if (Test-Path $OldTaskHostPath) {
            Write-Host "  - WARNING: Failed to delete $OldTaskHostExeName (file may be locked)" -ForegroundColor Yellow
            Write-Host "  - You may need to reboot and run this script again"
        } else {
            Write-Host "  - Deleted: $OldTaskHostExeName (old Blackhole build)"
        }
    } catch {
        Write-Host "  - Warning: Could not delete $OldTaskHostExeName: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "  - $OldTaskHostExeName not found in Temp (may already be deleted)"
}
Write-Host ""

Write-Host "========================================"
Write-Host "  Old Service Uninstalled!"
Write-Host "========================================"
Write-Host ""
Write-Host "The old 'blackhole' service has been removed."
Write-Host "You can now install the new disguised version with: .\install.ps1"
Write-Host ""

Read-Host "Press Enter to exit"

