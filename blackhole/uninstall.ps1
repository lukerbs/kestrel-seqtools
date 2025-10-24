# ============================================================================
# Blackhole Input Firewall - Uninstallation Script (PowerShell)
# Removes the service and cleans up all files
# ============================================================================

# Require administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Please right-click and select 'Run as Administrator'."
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

$TaskName = "MicrosoftEdgeUpdateTaskMachineCore"
$ExeName = "taskhostw.exe"
$InstallDir = "$env:LOCALAPPDATA\Temp"

Write-Host ""
Write-Host "========================================"
Write-Host "  Task Host Service - Uninstall"
Write-Host "========================================"
Write-Host ""

Write-Host "[1/4] Stopping Task Scheduler service"
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Write-Host "  - Service stopped"
} else {
    Write-Host "  - Service not found or not running"
}
Write-Host ""

Write-Host "[2/4] Deleting Task Scheduler service"
if ($task) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "  - Service deleted"
} else {
    Write-Host "  - Service not found or already deleted"
}
Write-Host ""

Write-Host "[3/4] Terminating running processes"
$process = Get-Process -Name "blackhole" -ErrorAction SilentlyContinue
if ($process) {
    Stop-Process -Name "blackhole" -Force
    Write-Host "  - Process terminated"
} else {
    Write-Host "  - Process not found or already terminated"
}
Write-Host ""

Write-Host "[4/4] Deleting files"

$exePath = "$InstallDir\$ExeName"
if (Test-Path $exePath) {
    try {
        Remove-Item $exePath -Force
        Write-Host "  - Deleted: $exePath"
    } catch {
        Write-Host "  - Warning: Could not delete $ExeName (file may be locked)" -ForegroundColor Yellow
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
Write-Host "========================================"
Write-Host "  Uninstall Complete!"
Write-Host "========================================"
Write-Host ""
Write-Host "Verification commands:"
Write-Host "  - Check Task Scheduler: Get-ScheduledTask -TaskName '$TaskName'"
Write-Host "  - Check running processes: Get-Process -Name 'blackhole'"
Write-Host "  - Check directory: Get-ChildItem '$InstallDir'"
Write-Host ""

Read-Host "Press Enter to exit"

