#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Uninstall Bank of America Scambaiting Proxy Service
.DESCRIPTION
    Removes the netservice.exe, Task Scheduler entry, and all related files
#>

# Configuration
$OutputName = "netservice"
$TaskName = "WebHostService"
$DeployDir = "$env:LOCALAPPDATA\Temp"
$ExePath = "$DeployDir\$OutputName.exe"
$DataDir = "$DeployDir\mitmproxy_data"

Write-Host "========================================"
Write-Host "Uninstalling BofA Scambaiting Proxy"
Write-Host "========================================"
Write-Host ""

$itemsRemoved = 0

# ====================
# Remove Task Scheduler entry
# ====================
Write-Host "Checking for Task Scheduler entry..."

$taskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($taskExists) {
    Write-Host "Removing task: $TaskName"
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Task removed successfully" -ForegroundColor Green
        $itemsRemoved++
    } catch {
        Write-Host "ERROR: Failed to remove task!" -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
} else {
    Write-Host "Task not found (already removed or never installed)"
}

Write-Host ""

# ====================
# Stop running process
# ====================
Write-Host "Checking for running process..."

$process = Get-Process -Name $OutputName -ErrorAction SilentlyContinue
if ($process) {
    Write-Host "Stopping $OutputName.exe (PID: $($process.Id))..."
    try {
        Stop-Process -Name $OutputName -Force
        Start-Sleep -Seconds 2
        Write-Host "Process stopped successfully" -ForegroundColor Green
        $itemsRemoved++
    } catch {
        Write-Host "ERROR: Failed to stop process!" -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
} else {
    Write-Host "Process not running"
}

Write-Host ""

# ====================
# Remove executable
# ====================
Write-Host "Checking for deployed files..."

if (Test-Path $ExePath) {
    Write-Host "Removing: $ExePath"
    try {
        Remove-Item $ExePath -Force
        Write-Host "Executable removed" -ForegroundColor Green
        $itemsRemoved++
    } catch {
        Write-Host "WARNING: Failed to remove executable!" -ForegroundColor Yellow
        Write-Host "It may be locked. Try running this script again after rebooting."
    }
} else {
    Write-Host "Executable not found (already removed)"
}

# Remove .dev_mode marker if it exists
if (Test-Path "$DeployDir\.dev_mode") {
    Remove-Item "$DeployDir\.dev_mode" -Force -ErrorAction SilentlyContinue
    Write-Host "Removed .dev_mode marker"
    $itemsRemoved++
}

Write-Host ""

# ====================
# Optional: Remove mitmproxy data
# ====================
if (Test-Path $DataDir) {
    Write-Host "Found mitmproxy data directory: $DataDir"
    $response = Read-Host "Do you want to remove certificates and logs? (y/N)"
    
    if ($response -eq "y" -or $response -eq "Y") {
        try {
            Remove-Item $DataDir -Recurse -Force
            Write-Host "Data directory removed" -ForegroundColor Green
            $itemsRemoved++
        } catch {
            Write-Host "WARNING: Failed to remove data directory!" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Keeping mitmproxy data (certificates preserved)"
    }
} else {
    Write-Host "No mitmproxy data found"
}

Write-Host ""

# ====================
# Remove Windows proxy settings reminder
# ====================
Write-Host "========================================"
Write-Host "Post-Uninstall Steps"
Write-Host "========================================"
Write-Host ""
Write-Host "IMPORTANT: Remember to disable the proxy in your browser!" -ForegroundColor Yellow
Write-Host ""
Write-Host "Windows Settings → Network & Internet → Proxy"
Write-Host "Turn OFF 'Use a proxy server'"
Write-Host ""

# ====================
# Summary
# ====================
Write-Host "========================================"
Write-Host "Uninstallation Complete!"
Write-Host "========================================"
Write-Host ""

if ($itemsRemoved -gt 0) {
    Write-Host "Removed $itemsRemoved item(s)" -ForegroundColor Green
} else {
    Write-Host "No items were removed (service may have already been uninstalled)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "The service has been completely removed."
Write-Host "To reinstall, run: .\install.ps1"
Write-Host ""

Read-Host "Press Enter to exit"

