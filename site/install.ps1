#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install Bank of America Scambaiting Proxy Service
.DESCRIPTION
    Deploys the netservice.exe and creates a Windows Task Scheduler entry for auto-start
#>

# Configuration
$OutputName = "netservice"
$TaskName = "WebHostService"
$DeployDir = "$env:LOCALAPPDATA\Temp"
$ExePath = "$DeployDir\$OutputName.exe"

Write-Host "========================================"
Write-Host "Installing BofA Scambaiting Proxy"
Write-Host "========================================"
Write-Host ""

# ====================
# Check if exe exists
# ====================
if (-not (Test-Path "dist\$OutputName.exe")) {
    Write-Host "ERROR: dist\$OutputName.exe not found!" -ForegroundColor Red
    Write-Host "Please run .\build_bank.ps1 first to create the executable."
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# ====================
# Stop existing service
# ====================
Write-Host "Checking for existing installation..."

$taskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($taskExists) {
    Write-Host "Removing existing task: $TaskName"
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Task removed"
}

$process = Get-Process -Name $OutputName -ErrorAction SilentlyContinue
if ($process) {
    Write-Host "Stopping existing $OutputName.exe process..."
    Stop-Process -Name $OutputName -Force
    Start-Sleep -Seconds 3
    Write-Host "Process stopped"
}

Write-Host ""

# ====================
# Deploy exe
# ====================
Write-Host "Deploying to: $ExePath"

if (-not (Test-Path $DeployDir)) {
    New-Item -ItemType Directory -Path $DeployDir -Force | Out-Null
}

# Copy with retry logic
$retryCount = 0
$maxRetries = 5
$copied = $false

while (-not $copied -and $retryCount -lt $maxRetries) {
    try {
        Copy-Item "dist\$OutputName.exe" $ExePath -Force -ErrorAction Stop
        Write-Host "Deployment successful!" -ForegroundColor Green
        $copied = $true
    } catch {
        $retryCount++
        if ($retryCount -lt $maxRetries) {
            Write-Host "File is locked, retrying in 2 seconds... (attempt $retryCount/$maxRetries)"
            Start-Sleep -Seconds 2
        } else {
            Write-Host ""
            Write-Host "ERROR: Could not deploy exe after $maxRetries attempts!" -ForegroundColor Red
            Write-Host "The file may still be locked by another process."
            Read-Host "Press Enter to exit"
            exit 1
        }
    }
}

# Copy .dev_mode marker if it exists
if (Test-Path "dist\.dev_mode") {
    Copy-Item "dist\.dev_mode" "$DeployDir\.dev_mode" -Force
    Write-Host "Copied .dev_mode marker (console window will be visible)"
} else {
    # Clean up any existing .dev_mode marker
    if (Test-Path "$DeployDir\.dev_mode") {
        Remove-Item "$DeployDir\.dev_mode" -Force
    }
}

Write-Host ""

# ====================
# Create Task Scheduler entry
# ====================
Write-Host "Creating Task Scheduler service..."

$action = New-ScheduledTaskAction -Execute $ExePath
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 0)

try {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "Task created: $TaskName" -ForegroundColor Green
    Write-Host "Service will start automatically on boot"
    Write-Host ""
} catch {
    Write-Host "ERROR: Failed to create Task Scheduler task!" -ForegroundColor Red
    Write-Host $_.Exception.Message
    Read-Host "Press Enter to exit"
    exit 1
}

# ====================
# Start the service
# ====================
Write-Host "Starting service now..."

try {
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 2
    
    # Verify it started
    $process = Get-Process -Name $OutputName -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "Service started successfully!" -ForegroundColor Green
        Write-Host "PID: $($process.Id)"
    } else {
        Write-Host "WARNING: Service may not have started properly." -ForegroundColor Yellow
        Write-Host "Check Task Scheduler or try rebooting."
    }
} catch {
    Write-Host "WARNING: Failed to start service automatically." -ForegroundColor Yellow
    Write-Host "You may need to start it manually or reboot."
}

Write-Host ""

# ====================
# Summary
# ====================
Write-Host "========================================"
Write-Host "Installation Complete!"
Write-Host "========================================"
Write-Host ""
Write-Host "Service Details:"
Write-Host "  Executable:  $ExePath"
Write-Host "  Task Name:   $TaskName"
Write-Host "  Proxy Port:  8080"
Write-Host "  Flask Port:  5000"
Write-Host ""
Write-Host "The service is now running and will start automatically on boot."
Write-Host ""
Write-Host "Browser Setup:"
Write-Host "  1. Configure browser to use proxy: 127.0.0.1:8080"
Write-Host "  2. Install certificate from: http://mitm.it"
Write-Host "  3. Visit: https://www.bankofamerica.com"
Write-Host ""
Write-Host "Management Commands:"
Write-Host "  Start:     Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "  Stop:      Stop-Process -Name '$OutputName' -Force"
Write-Host "  Uninstall: .\uninstall.ps1"
Write-Host ""

Read-Host "Press Enter to exit"

