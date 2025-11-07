# blackhole/diagnostics.ps1
# AnyDesk Log Monitoring Diagnostics - Snapshot Only

$ErrorActionPreference = "Continue"

function Test-FileLock {
    param([string]$Path)
    try {
        $stream = [System.IO.File]::Open($Path, 'Open', 'Read', 'None')
        $stream.Close()
        return $false
    } catch {
        return $true
    }
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host "ANYDESK LOG DIAGNOSTICS - $timestamp"
Write-Host ""

# AnyDesk Processes
Write-Host "ANYDESK PROCESSES:"
$processes = Get-Process -Name "AnyDesk" -ErrorAction SilentlyContinue
if ($processes) {
    foreach ($proc in $processes) {
        Write-Host "  PID: $($proc.Id)"
        Write-Host "  Path: $($proc.Path)"
        Write-Host "  Started: $($proc.StartTime)"
        Write-Host "  Memory: $([math]::Round($proc.WorkingSet64/1MB, 2)) MB"
        Write-Host ""
    }
} else {
    Write-Host "  No AnyDesk processes running"
    Write-Host ""
}

# Blackhole Process
Write-Host "BLACKHOLE PROCESS:"
$blackhole = Get-Process -Name "AnyDeskClient" -ErrorAction SilentlyContinue
if ($blackhole) {
    Write-Host "  PID: $($blackhole.Id)"
    Write-Host "  Memory: $([math]::Round($blackhole.WorkingSet64/1MB, 2)) MB"
    Write-Host "  Started: $($blackhole.StartTime)"
} else {
    Write-Host "  Not running"
}
Write-Host ""

# Log Directory Files
Write-Host "LOG FILES (C:\ProgramData\AnyDesk):"
$logDir = "C:\ProgramData\AnyDesk"
if (Test-Path $logDir) {
    $files = Get-ChildItem $logDir -File | Where-Object { $_.Name -match "(trace|\.txt$)" }
    foreach ($file in $files) {
        Write-Host "  $($file.Name)"
        Write-Host "    Size: $([math]::Round($file.Length/1KB, 2)) KB"
        Write-Host "    Modified: $($file.LastWriteTime)"
        $locked = Test-FileLock $file.FullName
        Write-Host "    Locked: $locked"
        Write-Host ""
    }
} else {
    Write-Host "  Directory not found"
    Write-Host ""
}

# Connection Trace (Last 10 lines)
Write-Host "CONNECTION_TRACE.TXT (Last 10 lines):"
$connFile = "C:\ProgramData\AnyDesk\connection_trace.txt"
if (Test-Path $connFile) {
    $lines = Get-Content $connFile -Tail 10
    foreach ($line in $lines) {
        if ($line.Trim()) {
            Write-Host "  $line"
        }
    }
} else {
    Write-Host "  File not found"
}
Write-Host ""

# Search for Client-IDs in ad_svc.trace
Write-Host "AD_SVC.TRACE - Client-IDs (Last 10):"
$traceFile = "C:\ProgramData\AnyDesk\ad_svc.trace"
if (Test-Path $traceFile) {
    $matches = Get-Content $traceFile -Tail 500 | Select-String "Client-ID:" | Select-Object -Last 10
    if ($matches) {
        foreach ($match in $matches) {
            Write-Host "  $($match.Line.Trim())"
        }
    } else {
        Write-Host "  No Client-ID entries found in last 500 lines"
    }
} else {
    Write-Host "  File not found"
}
Write-Host ""

# Search for IPs in ad_svc.trace
Write-Host "AD_SVC.TRACE - IP Addresses (Last 10):"
if (Test-Path $traceFile) {
    $matches = Get-Content $traceFile -Tail 500 | Select-String "logged in from" | Select-Object -Last 10
    if ($matches) {
        foreach ($match in $matches) {
            Write-Host "  $($match.Line.Trim())"
        }
    } else {
        Write-Host "  No IP entries found in last 500 lines"
    }
} else {
    Write-Host "  File not found"
}
Write-Host ""

# Portable mode logs
Write-Host "PORTABLE MODE LOGS (%APPDATA%\AnyDesk):"
$portableDir = Join-Path $env:APPDATA "AnyDesk"
if (Test-Path $portableDir) {
    Write-Host "  Directory exists"
    $portableFiles = Get-ChildItem $portableDir -File -Filter "*.trace" -ErrorAction SilentlyContinue
    if ($portableFiles) {
        foreach ($file in $portableFiles) {
            Write-Host "  $($file.Name) - $([math]::Round($file.Length/1KB, 2)) KB"
        }
    } else {
        Write-Host "  No trace files found"
    }
} else {
    Write-Host "  Directory not found (expected for service mode)"
}
Write-Host ""

Write-Host "Diagnostics complete"

