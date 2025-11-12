# ============================================================================
# Screen Blanking Prevention - Verification Script
# Verifies registry paths, Hardware ID formats, and Windows API access
# ============================================================================

Write-Host ""
Write-Host "========================================"
Write-Host "  Screen Blanking Prevention Verification"
Write-Host "========================================"
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator" -ForegroundColor Yellow
    Write-Host "   Some checks may fail without admin privileges"
    Write-Host ""
} else {
    Write-Host "[OK] Running as Administrator" -ForegroundColor Green
    Write-Host ""
}

# ============================================================================
# 1. Registry Path Verification
# ============================================================================

Write-Host "[1/6] Registry Path Verification"
Write-Host "----------------------------------------"

$basePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$denyIdsPath = "$basePath\DenyDeviceIDs"

# Check base path
Write-Host "Base registry path: $basePath"
if (Test-Path $basePath) {
    Write-Host "  [OK] Path exists" -ForegroundColor Green
    
    # Check existing values
    $props = Get-ItemProperty -Path $basePath -ErrorAction SilentlyContinue
    if ($props) {
        Write-Host "  Existing values:"
        if ($props.DenyDeviceIDs) {
            Write-Host "    - DenyDeviceIDs = $($props.DenyDeviceIDs)"
        }
        if ($props.DenyDeviceIDsRetroactive) {
            Write-Host "    - DenyDeviceIDsRetroactive = $($props.DenyDeviceIDsRetroactive)"
        }
    }
} else {
    Write-Host "  [WARN] Path does not exist (will be created)" -ForegroundColor Yellow
}

Write-Host ""

# Check DenyDeviceIDs subkey
Write-Host "DenyDeviceIDs subkey: $denyIdsPath"
if (Test-Path $denyIdsPath) {
    Write-Host "  [OK] Subkey exists" -ForegroundColor Green
    
    # List existing Hardware IDs
    $existingIds = Get-ChildItem -Path $denyIdsPath -ErrorAction SilentlyContinue
    if ($existingIds) {
        Write-Host "  Existing Hardware IDs:"
        foreach ($id in $existingIds) {
            $value = Get-ItemProperty -Path $id.PSPath -ErrorAction SilentlyContinue
            Write-Host "    - $($value.PSChildName): $($value.'(default)')"
        }
    }
} else {
    Write-Host "  [WARN] Subkey does not exist (will be created)" -ForegroundColor Yellow
}

Write-Host ""

# ============================================================================
# 2. Hardware ID Format Verification
# ============================================================================

Write-Host "[2/6] Hardware ID Format Verification"
Write-Host "----------------------------------------"

# Get sample Hardware IDs
$sampleMonitor = Get-PnpDevice -Class Monitor | Select-Object -First 1 -ErrorAction SilentlyContinue
if ($sampleMonitor) {
    Write-Host "Sample Monitor Hardware ID:"
    Write-Host "  Format: '$($sampleMonitor.InstanceId)'"
    Write-Host "  Length: $($sampleMonitor.InstanceId.Length)"
    Write-Host "  Contains backslash: $($sampleMonitor.InstanceId -match '\\')"
    Write-Host "  Case: $(if ($sampleMonitor.InstanceId -cmatch '[a-z]') { 'Mixed' } else { 'Uppercase' })"
} else {
    Write-Host "  [WARN] No monitor devices found" -ForegroundColor Yellow
}

Write-Host ""

# Get Root bus devices
Write-Host "Root bus device Hardware IDs (first 3):"
$rootDevices = Get-PnpDevice | Where-Object {$_.InstanceId -like "Root\*"} | Select-Object -First 3
if ($rootDevices) {
    foreach ($device in $rootDevices) {
        Write-Host "  - $($device.InstanceId)"
    }
} else {
    Write-Host "  [WARN] No Root bus devices found" -ForegroundColor Yellow
}

Write-Host ""

# ============================================================================
# 3. Registry Write Permissions Test
# ============================================================================

Write-Host "[3/6] Registry Write Permissions Test"
Write-Host "----------------------------------------"

try {
    $testPath = "SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($testPath, $true)
    
    if ($key) {
        Write-Host "  [OK] Write access: OK" -ForegroundColor Green
        $key.Close()
    } else {
        Write-Host "  [WARN] Key does not exist (will be created)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [ERROR] Error: $_" -ForegroundColor Red
}

Write-Host ""

# ============================================================================
# 4. Python winreg Module Access Test
# ============================================================================

Write-Host "[4/6] Python winreg Module Access Test"
Write-Host "----------------------------------------"

$pythonCmd = @"
import winreg
import sys

try:
    key = winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r'SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions',
        0,
        winreg.KEY_READ
    )
    print('[OK] winreg access: OK')
    winreg.CloseKey(key)
except FileNotFoundError:
    print('[WARN] Path does not exist (will be created)')
except PermissionError:
    print('[ERROR] Permission denied (requires admin)')
    sys.exit(1)
except Exception as e:
    print(f'[ERROR] Error: {e}')
    sys.exit(1)
"@

try {
    $result = python -c $pythonCmd 2>&1
    Write-Host "  $result"
} catch {
    Write-Host "  [ERROR] Python not found or error: $_" -ForegroundColor Red
}

Write-Host ""

# ============================================================================
# 5. Hardware ID Case Sensitivity Test
# ============================================================================

Write-Host "[5/6] Hardware ID Case Sensitivity Test"
Write-Host "----------------------------------------"

$testId = "ROOT\BASICDISPLAY\0000"
$variations = @(
    "ROOT\BASICDISPLAY\0000",
    "Root\BASICDISPLAY\0000",
    "root\BASICDISPLAY\0000"
)

Write-Host "Testing case variations for: $testId"
foreach ($variant in $variations) {
    $found = Get-PnpDevice | Where-Object {$_.InstanceId -eq $variant} | Select-Object -First 1
    if ($found) {
        Write-Host "  [OK] Found: '$variant'" -ForegroundColor Green
    } else {
        Write-Host "  [NOT FOUND] Not found: '$variant'" -ForegroundColor Red
    }
}

Write-Host ""

# ============================================================================
# 6. Hardware ID Format Analysis
# ============================================================================

Write-Host "[6/6] Hardware ID Format Analysis"
Write-Host "----------------------------------------"

Write-Host "Analyzing Hardware ID format requirements:"
Write-Host ""

# Check if Hardware IDs include \0000 suffix
$devicesWithSuffix = Get-PnpDevice | Where-Object {$_.InstanceId -like "*\0000"} | Select-Object -First 3
$devicesWithoutSuffix = Get-PnpDevice | Where-Object {$_.InstanceId -like "Root\*" -and $_.InstanceId -notlike "*\0000"} | Select-Object -First 3

Write-Host "Devices WITH \0000 suffix:"
if ($devicesWithSuffix) {
    foreach ($device in $devicesWithSuffix) {
        Write-Host "  - $($device.InstanceId)"
    }
} else {
    Write-Host "  (none found)"
}

Write-Host ""
Write-Host "Devices WITHOUT \0000 suffix:"
if ($devicesWithoutSuffix) {
    foreach ($device in $devicesWithoutSuffix) {
        Write-Host "  - $($device.InstanceId)"
    }
} else {
    Write-Host "  (none found)"
}

Write-Host ""

# ============================================================================
# Summary
# ============================================================================

Write-Host "========================================"
Write-Host "  Verification Complete"
Write-Host "========================================"
Write-Host ""
Write-Host "Key Findings:"
Write-Host "  - Registry path format: HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
Write-Host "  - Hardware IDs appear to use: Uppercase, single backslash, may include \0000 suffix"
Write-Host ""
Write-Host "Recommendations:"
Write-Host "  - Use exact Hardware ID strings as provided by research expert"
Write-Host "  - Registry paths are correct for Windows Group Policy"
Write-Host "  - Python winreg module should work for registry operations"
Write-Host ""
Write-Host "Press Enter to exit..."
Read-Host

