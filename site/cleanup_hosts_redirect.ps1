#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Cleanup Bank of America Hosts File Redirect + SSL
.DESCRIPTION
    This script removes all changes made by setup_hosts_redirect.ps1
#>

Write-Host "========================================"
Write-Host "Bank of America Cleanup"
Write-Host "========================================"
Write-Host ""

# Configuration
$Domain = "bankofamerica.com"
$HostsFile = "C:\Windows\System32\drivers\etc\hosts"
$CertFile = "${Domain}+3.pem"
$KeyFile = "${Domain}+3-key.pem"
$DeployDir = "$env:LOCALAPPDATA\Temp"

# ====================
# STEP 1: Remove SSL Certificate
# ====================
Write-Host "[1/4] SSL Certificate Cleanup"
Write-Host "-------------------------------------------"
Write-Host ""

# Remove from trust store using PowerShell
Write-Host "[+] Removing certificate from Windows trust store..."
try {
    Get-ChildItem Cert:\LocalMachine\Root | 
        Where-Object { $_.Subject -like "*$Domain*" } | 
        Remove-Item -Force -ErrorAction Stop
    
    Write-Host "[+] Certificate removed from trust store"
} catch {
    Write-Host "[!] Certificate not found in trust store (may not have been installed)"
}

# Delete certificate files from site directory
if (Test-Path $CertFile) {
    Remove-Item $CertFile -Force
    Write-Host "[+] Deleted $CertFile"
}

if (Test-Path $KeyFile) {
    Remove-Item $KeyFile -Force
    Write-Host "[+] Deleted $KeyFile"
}
Write-Host ""

# ====================
# STEP 2: Clean Hosts File
# ====================
Write-Host "[2/4] Hosts File Cleanup"
Write-Host "-------------------------------------------"
Write-Host ""

Write-Host "[+] Removing Bank of America redirect from hosts file..."
try {
    $hostsContent = Get-Content $HostsFile
    $newContent = $hostsContent | Where-Object { 
        $_ -notmatch "bankofamerica.com" -and $_ -notmatch "Scambaiting redirect" 
    }
    
    Set-Content -Path $HostsFile -Value $newContent -Force
    Write-Host "[+] Hosts file cleaned successfully"
} catch {
    Write-Host "[!] Error: Could not update hosts file"
}
Write-Host ""

# ====================
# STEP 3: DNS Cache
# ====================
Write-Host "[3/4] DNS Cache Flush"
Write-Host "-------------------------------------------"
Write-Host ""

Write-Host "[+] Flushing DNS cache..."
ipconfig /flushdns | Out-Null

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] DNS cache flushed successfully"
} else {
    Write-Host "[!] Warning: Could not flush DNS cache"
}
Write-Host ""

# ====================
# STEP 4: Clean Deployment Directory
# ====================
Write-Host "[4/4] Cleaning Deployment Directory"
Write-Host "-------------------------------------------"
Write-Host ""

$deployCertPath = Join-Path $DeployDir $CertFile
$deployKeyPath = Join-Path $DeployDir $KeyFile

if (Test-Path $deployCertPath) {
    Remove-Item $deployCertPath -Force
    Write-Host "[+] Deleted deployment certificate: $CertFile"
}

if (Test-Path $deployKeyPath) {
    Remove-Item $deployKeyPath -Force
    Write-Host "[+] Deleted deployment key: $KeyFile"
}
Write-Host ""

# ====================
# Summary
# ====================
Write-Host "========================================"
Write-Host "Cleanup Complete!"
Write-Host "========================================"
Write-Host ""
Write-Host "Bank of America will now resolve to the real website."
Write-Host "All SSL certificates and redirects have been removed:"
Write-Host "  - Certificate removed from Windows trust store"
Write-Host "  - Certificate files deleted from site directory"
Write-Host "  - Certificate files deleted from deployment directory"
Write-Host "  - Hosts file entries removed"
Write-Host "  - DNS cache flushed"
Write-Host ""
Write-Host "Note: To remove the mkcert local CA completely, run: mkcert -uninstall"
Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

