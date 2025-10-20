#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Setup Bank of America Hosts File Redirect + SSL for Scambaiting
.DESCRIPTION
    This script configures Windows to redirect bankofamerica.com to localhost
    and generates trusted SSL certificates using mkcert.
#>

Write-Host "========================================"
Write-Host "Bank of America Local HTTPS Setup"
Write-Host "========================================"
Write-Host ""

# Configuration
$Domain = "bankofamerica.com"
$HostsFile = "C:\Windows\System32\drivers\etc\hosts"
$BackupFile = "C:\Windows\System32\drivers\etc\hosts.backup"
$CertFile = "${Domain}+3.pem"
$KeyFile = "${Domain}+3-key.pem"

# ====================
# STEP 1: SSL Certificate
# ====================
Write-Host "[1/3] SSL Certificate Setup"
Write-Host "-------------------------------------------"
Write-Host ""

# Check if mkcert is installed
if (-not (Get-Command mkcert -ErrorAction SilentlyContinue)) {
    Write-Host "[!] mkcert is not installed"
    Write-Host "[+] Auto-installing Chocolatey and mkcert..."
    Write-Host "[+] This may take a few minutes..."
    Write-Host ""
    
    # Check if Chocolatey is installed
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "[+] Installing Chocolatey package manager..."
        
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            
            # Refresh environment to get choco
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
            
            if (Get-Command choco -ErrorAction SilentlyContinue) {
                Write-Host "[+] Chocolatey installed successfully"
                Write-Host ""
            } else {
                throw "Chocolatey command not found after installation"
            }
        } catch {
            Write-Host ""
            Write-Host "ERROR: Failed to install Chocolatey" -ForegroundColor Red
            Write-Host ""
            Write-Host "This may be due to a broken existing installation."
            Write-Host "Run fix_chocolatey.ps1 to remove it, then try again."
            Write-Host ""
            Read-Host "Press Enter to exit"
            exit 1
        }
    } else {
        Write-Host "[+] Chocolatey already installed"
    }
    
    # Install mkcert
    Write-Host "[+] Installing mkcert..."
    choco install mkcert -y --no-progress | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "ERROR: Failed to install mkcert" -ForegroundColor Red
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Refresh environment to get mkcert
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    
    Write-Host "[+] mkcert installed successfully"
    Write-Host ""
}

# Check if mkcert CA is installed (one-time setup)
try {
    $caRoot = (mkcert -CAROOT 2>&1) | Out-String
    $caRoot = $caRoot.Trim()
    
    if (-not (Test-Path "$caRoot\rootCA.pem")) {
        Write-Host "[+] Installing mkcert local CA (one-time setup)..."
        mkcert -install
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Local CA installed successfully"
        } else {
            Write-Host "[!] Failed to install mkcert CA"
            Write-Host "[!] Certificates may not be trusted by browsers"
        }
    } else {
        Write-Host "[+] Local CA already installed"
    }
} catch {
    Write-Host "[!] Warning: Could not check CA installation status"
}

# Check if certificate already exists
if (Test-Path $CertFile) {
    Write-Host "[!] Certificate already exists: $CertFile"
    Write-Host "[!] Skipping generation..."
} else {
    Write-Host "[+] Generating SSL certificate for $Domain..."
    mkcert $Domain "www.$Domain" "secure.$Domain" "online.$Domain"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Certificate generated successfully"
    } else {
        Write-Host "[!] Failed to generate certificate"
        Write-Host "[!] Continuing without HTTPS support..."
    }
}

# Install certificate to trust store
if (Test-Path $CertFile) {
    Write-Host "[+] Installing certificate to Windows trust store..."
    certutil -addstore -f "Root" $CertFile | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Certificate installed - browsers will trust this site"
    } else {
        Write-Host "[!] Warning: Could not install certificate to trust store"
    }
}
Write-Host ""

# ====================
# STEP 2: Hosts File
# ====================
Write-Host "[2/3] Hosts File Configuration"
Write-Host "-------------------------------------------"
Write-Host ""

# Backup hosts file
Write-Host "[+] Creating backup of hosts file..."
try {
    Copy-Item $HostsFile $BackupFile -Force
    Write-Host "[+] Backup created: $BackupFile"
} catch {
    Write-Host "[!] Warning: Could not create backup"
}
Write-Host ""

# Check if entries already exist
$hostsContent = Get-Content $HostsFile
if ($hostsContent -match "bankofamerica.com") {
    Write-Host "[!] Bank of America redirect already exists in hosts file"
    Write-Host "[!] Skipping modification"
} else {
    Write-Host "[+] Adding Bank of America redirect to hosts file..."
    
    $entries = @"

# Scambaiting redirect - Added by setup script
127.0.0.1 bankofamerica.com
127.0.0.1 www.bankofamerica.com
127.0.0.1 secure.bankofamerica.com
127.0.0.1 online.bankofamerica.com
"@
    
    Add-Content -Path $HostsFile -Value $entries
    Write-Host "[+] Hosts file updated successfully"
}
Write-Host ""

# ====================
# STEP 3: DNS Cache
# ====================
Write-Host "[3/3] DNS Cache Flush"
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
# Summary
# ====================
Write-Host "========================================"
Write-Host "Setup Complete!"
Write-Host "========================================"
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Start your Flask app as Administrator: python app.py"
Write-Host "2. App will auto-detect certificates and run on appropriate port:"
Write-Host "   - Port 443 (HTTPS) if certificates found"
Write-Host "   - Port 80 (HTTP) if no certificates"
Write-Host "3. Open browser and go to: https://www.bankofamerica.com (HTTPS)"
Write-Host "   or http://www.bankofamerica.com (HTTP)"
Write-Host ""
Write-Host "Configuration files created:"
if (Test-Path $CertFile) {
    Write-Host "   - $CertFile"
    Write-Host "   - $KeyFile"
    Write-Host "   [HTTPS enabled - app will run on port 443]"
} else {
    Write-Host "   [No certificates - app will run on port 80 HTTP only]"
}
Write-Host ""
Write-Host "NOTE: App will run on port 443 (HTTPS) when certificates are found"
Write-Host "NOTE: Both port 80 and 443 require Administrator privileges"
Write-Host ""
Write-Host "To undo this setup, run: cleanup_hosts_redirect.ps1"
Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

