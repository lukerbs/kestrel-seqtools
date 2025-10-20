@echo off
:: Setup Bank of America Hosts File Redirect + SSL for Scambaiting
:: Run this script as Administrator in your Windows VM

echo ========================================
echo Bank of America Local HTTPS Setup
echo ========================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script requires Administrator privileges.
    echo Right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo [+] Running with Administrator privileges
echo.

:: Configuration
set DOMAIN=bankofamerica.com
set HOSTS_FILE=C:\Windows\System32\drivers\etc\hosts
set BACKUP_FILE=C:\Windows\System32\drivers\etc\hosts.backup
set CERT_FILE=%DOMAIN%+3.pem
set KEY_FILE=%DOMAIN%+3-key.pem

:: ====================
:: STEP 1: SSL Certificate
:: ====================
echo [1/3] SSL Certificate Setup
echo -------------------------------------------

:: Check if mkcert is installed
where mkcert >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] mkcert is not installed
    echo [+] Auto-installing Chocolatey and mkcert...
    echo [+] This may take a few minutes...
    echo.
    
    :: Check if Chocolatey is installed
    where choco >nul 2>&1
    if %errorLevel% neq 0 (
        echo [+] Installing Chocolatey package manager...
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
        
        if %errorLevel% neq 0 (
            echo [!] ERROR: Failed to install Chocolatey
            echo [!] Please install manually: https://chocolatey.org/install
            echo [!] Skipping SSL certificate generation...
            echo.
            goto :hosts_setup
        )
        
        echo [+] Chocolatey installed successfully
        echo.
        
        :: Refresh PATH for current session
        set "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
    ) else (
        echo [+] Chocolatey already installed
    )
    
    :: Install mkcert
    echo [+] Installing mkcert...
    choco install mkcert -y --no-progress
    
    if %errorLevel% neq 0 (
        echo [!] ERROR: Failed to install mkcert
        echo [!] Skipping SSL certificate generation...
        echo.
        goto :hosts_setup
    )
    
    :: Refresh PATH for current session
    set "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
    
    echo [+] mkcert installed successfully
    echo.
)

:: Check if mkcert CA is installed (one-time setup)
:: Get the CA root directory path
for /f "delims=" %%i in ('mkcert -CAROOT 2^>nul') do set CAROOT=%%i
if not exist "%CAROOT%\rootCA.pem" (
    echo [+] Installing mkcert local CA (one-time setup)...
    mkcert -install
    if %errorLevel% neq 0 (
        echo [!] Failed to install mkcert CA
        echo [!] Certificates may not be trusted by browsers
    ) else (
        echo [+] Local CA installed successfully
    )
) else (
    echo [+] Local CA already installed
)

:: Check if certificate already exists
if exist "%CERT_FILE%" (
    echo [!] Certificate already exists: %CERT_FILE%
    echo [!] Skipping generation...
) else (
    echo [+] Generating SSL certificate for %DOMAIN%...
    mkcert %DOMAIN% www.%DOMAIN% secure.%DOMAIN% online.%DOMAIN%
    if %errorLevel% neq 0 (
        echo [!] Failed to generate certificate
        echo [!] Continuing without HTTPS support...
    ) else (
        echo [+] Certificate generated successfully
    )
)

:: Install certificate to trust store
if exist "%CERT_FILE%" (
    echo [+] Installing certificate to Windows trust store...
    certutil -addstore -f "Root" "%CERT_FILE%" >nul 2>&1
    if %errorLevel% equ 0 (
        echo [+] Certificate installed - browsers will trust this site
    ) else (
        echo [!] Warning: Could not install certificate to trust store
    )
)
echo.

:: ====================
:: STEP 2: Hosts File
:: ====================
:hosts_setup
echo [2/3] Hosts File Configuration
echo -------------------------------------------

:: Backup hosts file
echo [+] Creating backup of hosts file...
copy "%HOSTS_FILE%" "%BACKUP_FILE%" >nul 2>&1
if %errorLevel% equ 0 (
    echo [+] Backup created: %BACKUP_FILE%
) else (
    echo [!] Warning: Could not create backup
)
echo.

:: Check if entries already exist
findstr /i "bankofamerica.com" "%HOSTS_FILE%" >nul 2>&1
if %errorLevel% equ 0 (
    echo [!] Bank of America redirect already exists in hosts file
    echo [!] Skipping modification
) else (
    echo [+] Adding Bank of America redirect to hosts file...
    echo. >> "%HOSTS_FILE%"
    echo # Scambaiting redirect - Added by setup script >> "%HOSTS_FILE%"
    echo 127.0.0.1 bankofamerica.com >> "%HOSTS_FILE%"
    echo 127.0.0.1 www.bankofamerica.com >> "%HOSTS_FILE%"
    echo 127.0.0.1 secure.bankofamerica.com >> "%HOSTS_FILE%"
    echo 127.0.0.1 online.bankofamerica.com >> "%HOSTS_FILE%"
    echo [+] Hosts file updated successfully
)
echo.

:: ====================
:: STEP 3: DNS Cache
:: ====================
echo [3/3] DNS Cache Flush
echo -------------------------------------------
echo [+] Flushing DNS cache...
ipconfig /flushdns >nul 2>&1
if %errorLevel% equ 0 (
    echo [+] DNS cache flushed successfully
) else (
    echo [!] Warning: Could not flush DNS cache
)
echo.

:: ====================
:: Summary
:: ====================
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo Next steps:
echo 1. Start your Flask app as Administrator: python app.py
echo 2. App will auto-detect certificates and run on appropriate port:
echo    - Port 443 (HTTPS) if certificates found
echo    - Port 80 (HTTP) if no certificates
echo 3. Open browser and go to: https://www.bankofamerica.com (HTTPS)
echo    or http://www.bankofamerica.com (HTTP)
echo.
echo Configuration files created:
if exist "%CERT_FILE%" (
    echo    - %CERT_FILE%
    echo    - %KEY_FILE%
    echo    [HTTPS enabled - app will run on port 443]
) else (
    echo    [No certificates - app will run on port 80 HTTP only]
)
echo.
echo NOTE: App will run on port 443 (HTTPS) when certificates are found
echo NOTE: Both port 80 and 443 require Administrator privileges
echo.
echo To undo this setup, run: cleanup_hosts_redirect.bat
echo.
pause

