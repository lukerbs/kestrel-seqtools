@echo off
:: Setup Bank of America Hosts File Redirect for Scambaiting
:: Run this script as Administrator in your Windows VM

echo ========================================
echo Bank of America Hosts File Redirect
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

:: Backup hosts file
set HOSTS_FILE=C:\Windows\System32\drivers\etc\hosts
set BACKUP_FILE=C:\Windows\System32\drivers\etc\hosts.backup

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

:: Flush DNS cache
echo [+] Flushing DNS cache...
ipconfig /flushdns >nul 2>&1
if %errorLevel% equ 0 (
    echo [+] DNS cache flushed successfully
) else (
    echo [!] Warning: Could not flush DNS cache
)
echo.

echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo Next steps:
echo 1. Start your Flask app as Administrator: python app.py
echo 2. Open browser and go to: http://www.bankofamerica.com
echo 3. The site will load from localhost instead of the internet
echo.
echo NOTE: Running Flask on port 80 requires Administrator privileges
echo      Run Command Prompt as Administrator before starting app.py
echo.
echo To undo this redirect, run: cleanup_hosts_redirect.bat
echo.
pause

