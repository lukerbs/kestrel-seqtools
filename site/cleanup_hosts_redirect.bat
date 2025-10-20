@echo off
:: Cleanup Bank of America Hosts File Redirect + SSL
:: Run this script as Administrator to remove the redirect and certificates

echo ========================================
echo Bank of America Cleanup
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
set TEMP_FILE=%TEMP%\hosts.tmp
set CERT_FILE=%DOMAIN%+3.pem
set KEY_FILE=%DOMAIN%+3-key.pem

:: ====================
:: STEP 1: Remove SSL Certificate
:: ====================
echo [1/4] SSL Certificate Cleanup
echo -------------------------------------------

:: Remove from trust store using PowerShell for reliability
echo [+] Removing certificate from Windows trust store...
powershell -Command "Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*%DOMAIN%*' } | Remove-Item -Force" >nul 2>&1
if %errorLevel% equ 0 (
    echo [+] Certificate removed from trust store
) else (
    echo [!] Certificate not found in trust store (may not have been installed)
)

:: Delete certificate files
if exist "%CERT_FILE%" (
    del /f /q "%CERT_FILE%"
    echo [+] Deleted %CERT_FILE%
)
if exist "%KEY_FILE%" (
    del /f /q "%KEY_FILE%"
    echo [+] Deleted %KEY_FILE%
)
echo.

:: ====================
:: STEP 2: Clean Hosts File
:: ====================
echo [2/4] Hosts File Cleanup
echo -------------------------------------------
echo [+] Removing Bank of America redirect from hosts file...

(for /f "tokens=* delims=" %%a in ('type "%HOSTS_FILE%"') do (
    echo %%a | findstr /i /c:"bankofamerica.com" /c:"Scambaiting redirect" >nul 2>&1
    if errorlevel 1 echo %%a
)) > "%TEMP_FILE%"

:: Replace original file
move /y "%TEMP_FILE%" "%HOSTS_FILE%" >nul 2>&1
if %errorLevel% equ 0 (
    echo [+] Hosts file cleaned successfully
) else (
    echo [!] Error: Could not update hosts file
)
echo.

:: ====================
:: STEP 3: DNS Cache
:: ====================
echo [3/4] DNS Cache Flush
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
:: STEP 4: Clean Deployment Directory
:: ====================
echo [4/4] Cleaning Deployment Directory
echo -------------------------------------------

set "DEPLOY_DIR=%LOCALAPPDATA%\Temp"

if exist "%DEPLOY_DIR%\%CERT_FILE%" (
    del /f /q "%DEPLOY_DIR%\%CERT_FILE%"
    echo [+] Deleted deployment certificate: %CERT_FILE%
)

if exist "%DEPLOY_DIR%\%KEY_FILE%" (
    del /f /q "%DEPLOY_DIR%\%KEY_FILE%"
    echo [+] Deleted deployment key: %KEY_FILE%
)

echo.

:: ====================
:: Summary
:: ====================
echo ========================================
echo Cleanup Complete!
echo ========================================
echo.
echo Bank of America will now resolve to the real website.
echo All SSL certificates and redirects have been removed:
echo   - Certificate removed from Windows trust store
echo   - Certificate files deleted from site directory
echo   - Certificate files deleted from deployment directory
echo   - Hosts file entries removed
echo   - DNS cache flushed
echo.
echo Note: To remove the mkcert local CA completely, run: mkcert -uninstall
echo.
pause

