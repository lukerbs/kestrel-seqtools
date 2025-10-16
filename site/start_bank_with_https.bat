@echo off
:: Start Fake Bank of America Site with HTTPS Support
:: Runs both HTTP (port 80) and HTTPS redirect (port 443)
:: Run this script as Administrator

echo ========================================
echo Bank of America Site - HTTPS Enabled
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

:: Check if certificate exists
if not exist cert.pem (
    echo ERROR: SSL certificate not found!
    echo.
    echo Please run: generate_ssl_cert.bat first
    echo.
    pause
    exit /b 1
)

echo [+] SSL certificate found
echo.

:: Check if Python is available
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

echo [+] Python found
echo.

:: Start HTTPS redirect server in background
echo [+] Starting HTTPS redirect server (port 443)...
start /B python https_redirect.py

:: Wait a moment
timeout /t 2 /nobreak >nul

:: Start Flask app (port 80)
echo [+] Starting Flask app (port 80)...
echo.
echo ========================================
echo Servers Running!
echo ========================================
echo.
echo HTTP:  http://www.bankofamerica.com
echo HTTPS: https://www.bankofamerica.com (auto-redirects to HTTP)
echo.
echo Note: Browser will show a certificate warning for HTTPS
echo       Just click "Advanced" and "Proceed" to accept it once
echo.
echo Press Ctrl+C to stop both servers
echo.

:: Start Flask app (this will block until Ctrl+C)
python app.py

