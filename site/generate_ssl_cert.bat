@echo off
:: Generate Self-Signed SSL Certificate for Bank of America
:: This allows HTTPS to work without "Not secure" warning (browser will show different warning though)

echo ========================================
echo SSL Certificate Generator
echo ========================================
echo.

:: Check if OpenSSL is available
where openssl >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: OpenSSL is not installed or not in PATH
    echo.
    echo Please install OpenSSL for Windows:
    echo   1. Download from: https://slproweb.com/products/Win32OpenSSL.html
    echo   2. Install the "Win64 OpenSSL" package
    echo   3. Add OpenSSL to your PATH
    echo.
    echo Or use Git Bash if you have Git for Windows installed:
    echo   It includes OpenSSL by default
    echo.
    pause
    exit /b 1
)

echo [+] OpenSSL found
echo.

:: Check if certificate already exists
if exist cert.pem (
    echo [!] Certificate already exists: cert.pem
    echo [!] Delete it first if you want to regenerate
    pause
    exit /b 0
)

echo [+] Generating self-signed certificate...
echo.

:: Generate certificate
openssl req -x509 -newkey rsa:2048 -nodes ^
    -keyout key.pem -out cert.pem -days 365 ^
    -subj "/CN=www.bankofamerica.com"

if %errorLevel% equ 0 (
    echo.
    echo ========================================
    echo Certificate Generated Successfully!
    echo ========================================
    echo.
    echo Files created:
    echo   cert.pem - SSL certificate
    echo   key.pem  - Private key
    echo.
    echo You can now run: start_bank_with_https.bat
    echo.
) else (
    echo.
    echo [!] Error generating certificate
    echo.
)

pause

