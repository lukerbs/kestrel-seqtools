@echo off
:: Cleanup Bank of America Hosts File Redirect
:: Run this script as Administrator to remove the redirect

echo ========================================
echo Bank of America Hosts File Cleanup
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

set HOSTS_FILE=C:\Windows\System32\drivers\etc\hosts
set TEMP_FILE=%TEMP%\hosts.tmp

:: Remove Bank of America entries
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
echo Cleanup Complete!
echo ========================================
echo.
echo Bank of America will now resolve to the real website.
echo.
pause

