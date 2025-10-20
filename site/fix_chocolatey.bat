@echo off
:: Fix Broken Chocolatey Installation
:: Run this if you encounter Chocolatey installation errors
:: This script will completely remove any existing Chocolatey installation

echo ========================================
echo Fix Broken Chocolatey Installation
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
echo This script will:
echo   - Remove existing Chocolatey installation
echo   - Clean up registry entries
echo   - Remove PATH entries
echo   - Prepare for fresh installation
echo.
echo WARNING: This will remove Chocolatey and all packages installed via Chocolatey!
echo.
pause

echo.
echo ========================================
echo Step 1: Removing Chocolatey Directory
echo ========================================
echo.

if exist "C:\ProgramData\chocolatey" (
    echo [+] Removing C:\ProgramData\chocolatey...
    rd /s /q "C:\ProgramData\chocolatey" 2>nul
    if exist "C:\ProgramData\chocolatey" (
        echo [!] WARNING: Some files could not be removed (may be in use)
        echo [!] Try closing all terminals and running this script again
    ) else (
        echo [+] Chocolatey directory removed successfully
    )
) else (
    echo [!] Chocolatey directory not found (already clean)
)
echo.

echo ========================================
echo Step 2: Cleaning Environment Variables
echo ========================================
echo.

:: Remove Chocolatey from system PATH
echo [+] Cleaning PATH environment variable...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$path = [Environment]::GetEnvironmentVariable('Path', 'Machine'); $newPath = ($path.Split(';') | Where-Object { $_ -notlike '*chocolatey*' }) -join ';'; [Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')"

if %errorLevel% equ 0 (
    echo [+] PATH cleaned successfully
) else (
    echo [!] WARNING: Could not clean PATH variable
)
echo.

:: Remove ChocolateyInstall environment variable
echo [+] Removing ChocolateyInstall environment variable...
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Environment]::SetEnvironmentVariable('ChocolateyInstall', $null, 'Machine'); [Environment]::SetEnvironmentVariable('ChocolateyInstall', $null, 'User')"

if %errorLevel% equ 0 (
    echo [+] ChocolateyInstall variable removed
) else (
    echo [!] WARNING: Could not remove ChocolateyInstall variable
)
echo.

echo ========================================
echo Step 3: Cleaning Registry Entries
echo ========================================
echo.

echo [+] Removing Chocolatey registry entries...
reg delete "HKLM\SOFTWARE\Chocolatey" /f >nul 2>&1
if %errorLevel% equ 0 (
    echo [+] Registry entries removed
) else (
    echo [!] No registry entries found (already clean)
)
echo.

echo ========================================
echo Step 4: Cleaning User Profile
echo ========================================
echo.

if exist "%USERPROFILE%\.chocolatey" (
    echo [+] Removing %USERPROFILE%\.chocolatey...
    rd /s /q "%USERPROFILE%\.chocolatey" 2>nul
    echo [+] User profile cleaned
) else (
    echo [!] User profile directory not found (already clean)
)
echo.

if exist "%USERPROFILE%\AppData\Local\Temp\chocolatey" (
    echo [+] Removing temporary Chocolatey files...
    rd /s /q "%USERPROFILE%\AppData\Local\Temp\chocolatey" 2>nul
    echo [+] Temporary files cleaned
) else (
    echo [!] No temporary files found
)
echo.

echo ========================================
echo Cleanup Complete!
echo ========================================
echo.
echo Chocolatey has been completely removed from your system.
echo.
echo Next steps:
echo   1. Close this terminal
echo   2. Open a new terminal as Administrator
echo   3. Run setup_hosts_redirect.bat
echo.
echo The setup script will now be able to install a fresh copy of Chocolatey.
echo.
pause

