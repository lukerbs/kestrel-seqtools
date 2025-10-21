@echo off
REM ============================================================================
REM Blackhole Input Firewall - Uninstallation Script
REM Removes the service and cleans up all files
REM ============================================================================

setlocal

set "TASK_NAME=blackhole"
set "EXE_NAME=blackhole.exe"
set "INSTALL_DIR=%LOCALAPPDATA%\Temp"

echo.
echo ========================================
echo   Blackhole Input Firewall - Uninstall
echo ========================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator.
    echo Please right-click the script and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

echo [1/4] Stopping Task Scheduler service
schtasks /end /tn "%TASK_NAME%" >nul 2>&1
if %errorLevel% equ 0 (
    echo   - Service stopped.
) else (
    echo   - Service not running or not found.
)
echo.

echo [2/4] Deleting Task Scheduler service
schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1
if %errorLevel% equ 0 (
    echo   - Service deleted.
) else (
    echo   - Service not found or already deleted.
)
echo.

echo [3/4] Terminating running processes
taskkill /f /im "%EXE_NAME%" >nul 2>&1
if %errorLevel% equ 0 (
    echo   - Process terminated.
) else (
    echo   - Process not found or already terminated.
)
echo.

echo [4/4] Deleting files

if exist "%INSTALL_DIR%\%EXE_NAME%" (
    del /f /q "%INSTALL_DIR%\%EXE_NAME%" >nul 2>&1
    if %errorLevel% equ 0 (
        echo   - Deleted: %INSTALL_DIR%\%EXE_NAME%
    ) else (
        echo   - Warning: Could not delete %EXE_NAME% (file may be locked)
    )
) else (
    echo   - Executable not found at %INSTALL_DIR%\%EXE_NAME%
)

if exist "%INSTALL_DIR%\.dev_mode" (
    del /f /q "%INSTALL_DIR%\.dev_mode" >nul 2>&1
    echo   - Deleted: .dev_mode marker
)

echo.
echo ========================================
echo   Uninstall Complete!
echo ========================================
echo.
echo Verification commands:
echo   - Check Task Scheduler: schtasks /query /tn "%TASK_NAME%"
echo   - Check running processes: tasklist ^| findstr "%EXE_NAME%"
echo   - Check directory: dir "%INSTALL_DIR%"
echo.
pause

