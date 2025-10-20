@echo off
REM Uninstall TCP Receiver (taskhostw.exe) from Windows
REM Removes Task Scheduler entry, kills running processes, and deletes payload

echo.
echo ========================================
echo   Uninstalling TCP Receiver
echo ========================================
echo.

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script requires administrator privileges.
    echo Please right-click and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo [1/4] Stopping running task...
schtasks /end /tn "taskhostw" >nul 2>&1
if %errorLevel% equ 0 (
    echo   - Task stopped successfully
) else (
    echo   - Task not running or already stopped
)
echo.

echo [2/4] Deleting Task Scheduler entry...
schtasks /delete /tn "taskhostw" /f >nul 2>&1
if %errorLevel% equ 0 (
    echo   - Task deleted successfully
) else (
    echo   - Task not found or already deleted
)
echo.

echo [3/4] Killing any running payload processes...
taskkill /f /im "taskhostw.exe" >nul 2>&1
if %errorLevel% equ 0 (
    echo   - Process terminated successfully
) else (
    echo   - Process not found or already terminated
)
echo.

echo [4/4] Deleting payload files...
set "PAYLOAD_DIR=%LOCALAPPDATA%\Temp"

if exist "%PAYLOAD_DIR%\taskhostw.exe" (
    del /f /q "%PAYLOAD_DIR%\taskhostw.exe" >nul 2>&1
    if %errorLevel% equ 0 (
        echo   - Deleted: %PAYLOAD_DIR%\taskhostw.exe
    ) else (
        echo   - Warning: Could not delete taskhostw.exe (file may be locked)
    )
) else (
    echo   - Payload executable not found at %PAYLOAD_DIR%\taskhostw.exe
)

if exist "%PAYLOAD_DIR%\.dev_mode" (
    del /f /q "%PAYLOAD_DIR%\.dev_mode" >nul 2>&1
    echo   - Deleted: .dev_mode marker
)

echo.
echo ========================================
echo   Uninstall Complete!
echo ========================================
echo.
echo The TCP Receiver has been removed from your system.
echo.
echo Verification commands:
echo   schtasks /query /tn "taskhostw"     (should show: ERROR: The system cannot find the file specified)
echo   tasklist ^| findstr taskhostw        (should show no results)
echo.
pause

