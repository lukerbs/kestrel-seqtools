@echo off
REM ============================================================================
REM Blackhole Input Firewall - Installation Script
REM Installs the service to auto-start on Windows boot via Task Scheduler
REM ============================================================================

setlocal

REM Check for --dev flag
set DEV_MODE=0
if "%1"=="--dev" set DEV_MODE=1

echo.
echo ========================================
echo   Blackhole Input Firewall - Install
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

REM Check if executable exists
if not exist "dist\blackhole.exe" (
    echo ERROR: blackhole.exe not found in dist\ directory.
    echo Please run build.bat first to create the executable.
    echo.
    pause
    exit /b 1
)

REM Define installation paths
set "INSTALL_DIR=%LOCALAPPDATA%\Temp"
set "EXE_PATH=%INSTALL_DIR%\blackhole.exe"
set "TASK_NAME=blackhole"

echo [1/4] Creating installation directory...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
echo   - Directory: %INSTALL_DIR%
echo.

echo [2/4] Copying executable...
copy /y "dist\blackhole.exe" "%EXE_PATH%" >nul
if %errorLevel% neq 0 (
    echo ERROR: Failed to copy executable.
    pause
    exit /b 1
)
echo   - Copied: blackhole.exe
echo.

REM Create .dev_mode marker if in dev mode
if %DEV_MODE%==1 (
    echo [3/4] Creating .dev_mode marker (DEV MODE)...
    echo. > "%INSTALL_DIR%\.dev_mode"
    echo   - Created: .dev_mode marker
    echo   - Console window will be VISIBLE
    echo.
) else (
    echo [3/4] Skipping .dev_mode marker (PRODUCTION MODE)...
    REM Delete marker if it exists from previous dev install
    if exist "%INSTALL_DIR%\.dev_mode" del /f /q "%INSTALL_DIR%\.dev_mode"
    echo   - Service will run SILENTLY in background
    echo.
)

echo [4/4] Creating Task Scheduler service...

REM Delete existing task if it exists
schtasks /query /tn "%TASK_NAME%" >nul 2>&1
if %errorLevel% equ 0 (
    echo   - Removing existing task...
    schtasks /delete /tn "%TASK_NAME%" /f >nul
)

REM Create new task
schtasks /create ^
    /tn "%TASK_NAME%" ^
    /tr "\"%EXE_PATH%\"" ^
    /sc onstart ^
    /ru SYSTEM ^
    /rl highest ^
    /f >nul

if %errorLevel% neq 0 (
    echo ERROR: Failed to create Task Scheduler entry.
    pause
    exit /b 1
)

echo   - Task created: %TASK_NAME%
echo   - Trigger: At system startup
echo   - User: SYSTEM
echo.

echo [5/5] Starting service...
schtasks /run /tn "%TASK_NAME%" >nul
if %errorLevel% equ 0 (
    echo   - Service started successfully
) else (
    echo   - Warning: Could not start service automatically
    echo   - Service will start on next system boot
)
echo.

echo ========================================
echo   Installation Complete!
echo ========================================
echo.
if %DEV_MODE%==1 (
    echo Mode: DEV (console visible)
) else (
    echo Mode: PRODUCTION (silent background service)
)
echo.
echo Service: %TASK_NAME%
echo Location: %EXE_PATH%
echo Hotkey: Command+Shift+F (toggle firewall)
echo.
echo To uninstall: uninstall.bat
echo.
pause

