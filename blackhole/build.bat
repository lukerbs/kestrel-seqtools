@echo off
REM ============================================================================
REM Blackhole Input Firewall - Build Script
REM Builds the service into a standalone executable using PyInstaller
REM ============================================================================

setlocal

REM Check for --dev flag
set DEV_MODE=0
if "%1"=="--dev" set DEV_MODE=1

echo.
echo ========================================
echo   Blackhole Input Firewall - Build
echo ========================================
echo.

REM Check if PyInstaller is installed
python -c "import PyInstaller" 2>nul
if %errorLevel% neq 0 (
    echo ERROR: PyInstaller is not installed.
    echo Please install it with: pip install pyinstaller
    echo.
    pause
    exit /b 1
)

REM Clean previous builds
if exist "dist" rmdir /s /q dist
if exist "build" rmdir /s /q build
if exist "blackhole.spec" del /f /q blackhole.spec

echo Cleaning previous builds...
echo.

REM Build based on mode
if %DEV_MODE%==1 (
    echo Building in DEV mode (with console window)...
    echo.
    
    pyinstaller --onefile ^
                --name blackhole ^
                --hidden-import=pynput.keyboard._win32 ^
                --hidden-import=pynput.mouse._win32 ^
                main.py
    
    if %errorLevel% neq 0 (
        echo.
        echo ERROR: Build failed!
        pause
        exit /b 1
    )
    
    echo.
    echo ========================================
    echo   Build Complete (DEV MODE)
    echo ========================================
    echo.
    echo Output: dist\blackhole.exe
    echo Console: VISIBLE (for debugging)
    echo.
    echo To install: install.bat --dev
    echo.
    
) else (
    echo Building in PRODUCTION mode (headless, no console)...
    echo.
    
    pyinstaller --onefile ^
                --name blackhole ^
                --noconsole ^
                --hidden-import=pynput.keyboard._win32 ^
                --hidden-import=pynput.mouse._win32 ^
                main.py
    
    if %errorLevel% neq 0 (
        echo.
        echo ERROR: Build failed!
        pause
        exit /b 1
    )
    
    echo.
    echo ========================================
    echo   Build Complete (PRODUCTION MODE)
    echo ========================================
    echo.
    echo Output: dist\blackhole.exe
    echo Console: HIDDEN (silent background service)
    echo.
    echo To install: install.bat
    echo.
)

pause

