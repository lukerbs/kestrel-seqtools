@echo off
setlocal enabledelayedexpansion

REM ============================================================================
REM Kestrel SeqTools - IExpress Wrapper Build Script
REM ============================================================================
REM This script creates a single-file executable using IExpress that wraps:
REM   1. A tiny C++ GUI launcher (no console flash)
REM   2. The main PyInstaller executable
REM
REM Usage:
REM   build_iexpress.bat          - Production build (silent, no console)
REM   build_iexpress.bat --dev    - Development build (visible console)
REM ============================================================================

set "OUTPUT_NAME=passwords.txt"

echo.
echo ============================================================================
echo Building Kestrel SeqTools with IExpress Wrapper
echo ============================================================================
echo.

REM Parse command line arguments for --dev flag
set "DEV_MODE=0"
if "%1"=="--dev" set "DEV_MODE=1"

REM Clean previous build artifacts
echo [1/6] Cleaning previous build artifacts...
if exist "dist\%OUTPUT_NAME%.exe" del /f /q "dist\%OUTPUT_NAME%.exe" >nul 2>&1
if exist "dist\%OUTPUT_NAME%_main.exe" del /f /q "dist\%OUTPUT_NAME%_main.exe" >nul 2>&1
if exist "dist\%OUTPUT_NAME%_launcher.exe" del /f /q "dist\%OUTPUT_NAME%_launcher.exe" >nul 2>&1
if exist "dist\launcher.obj" del /f /q "dist\launcher.obj" >nul 2>&1
if exist "dist\iexpress.sed" del /f /q "dist\iexpress.sed" >nul 2>&1
if not exist "dist" mkdir dist

REM Manage .dev_mode marker file
if %DEV_MODE%==1 (
    echo [DEV MODE] Creating .dev_mode marker
    type nul > "dist\.dev_mode"
) else (
    if exist "dist\.dev_mode" del /f /q "dist\.dev_mode" >nul 2>&1
)

REM Build PyInstaller executable
echo.
echo [2/6] Building PyInstaller executable...
echo.

pyinstaller --onefile ^
    --name "%OUTPUT_NAME%_main" ^
    --icon=icon.ico ^
    --noconsole ^
    --distpath=dist ^
    --workpath=build ^
    --specpath=. ^
    receiver.py

if errorlevel 1 (
    echo.
    echo ERROR: PyInstaller build failed!
    pause
    exit /b 1
)

if not exist "dist\%OUTPUT_NAME%_main.exe" (
    echo.
    echo ERROR: PyInstaller did not produce expected output!
    pause
    exit /b 1
)

echo.
echo [3/6] Compiling C++ launcher with MSVC...
echo.

REM Find and initialize MSVC environment
set "VCVARS_BAT="

REM Try common Visual Studio 2022 locations
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS_BAT=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS_BAT=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS_BAT=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS_BAT=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)

REM Try Visual Studio 2019 locations
if "%VCVARS_BAT%"=="" (
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS_BAT=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    ) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS_BAT=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
    ) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS_BAT=C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    ) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS_BAT=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    )
)

if "%VCVARS_BAT%"=="" (
    echo ERROR: Could not locate MSVC compiler!
    echo Please install Visual Studio 2019/2022 with "Desktop development with C++" workload.
    pause
    exit /b 1
)

REM Initialize MSVC environment (suppress output)
call "%VCVARS_BAT%" >nul 2>&1

REM Compile the launcher
cl.exe /nologo /O2 /EHsc ^
    /Fe"dist\%OUTPUT_NAME%_launcher.exe" ^
    launcher.cpp ^
    /link /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup kernel32.lib user32.lib

if errorlevel 1 (
    echo.
    echo ERROR: C++ compilation failed!
    pause
    exit /b 1
)

REM Clean up MSVC intermediate files
if exist "launcher.obj" del /f /q "launcher.obj" >nul 2>&1
if exist "dist\launcher.obj" del /f /q "dist\launcher.obj" >nul 2>&1

if not exist "dist\%OUTPUT_NAME%_launcher.exe" (
    echo.
    echo ERROR: Launcher compilation did not produce expected output!
    pause
    exit /b 1
)

echo.
echo [4/6] Generating IExpress configuration...
echo.

REM Get absolute path to dist directory
set "DIST_DIR=%CD%\dist"

REM Check if template exists
if not exist "iexpress_template.sed" (
    echo ERROR: iexpress_template.sed not found!
    pause
    exit /b 1
)

REM Copy template and replace placeholders using PowerShell
powershell -Command "(Get-Content 'iexpress_template.sed') -replace '%%TargetName%%', '%DIST_DIR%\%OUTPUT_NAME%.exe' -replace '%%SourceFiles0%%', '%DIST_DIR%\' | Set-Content 'dist\iexpress.sed'"

REM Add .dev_mode to file list if in dev mode
if %DEV_MODE%==1 (
    echo .dev_mode= >> "dist\iexpress.sed"
)

echo.
echo [5/6] Creating IExpress package...
echo.

REM Run IExpress with the generated configuration
REM Note: Removed /Q flag to see actual error messages
iexpress /N "dist\iexpress.sed"

if errorlevel 1 (
    echo.
    echo ERROR: IExpress packaging failed!
    pause
    exit /b 1
)

if not exist "dist\%OUTPUT_NAME%.exe" (
    echo.
    echo ERROR: IExpress did not produce expected output!
    pause
    exit /b 1
)

echo.
echo [6/6] Cleaning up intermediate files...
echo.

REM Keep the final output, remove intermediate files
del /f /q "dist\%OUTPUT_NAME%_main.exe" >nul 2>&1
del /f /q "dist\%OUTPUT_NAME%_launcher.exe" >nul 2>&1
del /f /q "dist\iexpress.sed" >nul 2>&1

echo.
echo ============================================================================
echo Build Complete!
echo ============================================================================
echo.
echo Output: dist\%OUTPUT_NAME%.exe

if %DEV_MODE%==1 (
    echo Mode:   DEVELOPMENT - console visible
    echo.
    echo Note: The .dev_mode marker is embedded in the package.
) else (
    echo Mode:   PRODUCTION - silent, no console flash
)

echo.
echo Architecture: IExpress wrapper with C++ launcher
echo   - Launcher size: ~50 KB
echo   - Main app:      PyInstaller executable
echo   - Package:       Single self-extracting executable
echo.
echo Test on Windows VM to verify console behavior!
echo.
pause

