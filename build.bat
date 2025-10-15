@echo off
REM Build TCP Receiver as Windows executable
REM Requires: PyInstaller (pip install pyinstaller)
REM Requires: icon.ico in the same directory

echo.
echo ======================================
echo   Building TCP Receiver Executable
echo ======================================
echo.

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

REM Check if PyInstaller is installed
python -m pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo PyInstaller not found. Installing...
    python -m pip install pyinstaller
    if errorlevel 1 (
        echo ERROR: Failed to install PyInstaller
        pause
        exit /b 1
    )
)

echo Building executable...
echo.

REM Build the executable
pyinstaller --onefile ^
            --name "TCP-Receiver" ^
            --icon=icon.ico ^
            receiver.py

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo ======================================
echo   Build Complete!
echo ======================================
echo.
echo Executable location: dist\TCP-Receiver.exe
echo.
echo Cleaning up build artifacts...

REM Clean up temporary build folder
if exist build rmdir /s /q build

REM Keep the .spec file - it's useful for customizing future builds!
echo Build artifacts cleaned (kept TCP-Receiver.spec for future use)

echo.
echo Done! You can find your executable in the 'dist' folder.
echo.
pause

