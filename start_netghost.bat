@echo off
REM NetGhost Unified Console Launcher
REM Run as Administrator for raw packet steganography

echo.
echo =======================================================
echo   NETGHOST - Unified Network Steganography Console
echo =======================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Not running as Administrator!
    echo Packet capture and raw transmission require Administrator privileges.
    echo.
)

REM Activate virtual environment
if exist .venv\Scripts\activate.bat (
    call .venv\Scripts\activate.bat
) else (
    echo Virtual environment not found. Using system Python.
)

echo Starting NetGhost Unified Laboratory Console...
echo Opening browser: http://127.0.0.1:5000
echo.

start http://127.0.0.1:5000

python app.py

pause
