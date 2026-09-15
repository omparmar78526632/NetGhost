@echo off
REM NetGhost Sender Launcher
REM This script must be run as Administrator

echo.
echo ========================================
echo   NetGhost Sender Launcher
echo ========================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Not running as Administrator!
    echo.
    echo Please right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

echo [OK] Running as Administrator
echo.

REM Activate virtual environment
if exist .venv\Scripts\activate.bat (
    call .venv\Scripts\activate.bat
    echo [OK] Virtual environment activated
) else (
    echo ERROR: Virtual environment not found!
    echo Please run: python -m venv .venv
    echo Then run: .venv\Scripts\activate
    echo Then run: pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

echo.
echo Starting NetGhost Sender...
echo.
echo Open your browser to: http://127.0.0.1:5000
echo.
echo Press Ctrl+C to stop the sender
echo.
echo ========================================
echo.

python sender\sender_app.py

pause
