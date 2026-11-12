@echo off
REM NetGhost Dedicated Sender Node Launcher (Port 5000)
REM Run as Administrator for raw packet steganography

echo ===============================================================
echo   NETGHOST - DEDICATED SENDER NODE (PORT 5000)
echo ===============================================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Not running as Administrator!
    echo Raw packet transmission requires Administrator privileges.
    echo.
)

if exist .venv\Scripts\activate.bat (
    set "PY_EXE=.venv\Scripts\python.exe"
) else (
    set "PY_EXE=python"
)

echo Starting Sender Node on http://127.0.0.1:5000/sender ...
start http://127.0.0.1:5000/sender

%PY_EXE% sender/sender_app.py
pause
